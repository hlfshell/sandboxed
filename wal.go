package sandboxed

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	commitBatch     = 64
	commitBytes     = 4 << 20
	commitDelay     = time.Millisecond
	checkpointBytes = 8 << 20
	cleanupBatch    = 64
	walHeaderSize   = 32
)

// Each record describes only changed metadata and chunk references. Payload is
// already encrypted in immutable chunk files before a record can become durable.
type walChange struct {
	Name  string  `json:"name"`
	Item  *entry  `json:"item,omitempty"`
	Reset bool    `json:"reset,omitempty"`
	Put   []chunk `json:"put,omitempty"`
	Drop  []int   `json:"drop,omitempty"`
}

// journalFile keeps the durability boundary explicit and fault-testable.
type journalFile interface {
	io.ReaderAt
	io.WriterAt
	Stat() (fs.FileInfo, error)
	Sync() error
	Truncate(int64) error
	Close() error
}

type commitRequest struct {
	file *File
	done chan error
}

func changesBetween(previous, next manifest, names []string) []walChange {
	changes := make([]walChange, 0, len(names))
	for _, name := range names {
		current, exists := next.Entries[name]
		change := walChange{Name: name}
		if exists {
			before, existed := previous.Entries[name]
			change.Reset = !existed || !bytes.Equal(before.Key, current.Key)
			metadata := current
			metadata.Chunks = nil
			change.Item = &metadata
			if change.Reset {
				change.Put = current.Chunks
			} else {
				i, j := 0, 0
				for i < len(before.Chunks) || j < len(current.Chunks) {
					if j == len(current.Chunks) || (i < len(before.Chunks) && before.Chunks[i].Index < current.Chunks[j].Index) {
						change.Drop = append(change.Drop, before.Chunks[i].Index)
						i++
					} else if i == len(before.Chunks) || current.Chunks[j].Index < before.Chunks[i].Index {
						change.Put = append(change.Put, current.Chunks[j])
						j++
					} else {
						if !bytes.Equal(before.Chunks[i].ID, current.Chunks[j].ID) {
							change.Put = append(change.Put, current.Chunks[j])
						}
						i++
						j++
					}
				}
			}
		}
		changes = append(changes, change)
	}
	return changes
}

func applyChanges(value *manifest, changes []walChange) error {
	seen := make(map[string]bool, len(changes))
	for _, change := range changes {
		if seen[change.Name] || !fs.ValidPath(change.Name) {
			return fmt.Errorf("invalid WAL path")
		}
		seen[change.Name] = true
		if change.Item == nil {
			delete(value.Entries, change.Name)
			continue
		}
		item := *change.Item
		if len(item.Chunks) != 0 {
			return fmt.Errorf("unexpected WAL chunk list")
		}
		old := value.Entries[change.Name].Chunks
		if change.Reset {
			old = nil
		}
		// Merge sorted deltas in linear time without materializing logical holes.
		for i, part := range change.Put {
			if part.Index < 0 || (i > 0 && part.Index <= change.Put[i-1].Index) {
				return fmt.Errorf("invalid WAL chunk order")
			}
		}
		for i, index := range change.Drop {
			if index < 0 || (i > 0 && index <= change.Drop[i-1]) {
				return fmt.Errorf("invalid WAL removal order")
			}
		}
		i, j, d := 0, 0, 0
		item.Chunks = make([]chunk, 0, len(old)+len(change.Put))
		for i < len(old) || j < len(change.Put) {
			if j < len(change.Put) && (i == len(old) || change.Put[j].Index <= old[i].Index) {
				part := change.Put[j]
				j++
				if i < len(old) && old[i].Index == part.Index {
					i++
				}
				item.Chunks = append(item.Chunks, part)
			} else {
				part := old[i]
				i++
				for d < len(change.Drop) && change.Drop[d] < part.Index {
					d++
				}
				if d == len(change.Drop) || change.Drop[d] != part.Index {
					item.Chunks = append(item.Chunks, part)
				}
			}
		}
		value.Entries[change.Name] = item
	}
	return nil
}

func (s *Store) encodeRecord(changes []walChange, sequence uint64) ([]byte, error) {
	if sequence == 0 {
		return nil, fmt.Errorf("WAL sequence exhausted")
	}
	plain, err := json.Marshal(changes)
	if err != nil {
		return nil, err
	}
	header := make([]byte, walHeaderSize)
	copy(header, "SBWAL001")
	binary.BigEndian.PutUint64(header[12:20], sequence)
	encoded := plain
	if len(s.key) != 0 {
		aead, err := fileAEAD(s.key)
		if err != nil {
			return nil, err
		}
		nonce, err := randomKey()
		if err != nil {
			return nil, err
		}
		copy(header[20:32], nonce[:12])
		binary.BigEndian.PutUint32(header[8:12], uint32(len(plain)+aead.Overhead()))
		encoded = aead.Seal(nil, header[20:32], plain, header)
	} else {
		binary.BigEndian.PutUint32(header[8:12], uint32(len(plain)))
	}
	if len(encoded) > maxManifestSize {
		return nil, fmt.Errorf("WAL record exceeds maximum size")
	}
	record := make([]byte, 0, len(header)+len(encoded)+sha256.Size)
	record = append(record, header...)
	record = append(record, encoded...)
	digest := sha256.Sum256(record)
	return append(record, digest[:]...), nil
}

func (s *Store) openWAL(create bool) error {
	s.entrySizes = make(map[string]int64)
	s.metadataSize = 0
	names := make([]string, 0, len(s.manifest.Entries))
	for name := range s.manifest.Entries {
		names = append(names, name)
	}
	s.updateManifestBudget(s.manifest, names)
	flags := unix.O_RDWR
	if create {
		flags |= unix.O_CREAT
	}
	file, err := openInternal(s.root, "wal", flags, s.fileMode)
	if err != nil {
		return err
	}
	s.wal = file
	info, err := file.Stat()
	if err != nil {
		return err
	}
	// Checkpointing limits normal replay. Bound even an externally supplied log.
	if info.Size() > checkpointBytes+maxManifestSize+walHeaderSize+sha256.Size {
		return fmt.Errorf("WAL exceeds recovery limit")
	}
	offset := int64(0)
	previous := uint64(0)
	for offset < info.Size() {
		header := make([]byte, walHeaderSize)
		if _, err := file.ReadAt(header, offset); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if string(header[:8]) != "SBWAL001" {
			return fmt.Errorf("invalid WAL header")
		}
		length := int64(binary.BigEndian.Uint32(header[8:12]))
		sequence := binary.BigEndian.Uint64(header[12:20])
		if length > maxManifestSize || length == 0 || sequence == 0 || (previous != 0 && sequence != previous+1) {
			return fmt.Errorf("invalid WAL record bounds or sequence")
		}
		if info.Size()-offset < walHeaderSize+length+sha256.Size {
			break
		}
		body := make([]byte, int(length)+sha256.Size)
		if _, err := file.ReadAt(body, offset+walHeaderSize); err != nil {
			return err
		}
		hash := sha256.New()
		hash.Write(header)
		hash.Write(body[:length])
		if !bytes.Equal(hash.Sum(nil), body[length:]) {
			return fmt.Errorf("WAL checksum mismatch")
		}
		encoded := body[:length]
		if len(s.key) != 0 {
			aead, err := fileAEAD(s.key)
			if err != nil {
				return err
			}
			encoded, err = aead.Open(nil, header[20:32], encoded, header)
			if err != nil {
				return fmt.Errorf("authenticate WAL: %w", err)
			}
		} else if !bytes.Equal(header[20:32], make([]byte, 12)) {
			return fmt.Errorf("encrypted WAL without store key")
		}
		var changes []walChange
		if err := json.Unmarshal(encoded, &changes); err != nil {
			return fmt.Errorf("decode WAL: %w", err)
		}
		if sequence > s.manifest.Sequence {
			if sequence != s.manifest.Sequence+1 {
				return fmt.Errorf("missing WAL commit")
			}
			if err := applyChanges(&s.manifest, changes); err != nil {
				return err
			}
			if err := validateManifest(s.manifest, s.chunkSize); err != nil {
				return err
			}
			names := make([]string, 0, len(changes))
			for _, change := range changes {
				names = append(names, change.Name)
			}
			if err := s.checkManifestBudget(s.manifest, names); err != nil {
				return err
			}
			s.updateManifestBudget(s.manifest, names)
			s.manifest.Sequence = sequence
		}
		previous = sequence
		offset += walHeaderSize + length + sha256.Size
	}
	// Do not modify any disk state until recovered metadata and live payloads
	// have been validated by load. Startup finishes tail repair in reconcile.
	s.walSize = offset
	return nil
}

func (s *Store) flushCheckpoint() error {
	if s.walErr != nil {
		return s.walErr
	}
	if err := s.checkpoint(s.manifest); err != nil {
		return err
	}
	// Only a durable checkpoint allows retirement of its WAL prefix.
	if err := s.wal.Truncate(0); err != nil {
		s.walErr = err
		return err
	}
	if err := s.wal.Sync(); err != nil {
		s.walErr = err
		return err
	}
	s.walSize = 0
	s.checkpointCount++
	return nil
}

// commit is used for directory operations with the store lock already held.
func (s *Store) commit(next manifest, names ...string) error {
	if err := s.cleanupPressure(); err != nil {
		return err
	}
	return s.commitChanges(next, names)
}

func (s *Store) commitChanges(next manifest, names []string) error {
	if s.walErr != nil {
		return s.walErr
	}
	if err := validateManifest(next, s.chunkSize); err != nil {
		return err
	}
	// Checkpoint before the next append, bounding recovery work and log size.
	if s.walSize >= checkpointBytes {
		if err := s.flushCheckpoint(); err != nil {
			return err
		}
	}
	next.Sequence = s.manifest.Sequence + 1
	changes := changesBetween(s.manifest, next, names)
	record, err := s.encodeRecord(changes, next.Sequence)
	if err != nil {
		return err
	}
	if err := s.checkManifestBudget(next, names); err != nil {
		return err
	}
	if _, err := s.wal.WriteAt(record, s.walSize); err != nil {
		s.walErr = fmt.Errorf("append WAL: %w", err)
		return s.walErr
	}
	if err := s.wal.Sync(); err != nil {
		s.walErr = fmt.Errorf("sync WAL: %w", err)
		return s.walErr
	}
	s.walSize += int64(len(record))
	s.walBytes += uint64(len(record))
	s.walGroups++
	previous := s.manifest
	s.manifest = next
	for _, name := range names {
		s.retain(next.Entries[name])
	}
	for _, name := range names {
		s.release(previous.Entries[name])
	}
	s.updateManifestBudget(next, names)
	s.requestCleanup()
	return nil
}

func (s *Store) startWorkers() {
	s.commits = make(chan *commitRequest, commitBatch)
	s.stop = make(chan struct{})
	s.cleanupWake = make(chan struct{}, 1)
	s.workers.Add(2)
	go s.commitLoop()
	go s.cleanupLoop()
	if len(s.garbage) != 0 {
		s.requestCleanup()
	}
}

func (s *Store) submit(file *File) error {
	request := &commitRequest{file: file, done: make(chan error, 1)}
	select {
	case s.commits <- request:
	case <-s.stop:
		return fs.ErrClosed
	}
	return <-request.done
}

func (s *Store) commitLoop() {
	defer s.workers.Done()
	for {
		var first *commitRequest
		select {
		case first = <-s.commits:
		case <-s.stop:
			return
		}
		batch := []*commitRequest{first}
		s.lock.Lock()
		if s.writers <= 1 {
			s.commitFiles(batch)
			s.lock.Unlock()
			continue
		}
		s.lock.Unlock()
		timer := time.NewTimer(commitDelay)
	gather:
		for len(batch) < commitBatch {
			select {
			case request := <-s.commits:
				batch = append(batch, request)
			case <-timer.C:
				break gather
			}
		}
		timer.Stop()
		s.lock.Lock()
		s.commitFiles(batch)
		s.lock.Unlock()
	}
}

func (s *Store) commitFiles(batch []*commitRequest) {
	// Split groups by encoded delta bytes as well as count. An individual large
	// transaction is allowed alone, bounded by the manifest/record limit.
	for len(batch) != 0 {
		if err := s.cleanupPressure(); err != nil {
			for _, request := range batch {
				request.done <- err
			}
			return
		}
		next := cloneManifest(s.manifest)
		names := make([]string, 0, len(batch))
		ready := make([]*commitRequest, 0, len(batch))
		total := 0
		hasPayload := false
		for len(batch) != 0 {
			request := batch[0]
			f := request.file
			if err := s.checkWriter(f, next); err != nil {
				request.done <- err
				batch = batch[1:]
				continue
			}
			revision, err := randomKey()
			if err != nil {
				request.done <- err
				batch = batch[1:]
				continue
			}
			f.item.Revision = revision
			candidate := manifest{Entries: map[string]entry{f.source.name: f.item}}
			delta := changesBetween(next, candidate, []string{f.source.name})
			encoded, err := s.encodeRecord(delta, next.Sequence+1)
			if err != nil {
				request.done <- err
				batch = batch[1:]
				continue
			}
			if len(ready) != 0 && total+len(encoded) > commitBytes {
				break
			}
			batch = batch[1:]
			if err := s.promote(f); err != nil {
				request.done <- err
				s.requestCleanup()
				continue
			}
			hasPayload = hasPayload || (len(f.dirty) != 0 && len(f.item.Chunks) != 0)
			total += len(encoded)
			names = append(names, f.source.name)
			next.Entries[f.source.name] = f.item
			ready = append(ready, request)
		}
		if len(ready) == 0 {
			continue
		}
		var err error
		if hasPayload {
			err = s.chunks.Sync()
		}
		if err == nil {
			err = s.commitChanges(next, names)
		}
		for _, request := range ready {
			request.done <- err
		}
		s.requestCleanup()
	}
}

func (s *Store) checkWriter(f *File, next manifest) error {
	if s.walErr != nil {
		return s.walErr
	}
	previous, exists := next.Entries[f.source.name]
	if exists != f.existed || (exists && (previous.Directory || !bytes.Equal(previous.Key, f.source.entry.Key) || !bytes.Equal(previous.Revision, f.source.entry.Revision))) {
		return ErrConflict
	}
	parent, ok := next.Entries[path.Dir(f.source.name)]
	if !ok || !parent.Directory {
		return ErrConflict
	}
	return nil
}

func (s *Store) promote(f *File) error {
	// One descriptor remains cached while editing. Close it before immutable
	// publication; bounded workers reopen and sync separate encrypted chunks.
	if f.file != nil {
		err := f.file.Close()
		f.file = nil
		if err != nil {
			return err
		}
	}
	count := 0
	for _, part := range f.item.Chunks {
		if _, dirty := f.dirty[part.Index]; dirty {
			count++
		}
	}
	if count <= 1 {
		for _, part := range f.item.Chunks {
			if _, dirty := f.dirty[part.Index]; !dirty {
				continue
			}
			published, err := s.promoteChunk(f.staging[part.Index], part)
			if published {
				s.queueGarbage([32]byte(part.ID), int64(part.Size+16))
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	type result struct {
		part      chunk
		published bool
		err       error
	}
	jobs := make(chan chunk)
	results := make(chan result, 4)
	var workers sync.WaitGroup
	for range min(count, 4) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for part := range jobs {
				published, err := s.promoteChunk(f.staging[part.Index], part)
				results <- result{part, published, err}
			}
		}()
	}
	go func() {
		for _, part := range f.item.Chunks {
			if _, dirty := f.dirty[part.Index]; dirty {
				jobs <- part
			}
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	var err error
	for result := range results {
		if result.published {
			s.queueGarbage([32]byte(result.part.ID), int64(result.part.Size+16))
		}
		err = errors.Join(err, result.err)
	}
	return err
}

func (s *Store) promoteChunk(name string, part chunk) (bool, error) {
	file, info, err := openInternalWithInfo(s.root, name, unix.O_RDONLY, 0)
	if err != nil {
		return false, err
	}
	if info.Size() != int64(part.Size+16) {
		file.Close()
		return false, fmt.Errorf("invalid staged chunk length")
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return false, err
	}
	// Link then unlink gives exclusive publication without overwriting any live
	// identity. The inode and ciphertext bytes are unchanged.
	if err := unix.Linkat(int(s.root.Fd()), name, int(s.chunks.Fd()), chunkName(part), 0); err != nil {
		return false, err
	}
	return true, removeInternal(s.root, name)
}

func (s *Store) requestCleanup() {
	if s.cleanupWake == nil {
		return
	}
	select {
	case s.cleanupWake <- struct{}{}:
	default:
	}
}

func (s *Store) cleanupLoop() {
	defer s.workers.Done()
	for {
		select {
		case <-s.stop:
			return
		case <-s.cleanupWake:
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-s.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		s.lock.Lock()
		if !s.closed {
			s.cleanupErr = s.collect()
		}
		more := len(s.garbage) != 0
		s.lock.Unlock()
		if more {
			s.requestCleanup()
		}
	}
}

func (s *Store) queueGarbage(id [32]byte, size int64) {
	s.garbageBytes -= s.garbage[id]
	s.garbage[id] = size
	s.garbageBytes += size
}
func (s *Store) forgetGarbage(id [32]byte) {
	s.garbageBytes -= s.garbage[id]
	delete(s.garbage, id)
}

// A transaction may cross the high-water mark; the next group waits for
// bounded cleanup passes. Reader-pinned chunks are live, not garbage.
func (s *Store) cleanupPressure() error {
	for len(s.garbage) >= 1024 || s.garbageBytes >= 64<<20 {
		if err := s.collect(); err != nil {
			return fmt.Errorf("cleanup backpressure: %w", err)
		}
	}
	return nil
}

// Track the checkpoint budget incrementally; commit never serializes unrelated
// entries. Reserve space for top-level JSON, sequence, and encryption overhead.
func entryBudget(name string, item entry) int64 {
	encoded, _ := json.Marshal(item)
	key, _ := json.Marshal(name)
	return int64(len(encoded) + len(key) + 2)
}
func (s *Store) checkManifestBudget(next manifest, names []string) error {
	size := s.metadataSize
	for _, name := range names {
		size -= s.entrySizes[name]
		if item, ok := next.Entries[name]; ok {
			size += entryBudget(name, item)
		}
	}
	if size > maxManifestSize-512 {
		return fmt.Errorf("manifest exceeds maximum size")
	}
	return nil
}
func (s *Store) updateManifestBudget(next manifest, names []string) {
	for _, name := range names {
		s.metadataSize -= s.entrySizes[name]
		delete(s.entrySizes, name)
		if item, ok := next.Entries[name]; ok {
			size := entryBudget(name, item)
			s.entrySizes[name] = size
			s.metadataSize += size
		}
	}
}
