package sandboxed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

var errMissingManifest = errors.New("missing store manifest")

func (s *Store) load() error {
	file, info, err := openInternalWithInfo(s.root, "manifest", unix.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return errMissingManifest
	}
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := make([]byte, headerSize)
	if _, err := io.ReadFull(file, buffer); err != nil {
		return fmt.Errorf("read manifest header: %w", err)
	}
	h, err := decodeHeader(buffer)
	if err != nil {
		return err
	}
	if h.ManifestLen > maxManifestSize || info.Size() != headerSize+int64(h.ManifestLen)+sha256.Size {
		return fmt.Errorf("invalid manifest length")
	}
	if h.Flags&flagManifestAES == 0 && len(s.key) != 0 {
		return fmt.Errorf("store is not manifest-encrypted")
	}
	encoded := make([]byte, h.ManifestLen)
	if _, err := io.ReadFull(file, encoded); err != nil {
		return err
	}
	digest := make([]byte, sha256.Size)
	if _, err := io.ReadFull(file, digest); err != nil {
		return err
	}
	hash := sha256.New()
	hash.Write(buffer)
	hash.Write(encoded)
	if string(hash.Sum(nil)) != string(digest) {
		return fmt.Errorf("manifest checksum mismatch")
	}
	value, err := unmarshalManifest(h, encoded, s.key)
	if err != nil {
		return err
	}
	if err := validateManifest(value, int(h.ChunkSize)); err != nil {
		return err
	}
	s.chunkSize, s.manifest = int(h.ChunkSize), value
	if err := s.openWAL(false); err != nil {
		return err
	}
	value = s.manifest
	// Validate every live file before cleanup may delete anything.
	for _, item := range value.Entries {
		for _, part := range item.Chunks {
			file, info, err := openInternalWithInfo(s.chunks, chunkName(part), unix.O_RDONLY, 0)
			if err != nil {
				return fmt.Errorf("open live chunk: %w", err)
			}
			if err := file.Close(); err != nil {
				return err
			}
			if info.Size() != int64(part.Size+16) {
				return fmt.Errorf("invalid chunk length")
			}
		}
	}
	s.chunkSize, s.manifest = int(h.ChunkSize), value
	return nil
}

func (s *Store) lockLatest() error {
	s.lock.Lock()
	if s.closed {
		s.lock.Unlock()
		return fs.ErrClosed
	}
	return nil
}
func (s *Store) unlockLatest() { s.lock.Unlock() }

func validateManifest(value manifest, chunkSize int) error {
	root, ok := value.Entries["."]
	if !ok || !root.Directory {
		return fmt.Errorf("store manifest has no root")
	}
	ids := make(map[[32]byte]struct{})
	for name, item := range value.Entries {
		if !fs.ValidPath(name) {
			return fmt.Errorf("invalid virtual path %q", name)
		}
		if name != "." {
			parent, ok := value.Entries[path.Dir(name)]
			if !ok || !parent.Directory {
				return fmt.Errorf("file %q has no parent directory", name)
			}
		}
		if item.Directory {
			if item.Size != 0 || len(item.Key) != 0 || len(item.Chunks) != 0 || len(item.Revision) != 0 {
				return fmt.Errorf("directory contains file data")
			}
			continue
		}
		if len(item.Key) != 32 || len(item.Revision) != 32 || item.Size < 0 || item.Size > int64(chunkSize)*maxFileChunks {
			return fmt.Errorf("invalid file metadata")
		}
		if len(item.Chunks) > maxFileChunks {
			return fmt.Errorf("too many allocated chunks")
		}
		previous := -1
		for _, part := range item.Chunks {
			if len(part.ID) != 32 || part.Size <= 0 || part.Size > chunkSize || part.Index < 0 || part.Index >= maxFileChunks || part.Index <= previous {
				return fmt.Errorf("invalid chunk metadata")
			}
			start := int64(part.Index) * int64(chunkSize)
			if start >= item.Size || int64(part.Size) > item.Size-start {
				return fmt.Errorf("chunk extends beyond file size")
			}
			id := [32]byte(part.ID)
			if _, exists := ids[id]; exists {
				return fmt.Errorf("duplicate chunk identity")
			}
			ids[id] = struct{}{}
			previous = part.Index
		}
	}
	return nil
}

// Published entries and their chunk slices are immutable. Writers copy the
// target slice before editing, so unrelated entries can share their metadata.
func cloneManifest(source manifest) manifest {
	result := manifest{Entries: make(map[string]entry, len(source.Entries)), Sequence: source.Sequence}
	for name, item := range source.Entries {
		result.Entries[name] = item
	}
	return result
}

// checkpoint persists the current committed view. WAL retirement is allowed
// only after its replacement and directory entry are durable.
func (s *Store) checkpoint(next manifest) error {
	if err := validateManifest(next, s.chunkSize); err != nil {
		return err
	}
	h, encoded, err := marshalManifest(next, s.key, s.chunkSize)
	if err != nil {
		return err
	}
	if len(encoded) > maxManifestSize {
		return fmt.Errorf("manifest exceeds maximum size")
	}
	temporary, err := s.temporary(".manifest-")
	if err != nil {
		return err
	}
	defer func() { temporary.Close(); removeInternal(s.root, temporary.Name()) }()
	header := encodeHeader(h)
	hash := sha256.New()
	hash.Write(header)
	hash.Write(encoded)
	for _, data := range [][]byte{header, encoded, hash.Sum(nil)} {
		if _, err := temporary.Write(data); err != nil {
			return err
		}
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(int(s.root.Fd()), temporary.Name(), int(s.root.Fd()), "manifest"); err != nil {
		return err
	}
	s.manifestDirty = true
	return s.syncManifest()
}

func (s *Store) temporary(prefix string) (*os.File, error) {
	id, err := randomKey()
	if err != nil {
		return nil, err
	}
	return openInternal(s.root, prefix+hex.EncodeToString(id), unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, s.fileMode)
}

func chunkName(part chunk) string { return hex.EncodeToString(part.ID) }
func (s *Store) addRefs(value manifest) {
	for _, item := range value.Entries {
		s.retain(item)
	}
}
func (s *Store) retain(item entry) {
	for _, part := range item.Chunks {
		id := [32]byte(part.ID)
		s.refs[id]++
		s.forgetGarbage(id)
	}
}
func (s *Store) release(item entry) {
	for _, part := range item.Chunks {
		id := [32]byte(part.ID)
		s.refs[id]--
		if s.refs[id] == 0 {
			delete(s.refs, id)
			s.queueGarbage(id, int64(part.Size+16))
		}
	}
}

// syncManifest records the durability barrier before any old chunks are
// deleted. A successful commit already crossed this barrier; later handle
// closes need not sync the same manifest again. Failures remain retryable.
func (s *Store) syncManifest() error {
	if !s.manifestDirty {
		return nil
	}
	if err := s.root.Sync(); err != nil {
		return err
	}
	s.manifestDirty = false
	return nil
}

// collect is called with the store mutex held. Candidates come only from
// released references or failed writes, never from currently staged writers.
func (s *Store) collect() error {
	if s.walErr != nil {
		return s.walErr
	}
	if err := s.syncManifest(); err != nil {
		return err
	}
	if len(s.garbage) == 0 {
		return nil
	}
	var result error
	remaining := cleanupBatch
	for id := range s.garbage {
		if remaining == 0 {
			break
		}
		remaining--
		if s.refs[id] != 0 {
			s.forgetGarbage(id)
			continue
		}
		if err := removeInternal(s.chunks, hex.EncodeToString(id[:])); err != nil {
			result = errors.Join(result, err)
			continue
		}
		s.forgetGarbage(id)
	}
	return errors.Join(result, s.chunks.Sync())
}

// Cleanup drains deferred deletions in bounded passes, checking cancellation
// between passes. Referenced snapshots and active writes are preserved.
func (s *Store) Cleanup(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.lockLatest(); err != nil {
			return err
		}
		err := s.collect()
		more := len(s.garbage) != 0
		s.cleanupErr = err
		s.unlockLatest()
		if err != nil || !more {
			return err
		}
	}
}

// reconcile runs once under exclusive ownership, before handing out any handles.
func (s *Store) reconcile() error {
	entries, err := readDirectory(s.chunks)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !internalID(entry.Name()) || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected chunk entry %q", entry.Name())
		}
	}
	files, err := readDirectory(s.root)
	if err != nil {
		return err
	}
	for _, file := range files {
		name := file.Name()
		if name == "manifest" || name == "lock" || name == "chunks" || name == "wal" {
			continue
		}
		id := strings.TrimPrefix(strings.TrimPrefix(name, ".staging-"), ".manifest-")
		if id == name || !internalID(id) || !file.Type().IsRegular() {
			return fmt.Errorf("unexpected store entry %q", name)
		}
	}
	for _, entry := range entries {
		// Names were validated above before cleanup was allowed to begin.
		decoded, _ := hex.DecodeString(entry.Name())
		id := [32]byte(decoded)
		if s.refs[id] == 0 {
			file, info, err := openInternalWithInfo(s.chunks, entry.Name(), unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
			s.queueGarbage(id, info.Size())
		}
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".staging-") || strings.HasPrefix(file.Name(), ".manifest-") {
			if err := removeInternal(s.root, file.Name()); err != nil {
				return err
			}
		}
	}
	// Repair only an incomplete tail after all live data and names validated.
	if err := s.wal.Truncate(s.walSize); err != nil {
		return err
	}
	if err := s.wal.Sync(); err != nil {
		return err
	}
	if err := s.root.Sync(); err != nil {
		return err
	}
	return s.collect()
}
func internalID(name string) bool {
	if len(name) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(name)
	return err == nil && hex.EncodeToString(decoded) == name
}

func randomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	return key, err
}

func (s *Store) readChunk(key []byte, index int, part chunk) ([]byte, error) {
	return s.readChunkInto(nil, key, index, part)
}

// readChunkInto authenticates ciphertext in reusable, handle-owned storage.
func (s *Store) readChunkInto(buffer, key []byte, index int, part chunk) ([]byte, error) {
	file, info, err := openInternalWithInfo(s.chunks, chunkName(part), unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open chunk: %w", err)
	}
	defer file.Close()
	if info.Size() != int64(part.Size+16) {
		return nil, fmt.Errorf("invalid chunk length")
	}
	ciphertext := resizeBuffer(buffer, part.Size+16)
	if _, err := io.ReadFull(file, ciphertext); err != nil {
		return nil, err
	}
	return decryptChunkInto(ciphertext[:0], key, index, part, ciphertext)
}

func decryptChunk(fileKey []byte, index int, part chunk, ciphertext []byte) ([]byte, error) {
	return decryptChunkInto(nil, fileKey, index, part, ciphertext)
}

func decryptChunkInto(buffer, fileKey []byte, index int, part chunk, ciphertext []byte) ([]byte, error) {
	key := chunkKey(fileKey, part.ID)
	aead, err := fileAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(buffer, chunkNonce(key, uint64(index)), ciphertext, chunkAdditionalData(uint64(index), part.Size))
	if err != nil {
		return nil, fmt.Errorf("authenticate chunk: %w", err)
	}
	return plain, nil
}

// resizeBuffer preserves capacity between operations without retaining buffers
// globally. Callers explicitly clear any newly exposed plaintext region.
func resizeBuffer(buffer []byte, size int) []byte {
	if cap(buffer) < size {
		capacity := max(size, min(2*cap(buffer), maximumChunkSize+16))
		return make([]byte, size, capacity)
	}
	return buffer[:size]
}
