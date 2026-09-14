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
	file, err := openInternal(s.root, "manifest", unix.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return errMissingManifest
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
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
	// Validate every live file before cleanup may delete anything.
	for _, item := range value.Entries {
		for _, part := range item.Chunks {
			file, err := openInternal(s.chunks, chunkName(part), unix.O_RDONLY, 0)
			if err != nil {
				return fmt.Errorf("open live chunk: %w", err)
			}
			info, statErr := file.Stat()
			closeErr := file.Close()
			if err := errors.Join(statErr, closeErr); err != nil {
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
	ids := make(map[string]struct{})
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
		if len(item.Key) != 32 || len(item.Revision) != 32 || item.Size < 0 {
			return fmt.Errorf("invalid file metadata")
		}
		var size int64
		for index, part := range item.Chunks {
			if len(part.ID) != 32 || part.Size <= 0 || part.Size > chunkSize || (index < len(item.Chunks)-1 && part.Size != chunkSize) {
				return fmt.Errorf("invalid chunk metadata")
			}
			name := chunkName(part)
			if _, exists := ids[name]; exists {
				return fmt.Errorf("duplicate chunk identity")
			}
			ids[name] = struct{}{}
			if size > int64(^uint64(0)>>1)-int64(part.Size) {
				return fmt.Errorf("file size overflow")
			}
			size += int64(part.Size)
		}
		if size != item.Size {
			return fmt.Errorf("inconsistent file size")
		}
	}
	return nil
}

func cloneManifest(source manifest) manifest {
	result := manifest{Entries: make(map[string]entry, len(source.Entries))}
	for name, item := range source.Entries {
		item.Chunks = append([]chunk(nil), item.Chunks...)
		result.Entries[name] = item
	}
	return result
}

// commit publishes only metadata. New chunk files have already been synced.
// Once rename succeeds, memory follows the new manifest even if directory sync
// or cleanup fails; returning an error must never restore stale references.
func (s *Store) commit(next manifest) error {
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
	previous := s.manifest
	s.manifest = next
	s.addRefs(next)
	s.dropRefs(previous)
	// Garbage must survive until the manifest rename is durable. A sync failure
	// leaves it queued for a later cleanup, which retries the directory sync.
	if err := s.root.Sync(); err != nil {
		return err
	}
	return s.collect()
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
func (s *Store) dropRefs(value manifest) {
	for _, item := range value.Entries {
		s.release(item)
	}
}
func (s *Store) retain(item entry) {
	for _, part := range item.Chunks {
		name := chunkName(part)
		s.refs[name]++
		delete(s.garbage, name)
	}
}
func (s *Store) release(item entry) {
	for _, part := range item.Chunks {
		name := chunkName(part)
		s.refs[name]--
		if s.refs[name] == 0 {
			delete(s.refs, name)
			s.garbage[name] = struct{}{}
		}
	}
}

// collect is called with the store mutex held. Candidates come only from
// released references or failed writes, never from currently staged writers.
func (s *Store) collect() error {
	if len(s.garbage) == 0 {
		return nil
	}
	if err := s.root.Sync(); err != nil {
		return err
	}
	var result error
	for name := range s.garbage {
		if s.refs[name] != 0 {
			delete(s.garbage, name)
			continue
		}
		if err := removeInternal(s.chunks, name); err != nil {
			result = errors.Join(result, err)
			continue
		}
		delete(s.garbage, name)
	}
	return errors.Join(result, s.chunks.Sync())
}

// Cleanup retries deletion of unused chunks. Normal commits and handle closes
// already perform cleanup; referenced snapshots and active writes are preserved.
func (s *Store) Cleanup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.lockLatest(); err != nil {
		return err
	}
	defer s.unlockLatest()
	return s.collect()
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
		if name == "manifest" || name == "lock" || name == "chunks" {
			continue
		}
		id := strings.TrimPrefix(strings.TrimPrefix(name, ".staging-"), ".manifest-")
		if id == name || !internalID(id) || !file.Type().IsRegular() {
			return fmt.Errorf("unexpected store entry %q", name)
		}
	}
	for _, entry := range entries {
		if s.refs[entry.Name()] == 0 {
			s.garbage[entry.Name()] = struct{}{}
		}
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".staging-") || strings.HasPrefix(file.Name(), ".manifest-") {
			if err := removeInternal(s.root, file.Name()); err != nil {
				return err
			}
		}
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
	file, err := openInternal(s.chunks, chunkName(part), unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open chunk: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() != int64(part.Size+16) {
		return nil, fmt.Errorf("invalid chunk length")
	}
	ciphertext := make([]byte, part.Size+16)
	if _, err := io.ReadFull(file, ciphertext); err != nil {
		return nil, err
	}
	return decryptChunk(key, index, part, ciphertext)
}

func decryptChunk(fileKey []byte, index int, part chunk, ciphertext []byte) ([]byte, error) {
	key := chunkKey(fileKey, part.ID)
	aead, err := fileAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, chunkNonce(key, uint64(index)), ciphertext, chunkAdditionalData(uint64(index), part.Size))
	if err != nil {
		return nil, fmt.Errorf("authenticate chunk: %w", err)
	}
	return plain, nil
}
