package sandboxed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
)

func (s *Store) load() error {
	file, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := make([]byte, headerSize)
	if _, err := io.ReadFull(file, buffer); err != nil {
		return fmt.Errorf("read store header: %w", err)
	}
	h, err := decodeHeader(buffer)
	if err != nil {
		return err
	}
	if s.chunkSize == 0 {
		s.chunkSize = int(h.ChunkSize)
	} else if s.chunkSize != int(h.ChunkSize) {
		return fmt.Errorf("store chunk size changed")
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}

	// Only torn root records permit fallback. A published but corrupt manifest
	// is an error, never an invitation to silently roll back committed data.
	var latest commitRoot
	for slot := int64(1); slot <= 2; slot++ {
		buffer := make([]byte, rootSize)
		if _, err := file.ReadAt(buffer, slot*rootSpacing); err != nil {
			continue
		}
		root, err := decodeRoot(buffer)
		if err == nil && root.generation > latest.generation {
			latest = root
		}
	}
	if latest.generation == 0 {
		return fmt.Errorf("store has no complete commit")
	}
	if latest.header.Flags != h.Flags || latest.header.ChunkSize != h.ChunkSize || latest.offset < dataStart {
		return fmt.Errorf("commit does not match store header")
	}
	result, err := readManifest(file, latest.header, latest.offset, info.Size(), s.key, latest.digest)
	if err != nil {
		return err
	}
	if err := validateManifest(result, latest.offset, int(h.ChunkSize)); err != nil {
		return err
	}
	s.manifest, s.generation = result, latest.generation
	s.committedEnd = latest.offset + int64(latest.header.ManifestLen)
	return nil
}

func readManifest(file *os.File, h header, offset, size int64, key []byte, digest [32]byte) (manifest, error) {
	if offset < 0 || offset > size || h.ManifestLen > maxManifestSize || h.ManifestLen > uint64(size-offset) {
		return manifest{}, fmt.Errorf("invalid manifest length")
	}
	if h.Flags&flagManifestAES == 0 && len(key) != 0 {
		return manifest{}, fmt.Errorf("store is not manifest-encrypted")
	}
	encoded := make([]byte, h.ManifestLen)
	if _, err := file.ReadAt(encoded, offset); err != nil {
		return manifest{}, fmt.Errorf("read store manifest: %w", err)
	}
	if sha256.Sum256(encoded) != digest {
		return manifest{}, fmt.Errorf("store manifest checksum mismatch")
	}
	return unmarshalManifest(h, encoded, key)
}

// lockLatest serializes this Store with every other Store and process using the
// same blob, then reloads the manifest so an operation never uses stale offsets.
func (s *Store) lockLatest() error {
	// Serialize goroutines sharing this Store first.
	s.lock.Lock()

	// Serialize independently opened Stores and cooperating processes next.
	if err := s.fileLock.Lock(); err != nil {
		s.lock.Unlock()
		return fmt.Errorf("lock store: %w", err)
	}

	// Refresh state while both the manifest and blob generation are stable.
	if err := s.load(); err != nil {
		s.fileLock.Unlock()
		s.lock.Unlock()
		return err
	}

	return nil
}

func (s *Store) unlockLatest() {
	s.fileLock.Unlock()
	s.lock.Unlock()
}

func validateManifest(value manifest, dataSize int64, chunkSize int) error {
	// Every store must begin with one valid virtual root.
	root, ok := value.Entries["."]
	if !ok || !root.Directory {
		return fmt.Errorf("store manifest has no root")
	}

	// Validate paths, entry types, and every referenced ciphertext range.
	type chunkRange struct {
		start int64
		end   int64
	}
	ranges := []chunkRange{}

	for name, item := range value.Entries {
		if !fs.ValidPath(name) {
			return fmt.Errorf("store manifest contains invalid path %q", name)
		}

		if name != "." {
			parent, exists := value.Entries[path.Dir(name)]
			if !exists || !parent.Directory {
				return fmt.Errorf("file %q has no parent directory", name)
			}
		}

		if item.Directory {
			if item.Size != 0 || len(item.Key) != 0 || len(item.Chunks) != 0 || len(item.Revision) != 0 {
				return fmt.Errorf("directory %q contains file data", name)
			}
			continue
		}

		if len(item.Key) != 32 || item.Size < 0 || (len(item.Revision) != 0 && len(item.Revision) != 32) {
			return fmt.Errorf("file %q has invalid metadata", name)
		}

		var size int64
		for index, part := range item.Chunks {
			if len(part.ID) != 32 {
				return fmt.Errorf("invalid chunk identity")
			}
			if part.Offset < dataStart || (index < len(item.Chunks)-1 && part.Size != chunkSize) {
				return fmt.Errorf("invalid chunk layout")
			}
			if part.Offset < 0 || part.Size <= 0 || part.Size > chunkSize {
				return fmt.Errorf("file %q has invalid chunk metadata", name)
			}

			cipherSize := int64(part.Size) + 16
			if part.Offset > dataSize-cipherSize {
				return fmt.Errorf("file %q has invalid chunk metadata", name)
			}
			if size > int64(^uint64(0)>>1)-int64(part.Size) {
				return fmt.Errorf("file %q has inconsistent size", name)
			}

			ranges = append(ranges, chunkRange{start: part.Offset, end: part.Offset + cipherSize})
			size += int64(part.Size)
		}

		if size != item.Size {
			return fmt.Errorf("file %q has inconsistent size", name)
		}
	}

	// Live ciphertext ranges must never overlap.
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	expectedOffset := int64(0)
	for _, chunkRange := range ranges {
		if chunkRange.start < expectedOffset {
			return fmt.Errorf("store manifest contains overlapping chunk data")
		}
		expectedOffset = chunkRange.end
	}

	return nil
}

// commit appends only staged ciphertext and a complete metadata snapshot.
// The caller holds the process lock and has loaded the latest committed state.
func (s *Store) commit(replacement *pendingFile) error {
	file, err := os.OpenFile(s.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	// Discard only uncommitted tails left by a failed append.
	if err := file.Truncate(s.committedEnd); err != nil {
		return err
	}
	if _, err := file.Seek(s.committedEnd, io.SeekStart); err != nil {
		return err
	}
	destination := cloneManifest(s.manifest)
	if replacement != nil {
		item := destination.Entries[replacement.name]
		for index, part := range item.Chunks {
			sourcePart, staged := replacement.chunks[index]
			if replacement.chunks == nil {
				sourcePart, staged = part, true
			}
			if !staged {
				continue
			}
			offset, err := file.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			if _, err := io.CopyN(file, io.NewSectionReader(replacement.file, sourcePart.Offset, int64(part.Size+16)), int64(part.Size+16)); err != nil {
				return fmt.Errorf("append chunk: %w", err)
			}
			item.Chunks[index].Offset = offset
		}
		destination.Entries[replacement.name] = item
	}
	root, err := s.publish(file, destination, s.generation+1)
	if err != nil {
		return err
	}
	s.manifest, s.generation, s.committedEnd = destination, root.generation, root.offset+int64(root.header.ManifestLen)
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

// publish syncs payload and metadata before replacing the older commit slot.
// A final sync failure has an uncertain outcome; the next operation reloads it.
func (s *Store) publish(file *os.File, destination manifest, generation uint64) (commitRoot, error) {
	if generation == 0 {
		return commitRoot{}, fmt.Errorf("commit generation exhausted")
	}
	h, encoded, err := marshalManifest(destination, s.key, s.chunkSize)
	if err != nil {
		return commitRoot{}, err
	}
	if len(encoded) > maxManifestSize {
		return commitRoot{}, fmt.Errorf("manifest exceeds maximum size")
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return commitRoot{}, err
	}
	if err := validateManifest(destination, offset, s.chunkSize); err != nil {
		return commitRoot{}, err
	}
	if _, err := file.Write(encoded); err != nil {
		return commitRoot{}, err
	}
	if err := file.Sync(); err != nil {
		return commitRoot{}, err
	}
	root := commitRoot{header: h, generation: generation, offset: offset, digest: sha256.Sum256(encoded)}
	slot := int64(1 + (generation-1)%2)
	if _, err := file.WriteAt(encodeRoot(root), slot*rootSpacing); err != nil {
		return commitRoot{}, err
	}
	if err := file.Sync(); err != nil {
		return commitRoot{}, err
	}
	return root, nil
}

// Compact reclaims obsolete ciphertext and metadata by atomically replacing the
// blob. Existing readers retain their snapshots.
func (s *Store) Compact(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.lockLatest(); err != nil {
		return err
	}
	defer s.unlockLatest()
	return s.rewrite(ctx)
}

func (s *Store) rewrite(ctx context.Context) error {
	destination := cloneManifest(s.manifest)
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".sandboxed-*")
	if err != nil {
		return err
	}
	defer func() { temporary.Close(); os.Remove(temporary.Name()) }()
	if err := temporary.Chmod(s.fileMode); err != nil {
		return err
	}
	flags := uint16(0)
	if len(s.key) != 0 {
		flags = flagManifestAES
	}
	if _, err := temporary.Write(encodeHeader(header{Flags: flags, ChunkSize: uint32(s.chunkSize)})); err != nil {
		return err
	}
	if _, err := temporary.Seek(dataStart, io.SeekStart); err != nil {
		return err
	}
	old, oldErr := os.Open(s.path)
	if oldErr == nil {
		defer old.Close()
	}

	// Copy live ciphertext without decrypting it, preserving reader snapshots.
	names := make([]string, 0, len(destination.Entries))
	for name := range destination.Entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		item := destination.Entries[name]
		for index, part := range item.Chunks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if old == nil {
				return fmt.Errorf("missing source data for %q: %w", name, oldErr)
			}
			offset, err := temporary.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			if _, err := io.CopyN(temporary, io.NewSectionReader(old, part.Offset, int64(part.Size+16)), int64(part.Size+16)); err != nil {
				return fmt.Errorf("copy chunk for %q: %w", name, err)
			}
			item.Chunks[index].Offset = offset
		}
		destination.Entries[name] = item
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := s.publish(temporary, destination, 1)
	if err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), s.path); err != nil {
		return err
	}
	s.manifest, s.generation, s.committedEnd = destination, 1, root.offset+int64(root.header.ManifestLen)
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func randomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	return key, err
}
