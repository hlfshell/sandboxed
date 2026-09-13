package sandboxed

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

func (s *Store) load() error {
	// Open a stable snapshot of the current blob.
	file, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Decode the header and bound the manifest before allocating for it.
	headerBytes := make([]byte, headerSize)
	if _, err := io.ReadFull(file, headerBytes); err != nil {
		return fmt.Errorf("read store header: %w", err)
	}

	value, err := decodeHeader(headerBytes)
	if err != nil {
		return err
	}

	info, err := file.Stat()
	if err != nil {
		return err
	}
	if value.ManifestLen > uint64(info.Size()-headerSize) {
		return fmt.Errorf("invalid manifest length")
	}
	if value.ManifestLen > maxManifestSize {
		return fmt.Errorf("manifest exceeds maximum size")
	}

	// Authenticate, decode, and validate all metadata before publishing it.
	encoded := make([]byte, value.ManifestLen)
	if _, err := io.ReadFull(file, encoded); err != nil {
		return fmt.Errorf("read store manifest: %w", err)
	}

	result, err := unmarshalManifest(value, encoded, s.key)
	if err != nil {
		return err
	}
	if value.Flags&flagManifestAES == 0 && len(s.key) != 0 {
		return fmt.Errorf("store is not manifest-encrypted")
	}
	if err := validateManifest(result, info.Size()-headerSize-int64(value.ManifestLen), int(value.ChunkSize)); err != nil {
		return err
	}

	// Publish the complete validated manifest together.
	s.chunkSize = int(value.ChunkSize)
	s.manifest = result

	return nil
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

		if item.Directory {
			if item.Size != 0 || len(item.Key) != 0 || len(item.Chunks) != 0 {
				return fmt.Errorf("directory %q contains file data", name)
			}
			continue
		}

		if len(item.Key) != 32 || item.Size < 0 {
			return fmt.Errorf("file %q has invalid metadata", name)
		}

		var size int64
		for _, part := range item.Chunks {
			if part.Offset < 0 || part.Size < 0 || part.Size > chunkSize {
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

	// Generated blobs pack every ciphertext chunk exactly once without gaps.
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	expectedOffset := int64(0)
	for _, chunkRange := range ranges {
		if chunkRange.start != expectedOffset {
			return fmt.Errorf("store manifest contains overlapping or missing chunk data")
		}
		expectedOffset = chunkRange.end
	}
	if expectedOffset != dataSize {
		return fmt.Errorf("store manifest does not reference all chunk data")
	}

	return nil
}

func (s *Store) rewrite(replacement *pendingFile) error {
	// Preserve source offsets and build an independent destination manifest.
	sourceEntries := make(map[string]entry, len(s.manifest.Entries))
	destination := manifest{Entries: make(map[string]entry, len(s.manifest.Entries))}

	for name, item := range s.manifest.Entries {
		copyItem := item
		copyItem.Chunks = append([]chunk(nil), item.Chunks...)
		sourceEntries[name] = copyItem

		destinationItem := item
		destinationItem.Key = append([]byte(nil), item.Key...)
		destinationItem.Chunks = append([]chunk(nil), item.Chunks...)
		destination.Entries[name] = destinationItem
	}

	// Calculate deterministic chunk ordering and destination offsets.
	names := make([]string, 0, len(destination.Entries))
	for name, item := range destination.Entries {
		if !item.Directory {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var offset int64
	for _, name := range names {
		item := destination.Entries[name]
		for index := range item.Chunks {
			item.Chunks[index].Offset = offset
			offset += int64(item.Chunks[index].Size + 16)
		}
		destination.Entries[name] = item
	}

	// Create the replacement blob and write its header and manifest.
	h, encoded, err := marshalManifest(destination, s.key, s.chunkSize)
	if err != nil {
		return err
	}

	directory := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(directory, ".sandboxed-*")
	if err != nil {
		return err
	}

	temporaryName := temporary.Name()
	committed := false
	defer func() {
		temporary.Close()
		if !committed {
			os.Remove(temporaryName)
		}
	}()

	if err := temporary.Chmod(s.fileMode); err != nil {
		return err
	}
	if _, err := temporary.Write(encodeHeader(h)); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}

	// Open the prior blob as the source for unchanged ciphertext chunks.
	old, oldErr := os.Open(s.path)
	if oldErr == nil {
		defer old.Close()
	}

	var oldDataOffset int64
	if oldErr == nil {
		buffer := make([]byte, headerSize)
		if _, err := io.ReadFull(old, buffer); err != nil {
			return err
		}

		oldHeader, err := decodeHeader(buffer)
		if err != nil {
			return err
		}
		oldDataOffset = headerSize + int64(oldHeader.ManifestLen)
	}

	// Stream ciphertext from either the old blob or the pending replacement.
	for _, name := range names {
		destinationItem := destination.Entries[name]
		sourceItem := sourceEntries[name]

		for index, part := range destinationItem.Chunks {
			var source io.Reader
			if replacement != nil && replacement.name == name {
				sourcePart := sourceItem.Chunks[index]
				source = io.NewSectionReader(replacement.file, sourcePart.Offset, int64(part.Size+16))
			} else {
				if oldErr != nil {
					return fmt.Errorf("missing source data for %q", name)
				}

				sourcePart := sourceItem.Chunks[index]
				source = io.NewSectionReader(old, oldDataOffset+sourcePart.Offset, int64(part.Size+16))
			}

			if _, err := io.CopyN(temporary, source, int64(part.Size+16)); err != nil {
				return fmt.Errorf("copy chunk for %q: %w", name, err)
			}
		}
	}

	// Sync and atomically publish the completed replacement.
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return err
	}

	// Publish in-memory state and make the directory rename durable where possible.
	s.manifest = destination
	if directoryFile, err := os.Open(directory); err == nil {
		directoryFile.Sync()
		directoryFile.Close()
	}
	committed = true

	return nil
}

func randomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	return key, err
}
