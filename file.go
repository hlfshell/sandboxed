package sandboxed

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"time"
)

type pendingFile struct {
	name string
	file *os.File
}

type writer struct {
	store  *Store
	name   string
	key    []byte
	file   *os.File
	buffer []byte
	entry  entry
	closed bool
	err    error
}

// Create returns a streaming writer which atomically publishes the file when
// Close succeeds. Abandoning a writer leaves the store unchanged.
func (s *Store) Create(name string) (io.WriteCloser, error) {
	// Validate the virtual destination against the latest manifest.
	if err := cleanName(name); err != nil || name == "." {
		if err != nil {
			return nil, err
		}
		return nil, &fs.PathError{Op: "create", Path: name, Err: fs.ErrInvalid}
	}
	if err := s.lockLatest(); err != nil {
		return nil, err
	}
	parent, ok := s.manifest.Entries[path.Dir(name)]
	existing, exists := s.manifest.Entries[name]
	s.unlockLatest()
	if !ok || !parent.Directory {
		return nil, &fs.PathError{Op: "create", Path: name, Err: fs.ErrNotExist}
	}
	if exists && existing.Directory {
		return nil, &fs.PathError{Op: "create", Path: name, Err: fs.ErrInvalid}
	}

	// Give this file a unique encryption key and private staging file.
	key, err := randomKey()
	if err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp("", "sandboxed-file-*")
	if err != nil {
		return nil, err
	}

	return &writer{
		store: s, name: name, key: key, file: temporary,
		buffer: make([]byte, 0, s.chunkSize), entry: entry{Key: key, Chunks: []chunk{}},
	}, nil
}

func (w *writer) Write(p []byte) (int, error) {
	// Reject writes after completion or an earlier staging failure.
	if w.closed {
		return 0, fs.ErrClosed
	}
	if w.err != nil {
		return 0, w.err
	}

	// Fill and encrypt one configured chunk at a time.
	written := 0
	for len(p) != 0 {
		available := cap(w.buffer) - len(w.buffer)
		amount := len(p)
		if amount > available {
			amount = available
		}
		w.buffer = append(w.buffer, p[:amount]...)
		p = p[amount:]
		written += amount
		if len(w.buffer) == cap(w.buffer) {
			if err := w.flush(); err != nil {
				w.err = err
				return written, err
			}
		}
	}

	return written, nil
}

func (w *writer) flush() error {
	if len(w.buffer) == 0 {
		return nil
	}

	// Authenticate the chunk position and size while encrypting its payload.
	aead, err := fileAEAD(w.key)
	if err != nil {
		return err
	}
	position := uint64(len(w.entry.Chunks))
	ciphertext := aead.Seal(nil, chunkNonce(w.key, position), w.buffer, chunkAdditionalData(position, len(w.buffer)))

	// Append only ciphertext to the staging file and record its location.
	offset, err := w.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if _, err := w.file.Write(ciphertext); err != nil {
		return err
	}
	w.entry.Chunks = append(w.entry.Chunks, chunk{Offset: offset, Size: len(w.buffer)})
	w.entry.Size += int64(len(w.buffer))
	w.buffer = w.buffer[:0]

	return nil
}

func (w *writer) Close() error {
	// Finalize the private encrypted staging file before taking the store lock.
	if w.closed {
		return fs.ErrClosed
	}
	w.closed = true
	defer func() { w.file.Close(); os.Remove(w.file.Name()) }()
	if w.err != nil {
		return w.err
	}
	if err := w.flush(); err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}

	// Reload the latest manifest and verify the destination still accepts a file.
	if err := w.store.lockLatest(); err != nil {
		return err
	}
	defer w.store.unlockLatest()
	parent, ok := w.store.manifest.Entries[path.Dir(w.name)]
	if !ok || !parent.Directory {
		return &fs.PathError{Op: "create", Path: w.name, Err: fs.ErrNotExist}
	}
	previous, existed := w.store.manifest.Entries[w.name]
	if existed && previous.Directory {
		return &fs.PathError{Op: "create", Path: w.name, Err: fs.ErrInvalid}
	}

	// Publish the staged ciphertext atomically, restoring state on failure.
	w.store.manifest.Entries[w.name] = w.entry
	if err := w.store.rewrite(&pendingFile{name: w.name, file: w.file}); err != nil {
		if existed {
			w.store.manifest.Entries[w.name] = previous
		} else {
			delete(w.store.manifest.Entries, w.name)
		}
		return err
	}

	return nil
}

type openFile struct {
	name       string
	entry      entry
	file       *os.File
	dataOffset int64
	offset     int64
	chunkIndex int
	plain      []byte
	plainStart int64
	closed     bool
}

func (s *Store) Open(name string) (fs.File, error) {
	// Resolve the entry from the latest complete manifest.
	if err := cleanName(name); err != nil {
		return nil, err
	}
	if err := s.lockLatest(); err != nil {
		return nil, err
	}
	defer s.unlockLatest()
	item, ok := s.manifest.Entries[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	// Open the same blob snapshot used by this manifest before releasing the lock.
	file, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, headerSize)
	_, err = io.ReadFull(file, buffer)
	if err != nil {
		file.Close()
		return nil, err
	}
	h, err := decodeHeader(buffer)
	if err != nil {
		file.Close()
		return nil, err
	}

	// Return the specialized virtual handle for this entry type.
	if item.Directory {
		return &directoryFile{store: s, file: file, name: name}, nil
	}
	return &openFile{name: name, entry: item, file: file, dataOffset: headerSize + int64(h.ManifestLen), chunkIndex: -1}, nil
}

func (f *openFile) Stat() (fs.FileInfo, error) {
	if f.closed {
		return nil, fs.ErrClosed
	}
	return fileInfo{name: path.Base(f.name), size: f.entry.Size}, nil
}

func (f *openFile) Close() error { f.closed = true; return f.file.Close() }

func (f *openFile) Read(p []byte) (int, error) {
	// Validate the reader state before locating ciphertext.
	if f.closed {
		return 0, fs.ErrClosed
	}
	if f.offset >= f.entry.Size {
		return 0, io.EOF
	}

	// Decrypt at most one chunk at a time and copy from its plaintext window.
	written := 0
	for len(p) != 0 && f.offset < f.entry.Size {
		index, start := f.chunkAt(f.offset)
		if index < 0 {
			return written, fmt.Errorf("read %q: invalid chunk index", f.name)
		}
		if f.chunkIndex != index {
			if err := f.loadChunk(index, start); err != nil {
				return written, err
			}
		}
		inside := int(f.offset - f.plainStart)
		amount := copy(p, f.plain[inside:])
		p = p[amount:]
		written += amount
		f.offset += int64(amount)
	}

	return written, nil
}

func (f *openFile) Seek(offset int64, whence int) (int64, error) {
	if f.closed {
		return 0, fs.ErrClosed
	}
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = f.offset + offset
	case io.SeekEnd:
		next = f.entry.Size + offset
	default:
		return 0, errors.New("invalid seek whence")
	}
	if next < 0 {
		return 0, errors.New("negative seek position")
	}
	f.offset = next
	return next, nil
}

func (f *openFile) chunkAt(offset int64) (int, int64) {
	var start int64
	for index, part := range f.entry.Chunks {
		if offset < start+int64(part.Size) {
			return index, start
		}
		start += int64(part.Size)
	}
	return -1, start
}

func (f *openFile) loadChunk(index int, start int64) error {
	// Read only the requested ciphertext range from the immutable blob snapshot.
	part := f.entry.Chunks[index]
	ciphertext := make([]byte, part.Size+16)
	if _, err := f.file.ReadAt(ciphertext, f.dataOffset+part.Offset); err != nil {
		return fmt.Errorf("read chunk %d for %q: %w", index, f.name, err)
	}

	// Authenticate the chunk metadata before exposing any plaintext.
	aead, err := fileAEAD(f.entry.Key)
	if err != nil {
		return err
	}
	plain, err := aead.Open(nil, chunkNonce(f.entry.Key, uint64(index)), ciphertext, chunkAdditionalData(uint64(index), part.Size))
	if err != nil {
		return fmt.Errorf("decrypt chunk %d for %q: %w", index, f.name, err)
	}

	f.chunkIndex, f.plainStart, f.plain = index, start, plain

	return nil
}

type directoryFile struct {
	store  *Store
	file   *os.File
	name   string
	offset int
	closed bool
}

func (d *directoryFile) Stat() (fs.FileInfo, error) {
	if d.closed {
		return nil, fs.ErrClosed
	}
	return fileInfo{name: path.Base(d.name), directory: true}, nil
}
func (d *directoryFile) Close() error { d.closed = true; return d.file.Close() }
func (d *directoryFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}
func (d *directoryFile) ReadDir(count int) ([]fs.DirEntry, error) {
	if d.closed {
		return nil, fs.ErrClosed
	}
	entries, err := d.store.ReadDir(d.name)
	if err != nil {
		return nil, err
	}
	if d.offset >= len(entries) && count > 0 {
		return nil, io.EOF
	}
	end := len(entries)
	if count > 0 && d.offset+count < end {
		end = d.offset + count
	}
	result := entries[d.offset:end]
	d.offset = end
	return result, nil
}

func (s *Store) Stat(name string) (fs.FileInfo, error) {
	if err := cleanName(name); err != nil {
		return nil, err
	}
	if err := s.lockLatest(); err != nil {
		return nil, err
	}
	defer s.unlockLatest()
	item, ok := s.manifest.Entries[name]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return fileInfo{name: path.Base(name), size: item.Size, directory: item.Directory}, nil
}

func (s *Store) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := cleanName(name); err != nil {
		return nil, err
	}
	if err := s.lockLatest(); err != nil {
		return nil, err
	}
	defer s.unlockLatest()
	item, ok := s.manifest.Entries[name]
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	if !item.Directory {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}
	result := []fs.DirEntry{}
	for candidate, child := range s.manifest.Entries {
		if candidate != name && path.Dir(candidate) == name {
			result = append(result, dirEntry{fileInfo{name: path.Base(candidate), size: child.Size, directory: child.Directory}})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name() < result[j].Name() })
	return result, nil
}

type fileInfo struct {
	name      string
	size      int64
	directory bool
}

func (i fileInfo) Name() string { return i.name }
func (i fileInfo) Size() int64  { return i.size }
func (i fileInfo) Mode() fs.FileMode {
	if i.directory {
		return fs.ModeDir | 0500
	}
	return 0400
}
func (i fileInfo) ModTime() time.Time { return time.Time{} }
func (i fileInfo) IsDir() bool        { return i.directory }
func (i fileInfo) Sys() any           { return nil }

type dirEntry struct{ fileInfo }

func (d dirEntry) Type() fs.FileMode          { return d.Mode().Type() }
func (d dirEntry) Info() (fs.FileInfo, error) { return d.fileInfo, nil }
