package sandboxed

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"sync"
	"time"
)

type openFile struct {
	mutex      sync.Mutex
	store      *Store
	name       string
	entry      entry
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

	s.handles++
	if item.Directory {
		return &directoryFile{store: s, name: name}, nil
	}
	s.retain(item)
	return &openFile{store: s, name: name, entry: item, chunkIndex: -1}, nil
}

func (f *openFile) Stat() (fs.FileInfo, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed {
		return nil, fs.ErrClosed
	}
	return fileInfo{name: path.Base(f.name), size: f.entry.Size}, nil
}

func (f *openFile) Close() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed {
		return fs.ErrClosed
	}
	f.closed = true
	f.store.lock.Lock()
	defer f.store.lock.Unlock()
	f.store.handles--
	f.store.release(f.entry)
	return f.store.collect()
}

func (f *openFile) Read(p []byte) (int, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
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
	f.mutex.Lock()
	defer f.mutex.Unlock()
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
	part := f.entry.Chunks[index]
	plain, err := f.store.readChunk(f.entry.Key, index, part)
	if err != nil {
		return err
	}

	f.chunkIndex, f.plainStart, f.plain = index, start, plain

	return nil
}

type directoryFile struct {
	mutex  sync.Mutex
	store  *Store
	name   string
	offset int
	closed bool
}

func (d *directoryFile) Stat() (fs.FileInfo, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.closed {
		return nil, fs.ErrClosed
	}
	return fileInfo{name: path.Base(d.name), directory: true}, nil
}
func (d *directoryFile) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.closed {
		return fs.ErrClosed
	}
	d.closed = true
	d.store.lock.Lock()
	defer d.store.lock.Unlock()
	d.store.handles--
	return nil
}
func (d *directoryFile) Read([]byte) (int, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.closed {
		return 0, fs.ErrClosed
	}
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}
func (d *directoryFile) ReadDir(count int) ([]fs.DirEntry, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
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
