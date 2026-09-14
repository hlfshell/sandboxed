package sandboxed

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"os"
	"path"
	"sync"
)

// ErrConflict means the file changed after Create or Update captured its snapshot.
// Open a new handle to retry against the current contents.
var ErrConflict = errors.New("file changed while open")

// File is a virtual regular file with transactional writes. Read and Write share
// a seek position; ReadAt and WriteAt do not change it. Close publishes changes
// atomically and Abort discards them. Calls on a handle are serialized.
// File never exposes a host filesystem handle. Gaps are stored as encrypted zeros.
// Writable file sizes are limited to 524,288 chunks; the full store manifest
// must also fit the 64 MiB metadata limit.
type File struct {
	mutex   sync.Mutex
	store   *Store
	source  *openFile
	file    *os.File
	item    entry
	dirty   map[int]chunk
	offset  int64
	existed bool
	changed bool
	closed  bool
	err     error
}

// Reserve 128 bytes of manifest budget per chunk before accepting an offset.
const maxFileChunks = maxManifestSize / 128

var (
	_ fs.File            = (*File)(nil)
	_ io.ReadWriteSeeker = (*File)(nil)
	_ io.ReaderAt        = (*File)(nil)
	_ io.WriterAt        = (*File)(nil)
)

// Create creates or replaces a virtual file. The returned handle supports reads,
// writes, seeking, and truncation. Close publishes the replacement atomically;
// Abort discards it. Concurrent changes to the same file return ErrConflict.
func (s *Store) Create(name string) (*File, error) {
	return s.openWritable(name, true)
}

// Update opens an existing virtual file without clearing its contents. Writes
// automatically update only affected chunks. Close publishes changes atomically;
// Abort discards them. Concurrent changes to the same file return ErrConflict.
func (s *Store) Update(name string) (*File, error) {
	return s.openWritable(name, false)
}

func (s *Store) openWritable(name string, replace bool) (*File, error) {
	if err := cleanName(name); err != nil {
		return nil, err
	}
	if err := s.lockLatest(); err != nil {
		return nil, err
	}
	defer s.unlockLatest()
	base, exists := s.manifest.Entries[name]
	if exists && base.Directory {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if !exists && !replace {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	parent, ok := s.manifest.Entries[path.Dir(name)]
	if !ok || !parent.Directory {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	// Capture the source while its generation is stable. New files retain an empty
	// base so concurrent creation can be detected at commit time.
	var err error
	item := base
	if replace {
		item.Key, err = randomKey()
		if err != nil {
			return nil, err
		}
		item.Size, item.Chunks = 0, nil
	} else {
		item.Chunks = append([]chunk(nil), base.Chunks...)
	}
	result := &File{store: s, source: &openFile{store: s, name: name, entry: base}, item: item, existed: exists, changed: replace, dirty: make(map[int]chunk)}
	result.file, err = s.temporary(".staging-")
	if err != nil {
		return nil, err
	}

	s.handles++
	s.retain(base)
	return result, nil
}

// Write writes at the current position.
// Writes beyond EOF fill the gap with encrypted zero bytes.
func (f *File) Write(p []byte) (int, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	offset := f.offset
	n, err := f.writeAt(p, offset)
	if n > 0 {
		f.offset = offset + int64(n)
	}
	return n, err
}

// WriteAt stages p without changing the seek position. Gaps are filled with
// encrypted zero bytes.
func (f *File) WriteAt(p []byte, offset int64) (int, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	return f.writeAt(p, offset)
}

func (f *File) writable() error {
	if f.closed {
		return fs.ErrClosed
	}
	return f.err
}

// Bound the metadata implied by an offset before allocating or filling a gap.
// The full manifest, including other files, is also bounded at commit.
func (f *File) validSize(size int64) bool {
	return size >= 0 && size <= int64(f.store.chunkSize)*maxFileChunks
}

func (f *File) writeAt(p []byte, offset int64) (int, error) {
	if err := f.writable(); err != nil {
		return 0, err
	}
	if !f.validSize(offset) || int64(len(p)) > int64(f.store.chunkSize)*maxFileChunks-offset {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := f.grow(offset); err != nil {
		f.err = err
		return 0, err
	}
	written := 0
	for len(p) != 0 {
		amount, err := f.writeChunk(p, offset)
		if err != nil {
			f.err = err
			return written, err
		}
		written += amount
		offset += int64(amount)
		p = p[amount:]
	}
	return written, nil
}

func (f *File) grow(size int64) error {
	if size <= f.item.Size {
		return nil
	}
	zeros := make([]byte, f.store.chunkSize)
	for f.item.Size < size {
		amount := min(int64(len(zeros)), size-f.item.Size)
		if _, err := f.writeChunk(zeros[:amount], f.item.Size); err != nil {
			return err
		}
	}
	return nil
}

// Read reads staged contents at the current seek position.
func (f *File) Read(p []byte) (int, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	n, err := f.readAt(p, f.offset)
	f.offset += int64(n)
	if n > 0 && err == io.EOF {
		err = nil
	}
	return n, err
}

// ReadAt reads staged contents without changing the seek position.
func (f *File) ReadAt(p []byte, offset int64) (int, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.readAt(p, offset)
}

func (f *File) readAt(p []byte, offset int64) (int, error) {
	if f.closed {
		return 0, fs.ErrClosed
	}
	if offset < 0 {
		return 0, fs.ErrInvalid
	}
	written := 0
	for len(p) != 0 && offset < f.item.Size {
		index := int(offset / int64(f.store.chunkSize))
		plain, err := f.loadChunk(index)
		if err != nil {
			return written, err
		}
		amount := copy(p, plain[offset%int64(f.store.chunkSize):])
		written += amount
		offset += int64(amount)
		p = p[amount:]
	}
	if len(p) != 0 {
		return written, io.EOF
	}
	return written, nil
}

func (f *File) loadChunk(index int) ([]byte, error) {
	part := f.item.Chunks[index]
	if _, dirty := f.dirty[index]; !dirty {
		return f.store.readChunk(f.item.Key, index, part)
	}
	ciphertext := make([]byte, part.Size+16)
	if _, err := f.file.ReadAt(ciphertext, part.Offset); err != nil {
		return nil, err
	}
	return decryptChunk(f.item.Key, index, part, ciphertext)
}

// Seek sets the position used by Read and Write. Seeking beyond EOF does not
// extend the file until a nonempty write is made.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = f.offset
	case io.SeekEnd:
		base = f.item.Size
	default:
		return 0, fs.ErrInvalid
	}
	if offset < -base || offset > int64(^uint64(0)>>1)-base {
		return 0, fs.ErrInvalid
	}
	f.offset = base + offset
	return f.offset, nil
}

// Stat reports the staged size. It does not expose host permissions or handles.
func (f *File) Stat() (fs.FileInfo, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed {
		return nil, fs.ErrClosed
	}
	return fileInfo{name: path.Base(f.source.name), size: f.item.Size}, nil
}

// Truncate changes the staged size without changing the seek position. Extending
// fills with encrypted zeros. Shrinking discards data, including earlier writes.
func (f *File) Truncate(size int64) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if err := f.writable(); err != nil {
		return err
	}
	if !f.validSize(size) {
		return fs.ErrInvalid
	}
	if size >= f.item.Size {
		if err := f.grow(size); err != nil {
			f.err = err
			return err
		}
		return nil
	}
	count := int((size + int64(f.store.chunkSize) - 1) / int64(f.store.chunkSize))
	if tail := int(size % int64(f.store.chunkSize)); tail != 0 {
		plain, err := f.loadChunk(count - 1)
		if err != nil {
			f.err = err
			return err
		}
		if err := f.stageChunk(count-1, plain[:tail]); err != nil {
			f.err = err
			return err
		}
	}
	f.item.Chunks = f.item.Chunks[:count]
	for index := range f.dirty {
		if index >= count {
			delete(f.dirty, index)
		}
	}
	f.item.Size, f.changed = size, true
	return nil
}

func (f *File) writeChunk(p []byte, offset int64) (int, error) {
	size := f.store.chunkSize
	index, within := int(offset/int64(size)), int(offset%int64(size))
	amount := min(len(p), size-within)
	plain := make([]byte, within+amount)

	// Authenticate the previous version, including earlier writes by this file handle.
	if index < len(f.item.Chunks) {
		previous, err := f.loadChunk(index)
		if err != nil {
			return 0, err
		}
		if len(previous) > len(plain) {
			plain = append(plain, make([]byte, len(previous)-len(plain))...)
		}
		copy(plain, previous)
	}
	copy(plain[within:], p[:amount])

	if err := f.stageChunk(index, plain); err != nil {
		return 0, err
	}
	f.item.Size = max(f.item.Size, offset+int64(amount))
	return amount, nil
}

func (f *File) stageChunk(index int, plain []byte) error {
	part, ciphertext, err := sealChunk(f.item.Key, uint64(index), plain)
	if err != nil {
		return err
	}
	part.Offset, err = f.file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if _, err := f.file.Write(ciphertext); err != nil {
		return fmt.Errorf("stage file chunk: %w", err)
	}
	if index == len(f.item.Chunks) {
		f.item.Chunks = append(f.item.Chunks, part)
	} else {
		f.item.Chunks[index] = part
	}
	f.dirty[index], f.changed = part, true
	return nil
}

// Close publishes all staged updates together and releases resources, including
// on failure. Repeated calls return fs.ErrClosed. A sync error may have an
// uncertain commit outcome; reopen the file to inspect the latest state.
func (f *File) Close() (err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed {
		return fs.ErrClosed
	}
	f.closed = true
	defer func() { err = errors.Join(err, f.cleanup()) }()
	if f.err != nil {
		return f.err
	}
	if !f.changed {
		return nil
	}
	if err := f.store.lockLatest(); err != nil {
		return err
	}
	defer f.store.unlockLatest()
	previous, exists := f.store.manifest.Entries[f.source.name]
	if exists != f.existed || (exists && (previous.Directory || !bytes.Equal(previous.Key, f.source.entry.Key) || !bytes.Equal(previous.Revision, f.source.entry.Revision))) {
		return ErrConflict
	}

	parent, ok := f.store.manifest.Entries[path.Dir(f.source.name)]
	if !ok || !parent.Directory {
		return ErrConflict
	}

	// Publish each changed chunk under its immutable random name. Cleanup cannot
	// run concurrently because this commit holds the store mutex.
	for index, part := range f.dirty {
		if index >= len(f.item.Chunks) {
			continue
		}
		name := chunkName(part)
		output, err := openInternal(f.store.chunks, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, f.store.fileMode)
		if err != nil {
			return err
		}
		f.store.garbage[name] = struct{}{}
		_, copyErr := io.CopyN(output, io.NewSectionReader(f.file, part.Offset, int64(part.Size+16)), int64(part.Size+16))
		err = errors.Join(copyErr, output.Sync(), output.Close())
		if err != nil {
			return fmt.Errorf("publish chunk: %w", err)
		}
	}
	if err := f.store.chunks.Sync(); err != nil {
		return err
	}
	revision, err := randomKey()
	if err != nil {
		return err
	}
	f.item.Revision = revision
	next := cloneManifest(f.store.manifest)
	next.Entries[f.source.name] = f.item
	return f.store.commit(next)
}

// Abort discards staged updates and releases resources. It is safe to defer,
// including after Close or an earlier Abort.
func (f *File) Abort() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return f.cleanup()
}

func (f *File) cleanup() error {
	return errors.Join(f.file.Close(), removeInternal(f.store.root, f.file.Name()), f.source.Close())
}
