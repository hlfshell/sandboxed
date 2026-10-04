package sandboxed

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"sync"

	"golang.org/x/sys/unix"
)

// ErrConflict means the file changed after Create or Update captured its snapshot.
// Open a new handle to retry against the current contents.
var ErrConflict = errors.New("file changed while open")

// File is a virtual regular file with transactional writes. Read and Write share
// a seek position; ReadAt and WriteAt do not change it. Close publishes changes
// atomically and Abort discards them. Calls on a handle are serialized.
// File never exposes a host filesystem handle. Unwritten regions read as zeros without allocating chunks.
// Logical file sizes are limited to 524,288 chunk positions; the full store manifest
// must also fit the 64 MiB metadata limit.
type File struct {
	mutex     sync.Mutex
	store     *Store
	source    *openFile
	file      *os.File
	item      entry
	dirty     map[int]chunk
	positions map[int]int
	offset    int64
	existed   bool
	changed   bool
	closed    bool
	err       error

	// Scratch buffers are bounded by chunk size and never exposed to callers.
	plain      []byte
	ciphertext []byte
	staging    map[int]string
}

// Bound logical chunk positions and per-file metadata before accepting offsets.
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
	result := &File{store: s, source: &openFile{store: s, name: name, entry: base, writable: true}, item: item, existed: exists, changed: replace, dirty: make(map[int]chunk), staging: make(map[int]string)}

	result.indexChunks()
	s.handles++
	s.writers++
	s.retain(base)
	return result, nil
}

// Write writes at the current position.
// Writes beyond EOF leave unallocated, zero-filled gaps.
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

// WriteAt immediately encrypts p without changing the seek position. Gaps
// read as zeros without allocating payload chunks.
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

// Bound the logical file span independently of its allocated chunks.
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
	f.item.Size, f.changed = size, true
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
		within := int(offset % int64(f.store.chunkSize))
		amount := int(min(int64(len(p)), int64(f.store.chunkSize-within), f.item.Size-offset))
		copied := 0
		if within < len(plain) {
			copied = copy(p[:amount], plain[within:])
		}
		clear(p[copied:amount])
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
	position, exists := f.chunkPosition(index)
	if !exists {
		return nil, nil
	}
	part := f.item.Chunks[position]
	if _, dirty := f.dirty[index]; !dirty {
		plain, err := f.store.readChunkInto(f.plain, f.item.Key, index, part)
		if err != nil {
			return nil, err
		}
		f.plain = plain
		return plain, nil
	}
	ciphertext := resizeBuffer(f.plain, part.Size+16)
	file, err := f.stagingFile(index)
	if err != nil {
		return nil, err
	}
	if _, err := file.ReadAt(ciphertext, 0); err != nil {
		return nil, err
	}
	plain, err := decryptChunkInto(ciphertext[:0], f.item.Key, index, part, ciphertext)
	if err != nil {
		return nil, err
	}
	f.plain = plain
	return plain, nil
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
// creates unallocated zero-filled regions. Shrinking discards data, including
// earlier writes; subsequent growth never restores discarded contents.
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
		position, exists := f.chunkPosition(count - 1)
		if exists && f.item.Chunks[position].Size > tail {
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
	}

	// Compact only allocated records, preserving private slot offsets for reuse.
	kept := 0
	for _, part := range f.item.Chunks {
		if part.Index < count {
			f.item.Chunks[kept] = part
			kept++
		}
	}
	clear(f.item.Chunks[kept:])
	f.item.Chunks = f.item.Chunks[:kept]
	f.indexChunks()
	f.item.Size, f.changed = size, true
	return nil
}

func (f *File) writeChunk(p []byte, offset int64) (int, error) {
	size := f.store.chunkSize
	index, within := int(offset/int64(size)), int(offset%int64(size))
	amount := min(len(p), size-within)

	// Authenticate the previous version before modifying its reusable buffer.
	var previous []byte
	if _, exists := f.chunkPosition(index); exists {
		var err error
		previous, err = f.loadChunk(index)
		if err != nil {
			return 0, err
		}
	}

	length := max(len(previous), within+amount)
	plain := resizeBuffer(f.plain, length)
	if len(previous) != 0 {
		copy(plain, previous)
	}
	// Only a gap needs zeroing; the incoming bytes overwrite the rest.
	if within > len(previous) {
		clear(plain[len(previous):within])
	}
	f.plain = plain
	copy(plain[within:], p[:amount])

	if err := f.stageChunk(index, plain); err != nil {
		return 0, err
	}
	f.item.Size = max(f.item.Size, offset+int64(amount))
	return amount, nil
}

func (f *File) stageChunk(index int, plain []byte) error {
	f.ciphertext = resizeBuffer(f.ciphertext, len(plain)+16)
	part, ciphertext, err := sealChunkInto(f.ciphertext, f.item.Key, uint64(index), plain)
	if err != nil {
		return err
	}
	f.ciphertext = ciphertext

	// Reuse a private ciphertext file for this chunk. Publication renames it;
	// no payload bytes are copied at commit and no plaintext reaches the file.
	file, err := f.stagingFile(index)
	if err != nil {
		return err
	}
	if _, err := file.WriteAt(ciphertext, 0); err != nil {
		return fmt.Errorf("stage file chunk: %w", err)
	}
	if previous, exists := f.dirty[index]; exists && previous.Size > len(plain) {
		if err := file.Truncate(int64(len(ciphertext))); err != nil {
			return err
		}
	}
	position, exists := f.chunkPosition(index)
	if exists {
		f.item.Chunks[position] = part
	} else {
		if f.positions == nil && index != len(f.item.Chunks) {
			f.positions = make(map[int]int, len(f.item.Chunks)+1)
			for i, existing := range f.item.Chunks {
				f.positions[existing.Index] = i
			}
		}
		if f.positions != nil {
			f.positions[index] = len(f.item.Chunks)
		}
		f.item.Chunks = append(f.item.Chunks, part)
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
	if f.positions != nil {
		sort.Slice(f.item.Chunks, func(i, j int) bool { return f.item.Chunks[i].Index < f.item.Chunks[j].Index })
	}
	return f.store.submit(f)
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
	clear(f.plain[:cap(f.plain)])
	f.plain, f.ciphertext = nil, nil
	var err error
	if f.file != nil {
		err = f.file.Close()
		f.file = nil
	}
	for _, name := range f.staging {
		err = errors.Join(err, removeInternal(f.store.root, name))
	}
	return errors.Join(err, f.source.Close())
}

// Writable layouts append newly allocated chunks in any order. Build an index
// only for sparse layouts so random insertion stays O(1) without dense overhead.
func (f *File) indexChunks() {
	f.positions = nil
	for i, part := range f.item.Chunks {
		if part.Index != i {
			f.positions = make(map[int]int, len(f.item.Chunks))
			for position, part := range f.item.Chunks {
				f.positions[part.Index] = position
			}
			return
		}
	}
}

func (f *File) chunkPosition(index int) (int, bool) {
	if f.positions != nil {
		position, exists := f.positions[index]
		return position, exists
	}
	return index, index < len(f.item.Chunks)
}

// Cache only one descriptor per writer, even when it touches many chunks.
func (f *File) stagingFile(index int) (*os.File, error) {
	name, exists := f.staging[index]
	if f.file != nil && f.file.Name() == name {
		return f.file, nil
	}
	if f.file != nil {
		if err := f.file.Close(); err != nil {
			return nil, err
		}
		f.file = nil
	}
	var file *os.File
	var err error
	if exists {
		file, err = openInternal(f.store.root, name, unix.O_RDWR, 0)
	} else {
		file, err = f.store.temporary(".staging-")
	}
	if err != nil {
		return nil, err
	}
	f.file = file
	f.staging[index] = file.Name()
	return file, nil
}
