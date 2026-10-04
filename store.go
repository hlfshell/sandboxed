package sandboxed

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Store owns a directory of encrypted chunks and a private manifest. Store implements
// fs.FS, fs.ReadFileFS, fs.ReadDirFS, and fs.StatFS.
type Store struct {
	path          string
	chunkSize     int
	key           []byte
	fileMode      fs.FileMode
	manifest      manifest
	lock          sync.Mutex
	root          *os.File
	chunks        *os.File
	owner         *os.File
	refs          map[[32]byte]int
	garbage       map[[32]byte]struct{}
	handles       int
	closed        bool
	manifestDirty bool
}

// ErrBusy means the store is already owned, or still has open file handles.
var ErrBusy = errors.New("store is in use")

// Compilation-time check that we are indeed implementing these interfaces
var (
	_ fs.FS         = (*Store)(nil)
	_ fs.ReadFileFS = (*Store)(nil)
	_ fs.ReadDirFS  = (*Store)(nil)
	_ fs.StatFS     = (*Store)(nil)
)

// OpenStore opens or creates a private store directory. One Store instance in
// one process owns it until Close. Startup removes abandoned temporary files and
// unreferenced chunks only after acquiring exclusive ownership.
func OpenStore(directory string, options ...Option) (_ *Store, err error) {
	config := config{chunkSize: defaultChunkSize, fileMode: 0600}
	for _, option := range options {
		if err := option(&config); err != nil {
			return nil, err
		}
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	created := false
	if err := os.Mkdir(directory, 0700); err == nil {
		created = true
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	root, err := openDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("open store directory: %w", err)
	}
	store := &Store{
		path:          directory,
		chunkSize:     config.chunkSize,
		key:           config.key,
		fileMode:      config.fileMode,
		root:          root,
		refs:          make(map[[32]byte]int),
		garbage:       make(map[[32]byte]struct{}),
		manifestDirty: true,
	}
	defer func() {
		if err != nil {
			if store.chunks != nil {
				store.chunks.Close()
			}
			if store.owner != nil {
				store.owner.Close()
			}
			root.Close()
		}
	}()
	store.owner, err = openInternal(root, "lock", unix.O_RDWR|unix.O_CREAT, 0600)
	if err != nil {
		return nil, fmt.Errorf("open store lock: %w", err)
	}
	if err := unix.Flock(int(store.owner.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("lock store: %w", err)
	}
	if err := unix.Mkdirat(int(root.Fd()), "chunks", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(int(root.Fd()), "chunks", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open chunks directory: %w", err)
	}
	store.chunks = os.NewFile(uintptr(fd), "chunks")
	if err := store.load(); errors.Is(err, errMissingManifest) {
		entries, scanErr := readDirectory(store.chunks)
		if scanErr != nil {
			return nil, scanErr
		}
		if len(entries) != 0 {
			return nil, fmt.Errorf("missing manifest with existing chunks")
		}
		initial := manifest{Entries: map[string]entry{".": {Directory: true}}}
		if err := store.commit(initial); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	store.addRefs(store.manifest)
	if err := store.reconcile(); err != nil {
		return nil, err
	}
	if created {
		parent, err := os.Open(filepath.Dir(directory))
		if err != nil {
			return nil, err
		}
		if err := errors.Join(parent.Sync(), parent.Close()); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// Close releases store ownership. Close is idempotent, but returns ErrBusy while
// any reader or writer remains open. Close or abort those handles and retry.
func (s *Store) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.closed {
		return nil
	}
	if s.handles != 0 {
		return ErrBusy
	}
	if err := s.collect(); err != nil {
		return err
	}
	s.closed = true
	return errors.Join(s.chunks.Close(), s.root.Close(), s.owner.Close())
}

// Path returns the host directory containing this store.
func (s *Store) Path() string { return s.path }

// ChunkSize returns the store's plaintext chunk size.
func (s *Store) ChunkSize() int { return s.chunkSize }

func cleanName(name string) error {
	if !fs.ValidPath(name) {
		return &fs.PathError{Op: "access", Path: name, Err: fs.ErrInvalid}
	}
	return nil
}

// Mkdir creates a directory. Parent directories must already exist.
func (s *Store) Mkdir(name string) error {
	if err := cleanName(name); err != nil || name == "." {
		if err != nil {
			return err
		}
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
	}
	if err := s.lockLatest(); err != nil {
		return err
	}
	defer s.unlockLatest()
	if _, ok := s.manifest.Entries[name]; ok {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
	}
	parent := path.Dir(name)
	if item, ok := s.manifest.Entries[parent]; !ok || !item.Directory {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrNotExist}
	}
	next := cloneManifest(s.manifest)
	next.Entries[name] = entry{Directory: true}
	return s.commit(next, name)
}

// MkdirAll creates a directory and all missing parents.
func (s *Store) MkdirAll(name string) error {
	if err := cleanName(name); err != nil {
		return err
	}
	if name == "." {
		return nil
	}
	parts := strings.Split(name, "/")
	current := ""
	for _, part := range parts {
		if current == "" {
			current = part
		} else {
			current += "/" + part
		}
		if _, err := s.Stat(current); errors.Is(err, fs.ErrNotExist) {
			if err := s.Mkdir(current); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	return nil
}

// Remove removes a file or an empty directory.
func (s *Store) Remove(name string) error {
	if err := cleanName(name); err != nil {
		return err
	}
	if name == "." {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrPermission}
	}
	if err := s.lockLatest(); err != nil {
		return err
	}
	defer s.unlockLatest()
	item, ok := s.manifest.Entries[name]
	if !ok {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
	}
	if item.Directory {
		prefix := name + "/"
		for candidate := range s.manifest.Entries {
			if strings.HasPrefix(candidate, prefix) {
				return &fs.PathError{Op: "remove", Path: name, Err: errors.New("directory not empty")}
			}
		}
	}
	next := cloneManifest(s.manifest)
	delete(next.Entries, name)
	return s.commit(next, name)
}

// WriteFile replaces name with data read through a bounded chunk buffer.
func (s *Store) WriteFile(name string, reader io.Reader) error {
	output, err := s.Create(name)
	if err != nil {
		return err
	}
	defer output.Abort()

	// Buffer small reads so streaming replacements encrypt a chunk at a time.
	buffered := bufio.NewWriterSize(output, s.chunkSize)
	if _, err := io.Copy(buffered, reader); err != nil {
		return err
	}
	if err := buffered.Flush(); err != nil {
		return err
	}
	return output.Close()
}

// ReadFile reads a complete file. Use Open and io.Copy for bounded-memory reads.
func (s *Store) ReadFile(name string) ([]byte, error) {
	file, err := s.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}
