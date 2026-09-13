package sandboxed

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gofrs/flock"
)

// Store is a mutable filesystem backed by one binary file. Store implements
// fs.FS, fs.ReadFileFS, fs.ReadDirFS, and fs.StatFS.
type Store struct {
	path      string
	chunkSize int
	key       []byte
	fileMode  fs.FileMode
	manifest  manifest
	lock      sync.RWMutex
	fileLock  *flock.Flock
}

// Compilation-time check that we are indeed implementing these interfaces
var (
	_ fs.FS         = (*Store)(nil)
	_ fs.ReadFileFS = (*Store)(nil)
	_ fs.ReadDirFS  = (*Store)(nil)
	_ fs.StatFS     = (*Store)(nil)
)

// OpenStore opens the blob at filename, creating it when it does not exist.
func OpenStore(filename string, options ...Option) (*Store, error) {
	// Apply configuration and resolve the backing file.
	config := config{chunkSize: defaultChunkSize, fileMode: 0600}
	for _, option := range options {
		if err := option(&config); err != nil {
			return nil, err
		}
	}
	filename, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	store := &Store{
		path:      filename,
		chunkSize: config.chunkSize,
		key:       config.key,
		fileMode:  config.fileMode,
		fileLock:  flock.New(filename + ".lock"),
	}

	// Lock creation and loading so simultaneous openers see one complete store.
	if err := store.fileLock.Lock(); err != nil {
		return nil, fmt.Errorf("lock store: %w", err)
	}
	defer store.fileLock.Unlock()

	// Initialize a new blob or load the existing manifest.
	_, err = os.Stat(filename)
	if errors.Is(err, os.ErrNotExist) {
		store.manifest = manifest{Entries: map[string]entry{".": {Directory: true}}}
		if err := store.rewrite(nil); err != nil {
			return nil, err
		}
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

// Path returns the host path of the opaque backing blob.
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
	s.manifest.Entries[name] = entry{Directory: true}
	if err := s.rewrite(nil); err != nil {
		delete(s.manifest.Entries, name)
		return err
	}
	return nil
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
	delete(s.manifest.Entries, name)
	if err := s.rewrite(nil); err != nil {
		s.manifest.Entries[name] = item
		return err
	}
	return nil
}

// WriteFile replaces name with data read through a bounded chunk buffer.
func (s *Store) WriteFile(name string, reader io.Reader) error {
	output, err := s.Create(name)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, reader)
	if copyErr != nil {
		if pending, ok := output.(*writer); ok {
			pending.err = copyErr
		}
	}
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
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
