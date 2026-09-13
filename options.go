package sandboxed

import (
	"fmt"
	"io/fs"
)

const (
	defaultChunkSize = 1024 * 1024
	minimumChunkSize = 4 * 1024
	maximumChunkSize = 64 * 1024 * 1024
)

type config struct {
	chunkSize int
	key       []byte
	fileMode  fs.FileMode
}

// Option configures a Store when it is first created or opened.
type Option func(*config) error

// WithFileMode sets the permission bits used for the backing blob and atomic
// replacement files. The default is 0600.
func WithFileMode(mode fs.FileMode) Option {
	return func(config *config) error {
		if mode != mode.Perm() {
			return fmt.Errorf("file mode must contain permission bits only")
		}
		config.fileMode = mode
		return nil
	}
}

// WithChunkSize sets the maximum plaintext bytes encrypted in one chunk.
// It only affects a newly-created store.
func WithChunkSize(size int) Option {
	return func(config *config) error {
		if size < minimumChunkSize || size > maximumChunkSize {
			return fmt.Errorf("chunk size must be between %d and %d bytes", minimumChunkSize, maximumChunkSize)
		}
		config.chunkSize = size
		return nil
	}
}

// WithEncryption encrypts the store manifest, including paths and file keys.
// key must contain 32 bytes. Payload chunks are encrypted in every store.
func WithEncryption(key []byte) Option {
	return func(config *config) error {
		if len(key) != 32 {
			return fmt.Errorf("encryption key must contain 32 bytes")
		}
		config.key = append([]byte(nil), key...)
		return nil
	}
}
