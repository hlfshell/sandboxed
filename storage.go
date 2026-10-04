package sandboxed

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// Open internal names relative to pinned directory descriptors. Never follow
// symlinks. Nonblocking opens let us reject substituted FIFOs before reading.
func openDirectory(name string) (*os.File, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openInternal(directory *os.File, name string, flags int, mode fs.FileMode) (*os.File, error) {
	file, _, err := openInternalWithInfo(directory, name, flags, mode)
	return file, err
}

// Return the same stat result used to reject unsafe internal file types so
// callers validating ciphertext length do not need another filesystem call.
func openInternalWithInfo(directory *os.File, name string, flags int, mode fs.FileMode) (*os.File, fs.FileInfo, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(mode.Perm()))
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, fmt.Errorf("internal file %q is not regular", name)
	}
	return file, info, nil
}

func removeInternal(directory *os.File, name string) error {
	err := unix.Unlinkat(int(directory.Fd()), name, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func readDirectory(directory *os.File) ([]fs.DirEntry, error) {
	// A separate descriptor avoids sharing a directory cursor with other scans.
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), directory.Name())
	defer file.Close()
	// Bound memory even if the directory contains an attacker-controlled number
	// of abandoned files. Valid manifests already have a smaller metadata bound.
	entries := make([]fs.DirEntry, 0)
	for {
		batch, err := file.ReadDir(256)
		if len(entries)+len(batch) > maxManifestSize/64 {
			return nil, fmt.Errorf("store directory exceeds entry limit")
		}
		entries = append(entries, batch...)
		if err == io.EOF {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
