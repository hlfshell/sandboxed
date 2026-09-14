package sandboxed

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStoreRejectsInternalSymlinks(t *testing.T) {
	for _, target := range []string{"manifest", "lock", "chunks", "chunk"} {
		t.Run(target, func(t *testing.T) {
			store := testStore(t)
			putFile(t, store, "file", []byte("safe"))
			host := filepath.Join(store.path, target)
			if target == "chunk" {
				host = chunkPath(store, store.manifest.Entries["file"].Chunks[0])
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			if target == "chunks" {
				if err := os.Mkdir(outside, 0700); err != nil {
					t.Fatal(err)
				}
				// Move the original directory aside without introducing unknown store files.
				if err := os.Rename(host, filepath.Join(t.TempDir(), "saved")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(outside, []byte("do not touch"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(host); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, host); err != nil {
				t.Fatal(err)
			}
			if owner, err := OpenStore(store.path); err == nil {
				owner.Close()
				t.Fatal("accepted internal symlink")
			}
			if target != "chunks" {
				raw, err := os.ReadFile(outside)
				if err != nil || string(raw) != "do not touch" {
					t.Fatal("modified symlink target", err)
				}
			}
		})
	}
}

func TestReaderRejectsSubstitutedChunkSymlinkAndFIFO(t *testing.T) {
	for _, fifo := range []bool{false, true} {
		store := testStore(t)
		putFile(t, store, "file", []byte("original"))
		reader, err := store.Open("file")
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		part := store.manifest.Entries["file"].Chunks[0]
		name := chunkPath(store, part)
		ciphertext, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
		if fifo {
			if err := unix.Mkfifo(name, 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			outside := filepath.Join(t.TempDir(), "ciphertext")
			if err := os.WriteFile(outside, ciphertext, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, name); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := reader.Read(make([]byte, 8)); err == nil {
			t.Fatal("read substituted internal file")
		}
	}
}

func TestChunkTamperingAndTruncationFail(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		store := testStore(t)
		putFile(t, store, "file", bytes.Repeat([]byte("a"), minimumChunkSize))
		name := chunkPath(store, store.manifest.Entries["file"].Chunks[0])
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if truncated {
			raw = raw[:len(raw)-1]
		} else {
			raw[0] ^= 1
		}
		if err := os.WriteFile(name, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ReadFile("file"); err == nil {
			t.Fatal("returned corrupt plaintext")
		}
	}
}

func TestFailedOpenReleasesLockWithoutDeletingUnknownFiles(t *testing.T) {
	store := testStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(store.path, "chunks", "unexpected")
	if err := os.WriteFile(unknown, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if owner, err := OpenStore(store.path); err == nil {
		owner.Close()
		t.Fatal("accepted unknown chunk entry")
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal("deleted unknown entry", err)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	owner, err := openTestStore(t, store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Update("../outside"); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestPrivateDirectoryAndChunkModes(t *testing.T) {
	store := testStore(t, WithFileMode(0640))
	putFile(t, store, "file", []byte("data"))
	for name, mode := range map[string]fs.FileMode{
		store.path:                                                 0700,
		filepath.Join(store.path, "chunks"):                        0700,
		filepath.Join(store.path, "lock"):                          0600,
		filepath.Join(store.path, "manifest"):                      0640,
		chunkPath(store, store.manifest.Entries["file"].Chunks[0]): 0640,
	} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("mode for %s: %v %v", name, info, err)
		}
	}
}
