package sandboxed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func openWritable(t testing.TB, store *Store, name string) *File {
	t.Helper()
	handle, err := store.Update(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := handle.Abort(); err != nil {
			t.Error(err)
		}
	})
	return handle
}

func writeAt(t testing.TB, handle *File, data []byte, offset int64) {
	t.Helper()
	n, err := handle.WriteAt(data, offset)
	if err != nil || n != len(data) {
		t.Fatalf("WriteAt: %d, %v", n, err)
	}
}

func TestPartialWritesPublishOnlyChangedChunks(t *testing.T) {
	store := testStore(t, WithEncryption(bytes.Repeat([]byte{5}, 32)))
	original := bytes.Repeat([]byte("a"), minimumChunkSize*4)
	putFile(t, store, "file", original)
	before := chunkFiles(t, store)
	oldChunks := append([]chunk(nil), store.manifest.Entries["file"].Chunks...)
	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	handle := openWritable(t, store, "file")
	patch := []byte("cross-boundary")
	if _, err := handle.Seek(minimumChunkSize-3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if n, err := handle.Write(patch); err != nil || n != len(patch) {
		t.Fatalf("Write: %d %v", n, err)
	}
	firstID := append([]byte(nil), handle.item.Chunks[0].ID...)
	writeAt(t, handle, []byte("again"), 1)
	if bytes.Equal(firstID, handle.item.Chunks[0].ID) {
		t.Fatal("reused chunk encryption context")
	}
	assertFile(t, store, "file", original)
	staging, err := os.ReadFile(filepath.Join(store.path, handle.staging[0]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(staging, patch) || bytes.Contains(staging, bytes.Repeat([]byte("a"), 32)) {
		t.Fatal("plaintext in staging")
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	expected := append([]byte(nil), original...)
	copy(expected[minimumChunkSize-3:], patch)
	copy(expected[1:], "again")
	assertFile(t, store, "file", expected)
	after := chunkFiles(t, store)
	// The old reader pins two replaced chunks; only two new chunks are published.
	if len(after) != len(before)+2 {
		t.Fatalf("chunk count=%d want=%d", len(after), len(before)+2)
	}
	for index := 2; index < 4; index++ {
		part := store.manifest.Entries["file"].Chunks[index]
		if !bytes.Equal(part.ID, oldChunks[index].ID) || !bytes.Equal(after[chunkName(part)], before[chunkName(part)]) {
			t.Fatal("unchanged chunk was rewritten")
		}
	}
	snapshot, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(snapshot, original) {
		t.Fatalf("snapshot changed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.path, handle.staging[0])); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("staging survived close: %v", err)
	}
	if err := handle.Close(); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("second close: %v", err)
	}
	if _, err := handle.WriteAt([]byte("x"), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestPartialWriterExtendsWithoutHoles(t *testing.T) {
	for _, initial := range []int{0, minimumChunkSize - 3, minimumChunkSize} {
		store := testStore(t)
		original := bytes.Repeat([]byte("a"), initial)
		putFile(t, store, "file", original)
		handle := openWritable(t, store, "file")
		if _, err := handle.WriteAt([]byte("bad"), -1); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("negative offset: %v", err)
		}
		extension := bytes.Repeat([]byte("b"), minimumChunkSize+10)
		writeAt(t, handle, extension, int64(initial))
		writeAt(t, handle, []byte("end"), int64(initial+len(extension)))
		if err := handle.Close(); err != nil {
			t.Fatal(err)
		}
		assertFile(t, store, "file", append(append(original, extension...), []byte("end")...))
	}
}

func TestPartialWriterConflictsAndUnrelatedCommits(t *testing.T) {
	for _, operation := range []string{"edit", "replace", "remove", "recreate", "unrelated", "cleanup"} {
		t.Run(operation, func(t *testing.T) {
			store := testStore(t)
			original := bytes.Repeat([]byte("a"), minimumChunkSize*2)
			putFile(t, store, "file", original)
			handle := openWritable(t, store, "file")
			writeAt(t, handle, []byte("ours"), 1)
			other := store
			switch operation {
			case "edit":
				concurrent := openWritable(t, other, "file")
				writeAt(t, concurrent, []byte("theirs"), minimumChunkSize)
				if err := concurrent.Close(); err != nil {
					t.Fatal(err)
				}
			case "replace":
				putFile(t, other, "file", []byte("replacement"))
			case "remove", "recreate":
				if err := other.Remove("file"); err != nil {
					t.Fatal(err)
				}
				if operation == "recreate" {
					putFile(t, other, "file", original)
				}
			case "unrelated":
				putFile(t, other, "another", []byte("another"))
			case "cleanup":
				if err := other.Cleanup(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			err := handle.Close()
			if operation == "unrelated" || operation == "cleanup" {
				if err != nil {
					t.Fatal(err)
				}
				copy(original[1:], "ours")
				assertFile(t, store, "file", original)
			} else {
				if !errors.Is(err, ErrConflict) {
					t.Fatalf("close conflict: %v", err)
				}
				if operation == "edit" {
					copy(original[minimumChunkSize:], "theirs")
					assertFile(t, store, "file", original)
				}
				if operation == "replace" {
					assertFile(t, store, "file", []byte("replacement"))
				}
				if operation == "recreate" {
					assertFile(t, store, "file", original)
				}
				if operation == "remove" {
					if _, err := store.Open("file"); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal(err)
					}
				}
			}
			if _, err := os.Stat(filepath.Join(store.path, handle.staging[0])); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("staging survived: %v", err)
			}
		})
	}
}

func TestFileAbortAndNoOpReleaseResources(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	before := manifestBytes(t, store)
	handle := openWritable(t, store, "file")
	writeAt(t, handle, []byte("changed"), 0)
	if err := handle.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := handle.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.path, handle.staging[0])); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("abort left staging: %v", err)
	}
	noop := openWritable(t, store, "file")
	writeAt(t, noop, nil, 0)
	if err := noop.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, manifestBytes(t, store)) {
		t.Fatal("abort or no-op modified store")
	}
}

func TestFileRejectsUnsafePathsAndDirectories(t *testing.T) {
	store := testStore(t)
	for _, name := range []string{"../escape", "/escape", "", ".", "missing"} {
		if handle, err := store.Update(name); err == nil {
			handle.Abort()
			t.Fatalf("accepted %q", name)
		}
	}

}

func TestFileAuthenticationFailureDoesNotPublish(t *testing.T) {
	for _, staged := range []bool{false, true} {
		store := testStore(t)
		putFile(t, store, "file", []byte("original"))
		handle := openWritable(t, store, "file")
		target := chunkPath(store, handle.item.Chunks[0])
		offset := int64(0)
		if staged {
			writeAt(t, handle, []byte("changed"), 0)
			target = filepath.Join(store.path, handle.staging[0])
			offset = handle.item.Chunks[0].Offset
		}
		file, err := os.OpenFile(target, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		one := make([]byte, 1)
		if _, err := file.ReadAt(one, offset); err != nil {
			t.Fatal(err)
		}
		one[0] ^= 1
		if _, err := file.WriteAt(one, offset); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		before := manifestBytes(t, store)
		if _, err := handle.WriteAt([]byte("patch"), 0); err == nil {
			t.Fatal("accepted unauthenticated chunk")
		}
		if err := handle.Close(); err == nil {
			t.Fatal("published failed edit")
		}
		if !bytes.Equal(before, manifestBytes(t, store)) {
			t.Fatal("failed edit changed store")
		}
		if staged {
			assertFile(t, store, "file", []byte("original"))
		}
	}
}

func TestConcurrentFileCalls(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", bytes.Repeat([]byte("a"), minimumChunkSize*4))
	handle := openWritable(t, store, "file")
	results := make(chan error, 4)
	for index := range 4 {
		go func() {
			_, err := handle.WriteAt([]byte{byte('0' + index)}, int64(index*minimumChunkSize))
			results <- err
		}()
	}
	for range 4 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	expected := bytes.Repeat([]byte("a"), minimumChunkSize*4)
	for index := range 4 {
		expected[index*minimumChunkSize] = byte('0' + index)
	}
	assertFile(t, store, "file", expected)
}

func BenchmarkPartialWrite(b *testing.B) {
	for _, megabytes := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("store_%dMiB", megabytes), func(b *testing.B) {
			store := testStore(b, WithChunkSize(1024*1024))
			putFile(b, store, "large", bytes.Repeat([]byte("a"), megabytes*1024*1024))
			putFile(b, store, "target", bytes.Repeat([]byte("b"), minimumChunkSize))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				handle, err := store.Update("target")
				if err != nil {
					b.Fatal(err)
				}
				if _, err := handle.WriteAt([]byte("patch"), 0); err != nil {
					handle.Abort()
					b.Fatal(err)
				}
				if err := handle.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
