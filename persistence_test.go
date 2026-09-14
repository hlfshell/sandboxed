package sandboxed

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func openTestStore(t testing.TB, name string, options ...Option) (*Store, error) {
	t.Helper()
	store, err := OpenStore(name, options...)
	if err == nil {
		t.Cleanup(func() {
			if err := store.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	return store, err
}
func testStore(t testing.TB, options ...Option) *Store {
	t.Helper()
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "store"), append([]Option{WithChunkSize(minimumChunkSize)}, options...)...)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
func putFile(t testing.TB, store *Store, name string, data []byte) {
	t.Helper()
	if err := store.WriteFile(name, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
}
func assertFile(t testing.TB, store *Store, name string, want []byte) {
	t.Helper()
	got, err := store.ReadFile(name)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("read %s: length=%d want=%d err=%v", name, len(got), len(want), err)
	}
}
func manifestBytes(t testing.TB, store *Store) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(store.path, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func chunkPath(store *Store, part chunk) string {
	return filepath.Join(store.path, "chunks", chunkName(part))
}
func chunkFiles(t testing.TB, store *Store) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(store.path, "chunks"))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(store.path, "chunks", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = raw
	}
	return files
}

func TestChunksAreIndependentAndUnchangedFilesStayInPlace(t *testing.T) {
	store := testStore(t, WithChunkSize(1024*1024))
	putFile(t, store, "large", bytes.Repeat([]byte("a"), 5*1024*1024))
	before := chunkFiles(t, store)
	if len(before) != 5 {
		t.Fatalf("five MiB should have five chunk files, got %d", len(before))
	}
	for name := range before {
		if !internalID(name) {
			t.Fatalf("nonopaque chunk name %q", name)
		}
	}
	beforeInfo := make(map[string]os.FileInfo)
	for name := range before {
		info, err := os.Stat(filepath.Join(store.path, "chunks", name))
		if err != nil {
			t.Fatal(err)
		}
		beforeInfo[name] = info
	}
	putFile(t, store, "small", []byte("small"))
	putFile(t, store, "small", []byte("replacement"))
	after := chunkFiles(t, store)
	if len(after) != 6 {
		t.Fatalf("chunk count=%d", len(after))
	}
	for name, raw := range before {
		if !bytes.Equal(after[name], raw) {
			t.Fatal("unrelated chunk changed")
		}
	}
	for name, previous := range beforeInfo {
		current, err := os.Stat(filepath.Join(store.path, "chunks", name))
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(previous, current) || !previous.ModTime().Equal(current.ModTime()) {
			t.Fatal("unchanged chunk was rewritten or replaced")
		}
	}
	if err := store.Mkdir("directory"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("small"); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 5 {
		t.Fatal("removed chunks not reclaimed")
	}
}

func TestChunkReferencesKeepSharedVersionsAlive(t *testing.T) {
	store := testStore(t)
	original := bytes.Repeat([]byte("a"), minimumChunkSize*3)
	putFile(t, store, "file", original)
	first, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	update := openWritable(t, store, "file")
	writeAt(t, update, []byte("new"), 0)
	if err := update.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if len(chunkFiles(t, store)) != 4 {
		t.Fatal("old changed chunk should remain pinned")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 4 {
		t.Fatal("second reader lost its chunk")
	}
	if err := first.Close(); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	data, err := io.ReadAll(second)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("old version changed", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 3 {
		t.Fatal("old changed chunk not reclaimed")
	}
	if err := store.Remove("file"); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 3 {
		t.Fatal("removed file reader lost chunks")
	}
	data, err = io.ReadAll(current)
	if err != nil || string(data[:3]) != "new" {
		t.Fatal("current snapshot failed", err)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 0 {
		t.Fatal("last reader did not release removed chunks")
	}
}

func TestWriterSnapshotAndStagingSurviveCleanup(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", bytes.Repeat([]byte("a"), minimumChunkSize*2))
	writer := openWritable(t, store, "file")
	writeAt(t, writer, []byte("ours"), 0)
	staging := filepath.Join(store.path, writer.file.Name())
	putFile(t, store, "file", []byte("theirs"))
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatal("staging removed", err)
	}
	data := make([]byte, 4)
	if _, err := writer.ReadAt(data, 0); err != nil || string(data) != "ours" {
		t.Fatal(err)
	}
	if _, err := writer.ReadAt(data, minimumChunkSize); err != nil || string(data) != "aaaa" {
		t.Fatal("writer snapshot lost", err)
	}
	if err := writer.Close(); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 1 {
		t.Fatal("failed writer leaked snapshot chunks")
	}
	if _, err := os.Stat(staging); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("staging survived close", err)
	}
}

func TestStartupReclaimsOrphansAndTemporaryFiles(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("committed"))
	path := store.path
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	orphan := string(bytes.Repeat([]byte("a"), 64))
	temporary := ".staging-" + string(bytes.Repeat([]byte("b"), 64))
	manifestTemp := ".manifest-" + string(bytes.Repeat([]byte("c"), 64))
	for _, name := range []string{filepath.Join("chunks", orphan), temporary, manifestTemp} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("interrupted"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := openTestStore(t, path)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, reopened, "file", []byte("committed"))
	if len(chunkFiles(t, reopened)) != 1 {
		t.Fatal("orphan survived startup")
	}
	for _, name := range []string{temporary, manifestTemp} {
		if _, err := os.Stat(filepath.Join(path, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("temporary survived", err)
		}
	}
}

func TestOwnershipAndStoreCloseLifecycle(t *testing.T) {
	store := testStore(t)
	if _, err := OpenStore(store.path); !errors.Is(err, ErrBusy) {
		t.Fatalf("second owner: %v", err)
	}
	putFile(t, store, "file", []byte("data"))
	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	writer := openWritable(t, store, "file")
	if err := store.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	directory, err := store.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open("file"); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := store.Create("new"); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	reopened, err := openTestStore(t, store.path)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, reopened, "file", []byte("data"))
}

func TestPrivateHostFilesAreNotVirtualPaths(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("content"))
	id := chunkName(store.manifest.Entries["file"].Chunks[0])
	for _, name := range []string{"manifest", "lock", "chunks", "chunks/" + id, id} {
		if _, err := store.Open(name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("host file exposed as %q: %v", name, err)
		}
	}
	putFile(t, store, "manifest", []byte("virtual manifest"))
	assertFile(t, store, "manifest", []byte("virtual manifest"))
	if _, err := decodeHeader(manifestBytes(t, store)[:headerSize]); err != nil {
		t.Fatal("virtual path overwrote host manifest", err)
	}
}

func TestFailedChunkPublicationLeavesStoreUsable(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	writer := createVirtual(t, store, "file")
	writeAt(t, writer, bytes.Repeat([]byte("a"), minimumChunkSize*2), 0)
	if err := writer.file.Truncate(minimumChunkSize + 16 + 3); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err == nil {
		t.Fatal("published truncated staging")
	}
	assertFile(t, store, "file", []byte("original"))
	if len(chunkFiles(t, store)) != 1 {
		t.Fatal("failed publication leaked chunks")
	}
	putFile(t, store, "next", []byte("next"))
}

func TestManifestDamageFailsBeforeStartupCleanup(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		options := []Option{}
		if encrypted {
			options = append(options, WithEncryption(bytes.Repeat([]byte{1}, 32)))
		}
		store := testStore(t, options...)
		putFile(t, store, "file", []byte("data"))
		original := manifestBytes(t, store)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		orphan := filepath.Join(store.path, "chunks", string(bytes.Repeat([]byte("f"), 64)))
		if err := os.WriteFile(orphan, []byte("keep on failure"), 0600); err != nil {
			t.Fatal(err)
		}
		damaged := append([]byte(nil), original...)
		damaged[headerSize] ^= 1
		for _, data := range [][]byte{damaged, original[:len(original)-1]} {
			if err := os.WriteFile(filepath.Join(store.path, "manifest"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if s, err := OpenStore(store.path, options...); err == nil {
				s.Close()
				t.Fatal("accepted damaged manifest")
			}
			if _, err := os.Stat(orphan); err != nil {
				t.Fatal("cleanup ran before validation", err)
			}
		}
	}
}

func TestMissingLiveChunkDoesNotResetManifest(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("data"))
	original := manifestBytes(t, store)
	part := store.manifest.Entries["file"].Chunks[0]
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(chunkPath(store, part)); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenStore(store.path); err == nil {
		s.Close()
		t.Fatal("accepted missing live chunk")
	}
	if !bytes.Equal(original, manifestBytes(t, store)) {
		t.Fatal("replaced manifest after missing chunk")
	}
}

func TestCleanupFailureDoesNotRollbackPublishedManifest(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	name := chunkPath(store, store.manifest.Entries["file"].Chunks[0])
	saved := filepath.Join(t.TempDir(), "saved")
	if err := os.Rename(name, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	// A directory cannot be removed with the chunk-file unlink operation.
	if err := store.Remove("file"); err == nil {
		t.Fatal("cleanup error was hidden")
	}
	if _, err := store.Open("file"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("rolled back committed removal", err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, name); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Cleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(name); err != nil {
		t.Fatal("canceled cleanup deleted chunk", err)
	}
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 0 {
		t.Fatal("cleanup retry did not reclaim chunk")
	}
}

func TestFailedManifestPublicationDiscardsNewChunks(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	name := filepath.Join(store.path, "manifest")
	saved := filepath.Join(t.TempDir(), "manifest")
	if err := os.Rename(name, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	writer := createVirtual(t, store, "file")
	writeAt(t, writer, []byte("new"), 0)
	if err := writer.Close(); err == nil {
		t.Fatal("published over a directory")
	}
	if len(chunkFiles(t, store)) != 1 {
		t.Fatal("failed commit leaked chunks")
	}
	assertFile(t, store, "file", []byte("original"))
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, name); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatal("failed commit leaked temporary files")
	}
}
