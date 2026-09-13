package sandboxed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func testStore(t testing.TB, options ...Option) *Store {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "store"), append([]Option{WithChunkSize(minimumChunkSize)}, options...)...)
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
		t.Fatalf("read %s: length=%d, want=%d, err=%v", name, len(got), len(want), err)
	}
}

func blob(t testing.TB, store *Store) []byte {
	t.Helper()
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCommitsLeaveExistingPayloadAndMetadataInPlace(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "large", bytes.Repeat([]byte("a"), minimumChunkSize*256))
	before := blob(t, store)
	putFile(t, store, "small", []byte("small"))
	after := blob(t, store)
	if !bytes.Equal(before[dataStart:], after[dataStart:len(before)]) {
		t.Fatal("commit rewrote existing records")
	}
	// Only the new ciphertext and the new manifest are appended.
	_, encoded, err := marshalManifest(store.manifest, nil, store.chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(after)-len(before), 5+16+len(encoded); got != want {
		t.Fatalf("growth=%d want=%d", got, want)
	}
	// Replacing an existing file must also leave every prior payload in place.
	before = after
	putFile(t, store, "small", []byte("replacement"))
	after = blob(t, store)
	if !bytes.Equal(before[dataStart:], after[dataStart:len(before)]) {
		t.Fatal("replacement rewrote existing records")
	}
	_, encoded, err = marshalManifest(store.manifest, nil, store.chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(after)-len(before), len("replacement")+16+len(encoded); got != want {
		t.Fatalf("replacement growth=%d want=%d", got, want)
	}
	before = after
	if err := store.Mkdir("directory"); err != nil {
		t.Fatal(err)
	}
	after = blob(t, store)
	if !bytes.Equal(before[dataStart:], after[dataStart:len(before)]) {
		t.Fatal("mkdir rewrote payload")
	}
	if err := store.Remove("small"); err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "large", bytes.Repeat([]byte("a"), minimumChunkSize*256))
}

func TestIncompleteCommitRecovery(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("old"))
	before := blob(t, store)
	previousGeneration := store.generation
	putFile(t, store, "file", []byte("new"))
	complete := blob(t, store)
	slot := int(1+(store.generation-1)%2) * rootSpacing
	// Every possible prefix of a torn root must leave a complete old or new state.
	for cut := 0; cut <= rootSize; cut++ {
		raw := append([]byte(nil), complete...)
		copy(raw[slot:slot+rootSize], before[slot:slot+rootSize])
		copy(raw[slot:slot+cut], complete[slot:slot+cut])
		if err := os.WriteFile(store.path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenStore(store.path)
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		expected := []byte("new")
		if reopened.generation == previousGeneration {
			expected = []byte("old")
		}
		assertFile(t, reopened, "file", expected)
	}
	// A truncated append with unchanged roots is ignored and reclaimed on commit.
	raw := append(append([]byte(nil), before...), complete[len(before):len(complete)-1]...)
	if err := os.WriteFile(store.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, reopened, "file", []byte("old"))
	putFile(t, reopened, "other", []byte("next"))
	assertFile(t, reopened, "file", []byte("old"))
	assertFile(t, reopened, "other", []byte("next"))
}

func TestCommittedManifestDamageFailsClosed(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		options := []Option{}
		if encrypted {
			options = append(options, WithEncryption(bytes.Repeat([]byte{1}, 32)))
		}
		store := testStore(t, options...)
		putFile(t, store, "file", []byte("old"))
		putFile(t, store, "file", []byte("new"))
		complete := blob(t, store)
		root, err := decodeRoot(complete[int64(1+(store.generation-1)%2)*rootSpacing:][:rootSize])
		if err != nil {
			t.Fatal(err)
		}
		damaged := append([]byte(nil), complete...)
		damaged[root.offset] ^= 1
		for _, raw := range [][]byte{damaged, complete[:len(complete)-1]} {
			if err := os.WriteFile(store.path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenStore(store.path, options...); err == nil {
				t.Fatal("accepted damaged committed manifest")
			}
		}
	}
}

func TestCompactReclaimsSpaceAndPreservesSnapshots(t *testing.T) {
	store := testStore(t, WithEncryption(bytes.Repeat([]byte{2}, 32)))
	original := bytes.Repeat([]byte("old"), minimumChunkSize)
	putFile(t, store, "file", original)
	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	putFile(t, store, "file", []byte("new"))
	before := len(blob(t, store))
	if err := store.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(blob(t, store)) >= before {
		t.Fatal("compaction did not reclaim space")
	}
	assertFile(t, store, "file", []byte("new"))
	data, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatalf("lost reader snapshot: %v", err)
	}
	reopened, err := OpenStore(store.path, WithEncryption(bytes.Repeat([]byte{2}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, reopened, "file", []byte("new"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	beforeBlob := blob(t, store)
	if err := store.Compact(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled compact: %v", err)
	}
	if !bytes.Equal(beforeBlob, blob(t, store)) {
		t.Fatal("canceled compact changed store")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(store.path), ".sandboxed-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files: %v, %v", matches, err)
	}
}

func TestInvalidChunkRangesRejected(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", bytes.Repeat([]byte{1}, minimumChunkSize*2))
	raw := blob(t, store)
	slot := int64(1+(store.generation-1)%2) * rootSpacing
	root, err := decodeRoot(raw[slot:][:rootSize])
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*entry){
		func(e *entry) { e.Chunks[0].Offset = 0 },
		func(e *entry) { e.Chunks[1].Offset = e.Chunks[0].Offset },
		func(e *entry) { e.Chunks[0].Offset = root.offset },
		func(e *entry) { e.Chunks[0].ID = []byte{1} },
		func(e *entry) { e.Chunks[0].ID = nil },
		func(e *entry) { e.Chunks[0].Size = 0 },
	} {
		value := cloneManifest(store.manifest)
		item := value.Entries["file"]
		mutate(&item)
		value.Entries["file"] = item
		h, encoded, err := marshalManifest(value, nil, store.chunkSize)
		if err != nil {
			t.Fatal(err)
		}
		altered := append(append([]byte(nil), raw[:root.offset]...), encoded...)
		modified := root
		modified.header, modified.digest = h, sha256.Sum256(encoded)
		copy(altered[slot:], encodeRoot(modified))
		if err := os.WriteFile(store.path, altered, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(store.path); err == nil {
			t.Fatal("accepted invalid chunk ranges")
		}
	}
}

func TestFailedAppendLeavesCommittedStoreUsable(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	output, err := store.Create("file")
	if err != nil {
		t.Fatal(err)
	}
	writer := output
	if _, err := writer.Write(bytes.Repeat([]byte("a"), minimumChunkSize*2)); err != nil {
		t.Fatal(err)
	}
	// A short staging source fails after part of the replacement was appended.
	if err := writer.file.Truncate(minimumChunkSize + 16 + 3); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err == nil {
		t.Fatal("accepted truncated staging")
	}
	if _, err := os.Stat(writer.file.Name()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging survived failure: %v", err)
	}
	assertFile(t, store, "file", []byte("original"))
	putFile(t, store, "next", []byte("next"))
	assertFile(t, store, "file", []byte("original"))
	assertFile(t, store, "next", []byte("next"))
}

// cancelDuringCopy makes cancellation deterministic after compaction has
// created its temporary file and copied one chunk.
type cancelDuringCopy struct {
	context.Context
	checks int
}

func (ctx *cancelDuringCopy) Err() error {
	ctx.checks++
	if ctx.checks >= 3 {
		return context.Canceled
	}
	return nil
}

func TestInterruptedCompactionCleansTemporaryFile(t *testing.T) {
	store := testStore(t)
	original := bytes.Repeat([]byte("a"), minimumChunkSize*3)
	putFile(t, store, "file", original)
	before := blob(t, store)
	ctx := &cancelDuringCopy{Context: context.Background()}
	if err := store.Compact(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted compaction: %v", err)
	}
	if !bytes.Equal(before, blob(t, store)) {
		t.Fatal("interrupted compaction changed blob")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(store.path), ".sandboxed-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files: %v, %v", matches, err)
	}
	assertFile(t, store, "file", original)
}
