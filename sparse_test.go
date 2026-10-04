package sandboxed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"testing"
)

type sparsePatch struct {
	offset int64
	data   []byte
}

func assertSparseWindow(t testing.TB, reader io.ReadSeeker, offset, size int64, patches []sparsePatch) {
	t.Helper()
	const length = 64
	want := make([]byte, length)
	n := int(min(int64(length), max(int64(0), size-offset)))
	for _, patch := range patches {
		start := max(offset, patch.offset)
		end := min(offset+int64(n), patch.offset+int64(len(patch.data)))
		if start < end {
			copy(want[start-offset:end-offset], patch.data[start-patch.offset:end-patch.offset])
		}
	}
	if _, err := reader.Seek(offset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got := bytes.Repeat([]byte{0xcc}, length)
	count, err := io.ReadFull(reader, got)
	var wantErr error
	if n == 0 {
		wantErr = io.EOF
	} else if n < length {
		wantErr = io.ErrUnexpectedEOF
	}
	if count != n || !errors.Is(err, wantErr) || !bytes.Equal(got[:n], want[:n]) {
		t.Fatalf("read at %d: n=%d/%d err=%v/%v got=%x want=%x", offset, count, n, err, wantErr, got[:count], want[:n])
	}
	if !bytes.Equal(got[n:], bytes.Repeat([]byte{0xcc}, length-n)) {
		t.Fatal("read modified bytes beyond EOF")
	}
}

func TestSparseAllocationRoundTrip(t *testing.T) {
	for _, chunkSize := range []int{minimumChunkSize, 64 << 10, defaultChunkSize} {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("chunk=%d/encrypted=%t", chunkSize, encrypted), func(t *testing.T) {
				options := []Option{WithChunkSize(chunkSize)}
				if encrypted {
					options = append(options, WithEncryption(bytes.Repeat([]byte{42}, 32)))
				}
				store := testStore(t, options...)
				file := createVirtual(t, store, "sparse")
				const gap = int64(1 << 30)
				size := gap + int64(2*chunkSize) + 17
				patches := []sparsePatch{
					{gap + int64(chunkSize) - 2, []byte("boundary")},
					{0, []byte("HEAD")},
				}
				for _, patch := range patches {
					writeAt(t, file, patch.data, patch.offset)
				}
				if err := file.Truncate(size); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Stat("sparse"); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("creation visible before close", err)
				}
				if len(file.item.Chunks) != 3 {
					t.Fatalf("allocated %d chunks for three touched positions", len(file.item.Chunks))
				}

				// Every allocated record is already authenticated ciphertext before Close.
				for _, part := range file.item.Chunks {
					ciphertext := make([]byte, part.Size+16)
					if _, err := file.file.ReadAt(ciphertext, part.Offset); err != nil {
						t.Fatal(err)
					}
					if _, err := decryptChunk(file.item.Key, part.Index, part, ciphertext); err != nil {
						t.Fatal(err)
					}
				}
				offsets := []int64{0, 2, int64(chunkSize) - 2, gap - 2, gap + int64(chunkSize) - 4, size - 4, size, size + 10}
				for _, offset := range offsets {
					assertSparseWindow(t, file, offset, size, patches)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				if len(chunkFiles(t, store)) != 3 {
					t.Fatal("hole created chunk files")
				}
				if len(manifestBytes(t, store)) > 2048 {
					t.Fatal("gap expanded metadata")
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}

				reopened, err := openTestStore(t, store.Path(), options...)
				if err != nil {
					t.Fatal(err)
				}
				reader, err := reopened.Open("sparse")
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				info, err := reader.Stat()
				if err != nil || info.Size() != size {
					t.Fatalf("size: %v, %v", info, err)
				}
				for _, offset := range offsets {
					assertSparseWindow(t, reader.(io.ReadSeeker), offset, size, patches)
				}
			})
		}
	}
}

func TestSparseTruncationPreservesSnapshotsAndClearsDiscardedData(t *testing.T) {
	store := testStore(t)
	chunkSize := int64(store.ChunkSize())
	file := createVirtual(t, store, "file")
	original := make([]byte, 6*chunkSize)
	for _, index := range []int64{5, 0, 2} {
		data := bytes.Repeat([]byte{byte(index + 1)}, 200)
		writeAt(t, file, data, index*chunkSize)
		copy(original[index*chunkSize:], data)
	}
	if err := file.Truncate(int64(len(original))); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	old, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()

	update := openWritable(t, store, "file")
	if err := update.Truncate(2*chunkSize + 100); err != nil {
		t.Fatal(err)
	}
	if err := update.Truncate(8 * chunkSize); err != nil {
		t.Fatal(err)
	}
	writeAt(t, update, []byte("new"), 7*chunkSize+3)
	if err := update.Close(); err != nil {
		t.Fatal(err)
	}
	expected := make([]byte, 8*chunkSize)
	copy(expected, original[:2*chunkSize+100])
	copy(expected[7*chunkSize+3:], "new")
	assertFile(t, store, "file", expected)
	snapshot, err := io.ReadAll(old)
	if err != nil || !bytes.Equal(snapshot, original) {
		t.Fatal("old layout was mutated", err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != len(store.manifest.Entries["file"].Chunks) {
		t.Fatal("old chunks leaked")
	}

	// Reallocate the same distant position after repeatedly discarding it.
	update = openWritable(t, store, "file")
	for range 20 {
		if err := update.Truncate(0); err != nil {
			t.Fatal(err)
		}
		if err := update.Truncate(8 * chunkSize); err != nil {
			t.Fatal(err)
		}
		writeAt(t, update, []byte("x"), 7*chunkSize+3)
	}
	if err := update.Close(); err != nil {
		t.Fatal(err)
	}
	clear(expected)
	expected[7*chunkSize+3] = 'x'
	assertFile(t, store, "file", expected)
	if len(chunkFiles(t, store)) != 1 {
		t.Fatal("discarded chunks were republished")
	}
}

func TestSparseHolesHaveBoundsAndDoNotAllocateOnRead(t *testing.T) {
	store := testStore(t)
	file := createVirtual(t, store, "file")
	limit := int64(store.ChunkSize()) * maxFileChunks
	for _, size := range []int64{-1, limit + 1, math.MaxInt64} {
		if err := file.Truncate(size); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("truncate(%d): %v", size, err)
		}
	}
	if _, err := file.WriteAt([]byte("x"), limit); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if err := file.Truncate(limit); err != nil {
		t.Fatal(err)
	}
	if len(file.item.Chunks) != 0 || file.plain != nil || file.ciphertext != nil {
		t.Fatal("hole growth allocated payload")
	}
	got := bytes.Repeat([]byte{0xcc}, 8)
	if n, err := file.ReadAt(got, limit-3); n != 3 || err != io.EOF || !bytes.Equal(got[:3], make([]byte, 3)) {
		t.Fatalf("EOF: %d %v %x", n, err, got)
	}
	if n, err := file.ReadAt(nil, limit); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int64{0, limit / 2, limit - 4, limit} {
		assertSparseWindow(t, reader.(io.ReadSeeker), offset, limit, nil)
	}
	if reader.(*openFile).plain != nil {
		t.Fatal("reading holes allocated a chunk buffer")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 0 {
		t.Fatal("hole created payload storage")
	}
	update := openWritable(t, store, "file")
	writeAt(t, update, []byte("x"), limit-1)
	if err := update.Close(); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 1 {
		t.Fatal("last-byte write allocated the gap")
	}
}

func TestSparseMissingOrDamagedChunkIsNotAHole(t *testing.T) {
	for _, damage := range []string{"missing", "truncated", "tampered"} {
		t.Run(damage, func(t *testing.T) {
			store := testStore(t)
			file := createVirtual(t, store, "file")
			const offset = 1 << 20
			writeAt(t, file, []byte("payload"), offset)
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			part := store.manifest.Entries["file"].Chunks[0]
			name := chunkPath(store, part)
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if damage == "missing" {
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
			} else {
				if damage == "truncated" {
					raw = raw[:len(raw)-1]
				} else {
					raw[0] ^= 1
				}
				if err := os.WriteFile(name, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			reader, err := store.Open("file")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.(io.Seeker).Seek(offset, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Read(make([]byte, 7)); err == nil {
				t.Fatal("damaged ciphertext read as zeros")
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			update := openWritable(t, store, "file")
			if _, err := update.WriteAt([]byte("x"), offset); err == nil {
				t.Fatal("edited unauthenticated sparse chunk")
			}
			if err := update.Close(); err == nil {
				t.Fatal("published a failed edit")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if damage != "tampered" {
				reopened, err := OpenStore(store.Path())
				if err == nil {
					reopened.Close()
					t.Fatal("startup treated a missing live payload as a hole")
				}
			}
		})
	}
}

func writeSparseManifest(t *testing.T, store *Store, value manifest) {
	t.Helper()
	h, payload, err := marshalManifest(value, store.key, store.chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(encodeHeader(h), payload...)
	digest := sha256.Sum256(raw)
	raw = append(raw, digest[:]...)
	if err := os.WriteFile(filepath.Join(store.Path(), "manifest"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedSparseMetadataFailsBeforeCleanup(t *testing.T) {
	store := testStore(t)
	file := createVirtual(t, store, "file")
	writeAt(t, file, []byte("first"), minimumChunkSize)
	writeAt(t, file, []byte("second"), 4*minimumChunkSize)
	if err := file.Truncate(8 * minimumChunkSize); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(store.Path(), "chunks", fmt.Sprintf("%064x", 123))
	if err := os.WriteFile(orphan, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*entry){
		"negative index":     func(e *entry) { e.Chunks[0].Index = -1 },
		"index limit":        func(e *entry) { e.Chunks[1].Index = maxFileChunks },
		"index overflow":     func(e *entry) { e.Chunks[1].Index = math.MaxInt },
		"duplicate index":    func(e *entry) { e.Chunks[1].Index = e.Chunks[0].Index },
		"unordered index":    func(e *entry) { e.Chunks[0], e.Chunks[1] = e.Chunks[1], e.Chunks[0] },
		"duplicate identity": func(e *entry) { e.Chunks[1].ID = e.Chunks[0].ID },
		"zero payload":       func(e *entry) { e.Chunks[0].Size = 0 },
		"oversized payload":  func(e *entry) { e.Chunks[0].Size = minimumChunkSize + 1 },
		"payload past EOF":   func(e *entry) { e.Size = 4*minimumChunkSize + 1 },
		"logical size limit": func(e *entry) { e.Size = int64(minimumChunkSize)*maxFileChunks + 1 },
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			next := cloneManifest(store.manifest)
			item := next.Entries["file"]
			item.Chunks = append([]chunk(nil), item.Chunks...)
			damage(&item)
			next.Entries["file"] = item
			writeSparseManifest(t, store, next)
			reopened, err := OpenStore(store.Path())
			if err == nil {
				reopened.Close()
				t.Fatal("accepted malformed sparse layout")
			}
			if _, err := os.Stat(orphan); err != nil {
				t.Fatal("cleanup ran before layout validation", err)
			}
		})
	}
}

func TestSparseChunkPositionIsAuthenticated(t *testing.T) {
	store := testStore(t)
	file := createVirtual(t, store, "file")
	writeAt(t, file, []byte("payload"), 3*minimumChunkSize)
	if err := file.Truncate(8 * minimumChunkSize); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	next := cloneManifest(store.manifest)
	item := next.Entries["file"]
	item.Chunks = append([]chunk(nil), item.Chunks...)
	item.Chunks[0].Index = 5
	next.Entries["file"] = item
	writeSparseManifest(t, store, next)
	reopened, err := openTestStore(t, store.Path())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := reopened.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.(io.Seeker).Seek(5*minimumChunkSize, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(make([]byte, 7)); err == nil {
		t.Fatal("moved ciphertext authenticated at another logical position")
	}
}

func TestSparseAbortConflictAndCleanup(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	first := openWritable(t, store, "file")
	second := openWritable(t, store, "file")
	writeAt(t, first, []byte("ours"), 1<<20)
	writeAt(t, second, []byte("theirs"), 2<<20)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); !errors.Is(err, ErrConflict) {
		t.Fatal("missing conflict", err)
	}
	third := openWritable(t, store, "file")
	if err := third.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if err := third.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	writeAt(t, third, []byte("discard"), 1<<29)
	if err := third.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(chunkFiles(t, store)) != 2 {
		t.Fatal("aborted sparse chunks leaked")
	}
	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	patches := []sparsePatch{{0, []byte("original")}, {1 << 20, []byte("ours")}}
	assertSparseWindow(t, reader.(io.ReadSeeker), 0, 1<<20+4, patches)
	assertSparseWindow(t, reader.(io.ReadSeeker), 1<<20-2, 1<<20+4, patches)
}

func TestSparseConcurrentWrites(t *testing.T) {
	store := testStore(t)
	file := createVirtual(t, store, "file")
	indices := []int{900, 2, 77, 0, 400, 300, 12, 600}
	results := make(chan error, len(indices))
	for _, index := range indices {
		go func() {
			n, err := file.WriteAt([]byte{byte(index)}, int64(index*minimumChunkSize+3))
			if err == nil && n != 1 {
				err = io.ErrShortWrite
			}
			results <- err
		}()
	}
	for range indices {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	patches := make([]sparsePatch, 0, len(indices))
	for _, index := range indices {
		patches = append(patches, sparsePatch{int64(index*minimumChunkSize + 3), []byte{byte(index)}})
	}
	size := int64(900*minimumChunkSize + 4)
	for _, index := range indices {
		assertSparseWindow(t, reader.(io.ReadSeeker), int64(index*minimumChunkSize), size, patches)
	}
}

func TestFailedSparsePublicationKeepsCommittedLayout(t *testing.T) {
	for _, failure := range []string{"staging", "manifest"} {
		t.Run(failure, func(t *testing.T) {
			store := testStore(t)
			putFile(t, store, "file", []byte("original"))
			file := openWritable(t, store, "file")
			writeAt(t, file, []byte("new"), 1<<30)
			if failure == "staging" {
				if err := file.file.Truncate(1); err != nil {
					t.Fatal(err)
				}
			} else {
				name := filepath.Join(store.Path(), "manifest")
				saved := filepath.Join(t.TempDir(), "saved")
				if err := os.Rename(name, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Remove(name); err != nil {
						t.Error(err)
					}
					if err := os.Rename(saved, name); err != nil {
						t.Error(err)
					}
				}()
			}
			if err := file.Close(); err == nil {
				t.Fatal("failed publication reported success")
			}
			assertFile(t, store, "file", []byte("original"))
			if len(chunkFiles(t, store)) != 1 {
				t.Fatal("failed sparse publication leaked chunks")
			}
		})
	}
}
