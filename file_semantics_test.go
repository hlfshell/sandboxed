package sandboxed

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"testing"
)

type regularFile interface {
	io.ReadWriteSeeker
	io.ReaderAt
	io.WriterAt
	Truncate(int64) error
	Stat() (fs.FileInfo, error)
}

func createVirtual(t *testing.T, store *Store, name string) *File {
	t.Helper()
	file, err := store.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Abort(); err != nil {
			t.Error(err)
		}
	})
	return file
}

func TestFileOperationsMatchOSFile(t *testing.T) {
	store := testStore(t)
	virtual := createVirtual(t, store, "file")
	host, err := os.OpenFile(filepath.Join(t.TempDir(), "reference"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	// The host file is an independent oracle for positions, partial reads, gaps,
	// and data discarded by truncation and later extension.
	for _, operation := range []struct {
		name  string
		apply func(regularFile) error
	}{
		{"initial write", func(f regularFile) error { _, err := f.Write([]byte("original")); return err }},
		{"seek middle", func(f regularFile) error { _, err := f.Seek(2, io.SeekStart); return err }},
		{"overwrite", func(f regularFile) error { _, err := f.Write([]byte("XYZ")); return err }},
		{"positional gap", func(f regularFile) error { _, err := f.WriteAt([]byte("tail"), minimumChunkSize*2+7); return err }},
		{"seek from end", func(f regularFile) error { _, err := f.Seek(-2, io.SeekEnd); return err }},
		{"extend sequentially", func(f regularFile) error { _, err := f.Write([]byte("longer tail")); return err }},
		{"shrink partial chunk", func(f regularFile) error { return f.Truncate(minimumChunkSize + 3) }},
		{"extend after shrink", func(f regularFile) error { return f.Truncate(minimumChunkSize*3 + 1) }},
		{"shrink on boundary", func(f regularFile) error { return f.Truncate(minimumChunkSize) }},
		{"empty", func(f regularFile) error { return f.Truncate(0) }},
		{"write at retained offset", func(f regularFile) error { _, err := f.Write([]byte("after truncate")); return err }},
		{"seek current", func(f regularFile) error { _, err := f.Seek(-3, io.SeekCurrent); return err }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.apply(host); err != nil {
				t.Fatal(err)
			}
			if err := operation.apply(virtual); err != nil {
				t.Fatal(err)
			}
			wantInfo, err := host.Stat()
			if err != nil {
				t.Fatal(err)
			}
			gotInfo, err := virtual.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if gotInfo.Size() != wantInfo.Size() {
				t.Fatalf("size=%d want=%d", gotInfo.Size(), wantInfo.Size())
			}
			wantPos, err := host.Seek(0, io.SeekCurrent)
			if err != nil {
				t.Fatal(err)
			}
			gotPos, err := virtual.Seek(0, io.SeekCurrent)
			if err != nil {
				t.Fatal(err)
			}
			if gotPos != wantPos {
				t.Fatalf("position=%d want=%d", gotPos, wantPos)
			}
			for _, offset := range []int64{0, wantInfo.Size(), max(0, wantInfo.Size()-2)} {
				want, got := make([]byte, wantInfo.Size()+3), make([]byte, wantInfo.Size()+3)
				wn, we := host.ReadAt(want, offset)
				gn, ge := virtual.ReadAt(got, offset)
				if wn != gn || !errors.Is(ge, we) || !bytes.Equal(want, got) {
					t.Fatalf("ReadAt(%d): n=%d/%d err=%v/%v", offset, gn, wn, ge, we)
				}
			}
			want, got := make([]byte, 7), make([]byte, 7)
			wn, we := host.Read(want)
			gn, ge := virtual.Read(got)
			if wn != gn || !errors.Is(ge, we) || !bytes.Equal(want, got) {
				t.Fatalf("Read: n=%d/%d err=%v/%v", gn, wn, ge, we)
			}
		})
	}
	if _, err := store.Stat("file"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("creation visible before close: %v", err)
	}
	if err := virtual.Close(); err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(host.Name())
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "file", expected)
}

func TestFileSeekAndInvalidSizesDoNotMutateContents(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	file := openWritable(t, store, "file")
	if _, err := file.Seek(99, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if n, err := file.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty write: %d %v", n, err)
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 8 {
		t.Fatalf("empty write extended file: %v %v", info, err)
	}
	if _, err := file.Seek(math.MaxInt64, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(1, io.SeekCurrent); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := file.Seek(-1, io.SeekStart); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 99); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("bad")); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if err := file.Truncate(math.MaxInt64); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if err := file.Truncate(-1); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := file.ReadAt(make([]byte, 1), -1); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "file", []byte("original"))
	for _, op := range []func() error{
		func() error { _, err := file.Read(nil); return err },
		func() error { _, err := file.ReadAt(nil, 0); return err },
		func() error { _, err := file.Write(nil); return err },
		func() error { _, err := file.Seek(0, 0); return err },
		func() error { _, err := file.Stat(); return err },
		func() error { return file.Truncate(0) },
	} {
		if err := op(); !errors.Is(err, fs.ErrClosed) {
			t.Fatalf("closed operation: %v", err)
		}
	}
}

func TestCreateReplacesAndUpdatePreserves(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	update := openWritable(t, store, "file")
	data, err := io.ReadAll(update)
	if err != nil || string(data) != "original" {
		t.Fatalf("update contents: %q %v", data, err)
	}
	if err := update.Close(); err != nil {
		t.Fatal(err)
	}
	replacement := createVirtual(t, store, "file")
	info, err := replacement.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatalf("replacement not empty: %v", err)
	}
	assertFile(t, store, "file", []byte("original"))
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "file", nil)
	empty := createVirtual(t, store, "empty")
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "empty", nil)
	if _, err := store.Update("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := store.Create("missing/file"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := store.Create("."); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestAppendWithSeek(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	file := openWritable(t, store, "file")
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(file, bytes.NewBufferString("-one-two")); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	if err != nil || string(data) != "original-one-two" {
		t.Fatalf("append: %q %v", data, err)
	}
	assertFile(t, store, "file", []byte("original"))
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "file", data)
}

func TestCreateAndUpdateUseSameConflictRules(t *testing.T) {
	for _, existing := range []bool{false, true} {
		store := testStore(t)
		if existing {
			putFile(t, store, "file", []byte("original"))
		}
		first := createVirtual(t, store, "file")
		second := createVirtual(t, store, "file")
		if _, err := first.Write([]byte("first")); err != nil {
			t.Fatal(err)
		}
		if _, err := second.Write([]byte("second")); err != nil {
			t.Fatal(err)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		if err := second.Close(); !errors.Is(err, ErrConflict) {
			t.Fatalf("competing create: %v", err)
		}
		assertFile(t, store, "file", []byte("first"))
		update := openWritable(t, store, "file")
		if _, err := update.Write([]byte("update")); err != nil {
			t.Fatal(err)
		}
		putFile(t, store, "file", []byte("replacement"))
		if err := update.Close(); !errors.Is(err, ErrConflict) {
			t.Fatalf("update conflict: %v", err)
		}
		replacement := createVirtual(t, store, "file")
		update = openWritable(t, store, "file")
		if _, err := update.Write([]byte("new")); err != nil {
			t.Fatal(err)
		}
		if err := update.Close(); err != nil {
			t.Fatal(err)
		}
		if err := replacement.Close(); !errors.Is(err, ErrConflict) {
			t.Fatalf("replacement conflict: %v", err)
		}
	}
}

func TestCreateAbortAndRemovedParent(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	for _, name := range []string{"file", "new"} {
		file := createVirtual(t, store, name)
		if err := file.Abort(); err != nil {
			t.Fatal(err)
		}
	}
	assertFile(t, store, "file", []byte("original"))
	if _, err := store.Open("new"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := store.Mkdir("parent"); err != nil {
		t.Fatal(err)
	}
	file := createVirtual(t, store, "parent/file")
	if err := store.Remove("parent"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

// callbackReader lets a competing commit occur after WriteFile opens its handle.
type callbackReader func([]byte) (int, error)

func (read callbackReader) Read(p []byte) (int, error) { return read(p) }

func TestWriteFileRejectsConcurrentReplacement(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	reader := callbackReader(func(p []byte) (int, error) {
		putFile(t, store, "file", []byte("competing write"))
		return copy(p, "stale replacement"), io.EOF
	})
	if err := store.WriteFile("file", reader); !errors.Is(err, ErrConflict) {
		t.Fatalf("WriteFile conflict: %v", err)
	}
	assertFile(t, store, "file", []byte("competing write"))
}

func TestWriteFilePreservesUnexpectedSourceError(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("original"))
	source := io.MultiReader(bytes.NewBufferString("partial"), errorReader{io.ErrUnexpectedEOF})
	if err := store.WriteFile("file", source); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("source error: %v", err)
	}
	assertFile(t, store, "file", []byte("original"))
}
