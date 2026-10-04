package sandboxed

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHeaderUsesStructuredIdentifier(t *testing.T) {
	headerBytes := encodeHeader(header{
		Flags:     flagManifestAES,
		ChunkSize: defaultChunkSize,
	})

	if string(headerBytes[:9]) != "SANDBOXED" {
		t.Fatalf("signature = %q", headerBytes[:9])
	}
	if flags := binary.BigEndian.Uint16(headerBytes[9:11]); flags != flagManifestAES {
		t.Fatalf("configuration flags = %016b", flags)
	}
	if !bytes.Equal(headerBytes[11:14], []byte{0, 0, 0}) {
		t.Fatalf("reserved bytes = %v", headerBytes[11:14])
	}
	if version := binary.BigEndian.Uint16(headerBytes[14:16]); version != formatVersion {
		t.Fatalf("format version = %d", version)
	}
}

func TestStoreImplementsExpectedInterfaces(t *testing.T) {
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "data.sandboxed"))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := any(store).(fs.FS); !ok {
		t.Fatal("Store does not implement fs.FS")
	}
	if _, ok := any(store).(fs.StatFS); !ok {
		t.Fatal("Store does not implement fs.StatFS")
	}
	if _, ok := any(store).(fs.ReadFileFS); !ok {
		t.Fatal("Store does not implement fs.ReadFileFS")
	}
	if _, ok := any(store).(fs.ReadDirFS); !ok {
		t.Fatal("Store does not implement fs.ReadDirFS")
	}

	root, err := store.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, ok := root.(fs.ReadDirFile); !ok {
		t.Fatal("opened directory does not implement fs.ReadDirFile")
	}

	if err := store.WriteFile("file", strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	file, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, ok := file.(io.Seeker); !ok {
		t.Fatal("opened regular file does not implement io.Seeker")
	}
}

func TestStoreRoundTripAcrossChunks(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data.sandboxed")
	store, err := openTestStore(t, filename, WithChunkSize(minimumChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MkdirAll("media/movies"); err != nil {
		t.Fatal(err)
	}

	data := bytes.Repeat([]byte("0123456789abcdef"), 900)
	if err := store.WriteFile("media/movies/sample.bin", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	opened, err := store.Open("media/movies/sample.bin")
	if err != nil {
		t.Fatal(err)
	}
	seeker, ok := opened.(io.Seeker)
	if !ok {
		t.Fatal("open file does not implement io.Seeker")
	}
	if _, err := seeker.Seek(4090, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 40)
	if _, err := io.ReadFull(opened, buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, data[4090:4130]) {
		t.Fatal("seek across chunk returned incorrect data")
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openTestStore(t, filename)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := reopened.ReadFile("media/movies/sample.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, data) {
		t.Fatal("reopened data does not match")
	}
	if reopened.ChunkSize() != minimumChunkSize {
		t.Fatalf("unexpected chunk size: %d", reopened.ChunkSize())
	}

	info, err := reopened.Stat("media/movies/sample.bin")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0111 != 0 {
		t.Fatalf("stored file is executable: %v", info.Mode())
	}
}

func TestStoreImplementsStandardFilesystemHelpers(t *testing.T) {
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "data.sandboxed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Mkdir("docs"); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("docs/readme.txt", strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("alpha.txt", strings.NewReader("alpha")); err != nil {
		t.Fatal(err)
	}

	data, err := fs.ReadFile(store, "docs/readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("unexpected data %q", data)
	}
	names, err := fs.Glob(store, "*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"alpha.txt"}) {
		t.Fatalf("unexpected matches: %#v", names)
	}
	entries, err := fs.ReadDir(store, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != "alpha.txt" || entries[1].Name() != "docs" {
		t.Fatalf("unexpected directory entries: %#v", entries)
	}
}

func TestVirtualPathsCannotEscapeStore(t *testing.T) {
	directory := t.TempDir()
	store, err := openTestStore(t, filepath.Join(directory, "data.sandboxed"))
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(directory, "outside")

	invalid := []string{"../outside", "/outside", "a/../../outside", "./outside", "a//b", ""}
	for _, name := range invalid {
		err := store.WriteFile(name, strings.NewReader("unsafe"))
		if !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("WriteFile(%q) error = %v", name, err)
		}
	}
	if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside path was created: %v", err)
	}

	// Backslash is an ordinary io/fs character on Unix, never a host separator.
	if err := store.WriteFile(`folder\name`, strings.NewReader("safe")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "folder", "name")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("virtual backslash escaped into host path: %v", err)
	}
}

func TestPayloadIsNeverStoredAsPlaintext(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data.sandboxed")
	store, err := openTestStore(t, filename, WithChunkSize(minimumChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte("plaintext-must-not-appear-"), 400)
	if err := store.WriteFile("recognizable-name.txt", bytes.NewReader(secret)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(filename, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte("plaintext-must-not-appear-plaintext")) {
		t.Fatal("manifest contains recognizable plaintext payload")
	}
	for _, ciphertext := range chunkFiles(t, store) {
		if bytes.Contains(ciphertext, []byte("plaintext-must-not-appear-plaintext")) {
			t.Fatal("chunk contains plaintext payload")
		}
	}

	wal, err := os.ReadFile(filepath.Join(filename, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wal, []byte("recognizable-name.txt")) {
		t.Fatal("unencrypted manifest should keep pathing readable")
	}
}

func TestEncryptedManifestHidesPathsAndRejectsWrongKeys(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data.sandboxed")
	key := bytes.Repeat([]byte{0x42}, 32)
	store, err := openTestStore(t, filename, WithEncryption(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("private-name.txt", strings.NewReader("private body")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(filename, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private-name.txt")) || bytes.Contains(raw, []byte("private body")) {
		t.Fatal("encrypted store exposed manifest or payload plaintext")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openTestStore(t, filename); err == nil {
		t.Fatal("opening encrypted store without key succeeded")
	}
	wrong := bytes.Repeat([]byte{0x24}, 32)
	if _, err := openTestStore(t, filename, WithEncryption(wrong)); err == nil {
		t.Fatal("opening encrypted store with wrong key succeeded")
	}
	reopened, err := openTestStore(t, filename, WithEncryption(key))
	if err != nil {
		t.Fatal(err)
	}
	data, err := reopened.ReadFile("private-name.txt")
	if err != nil || string(data) != "private body" {
		t.Fatalf("read encrypted store: %q, %v", data, err)
	}
}

func TestTamperedChunkFailsAuthentication(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data.sandboxed")
	store, err := openTestStore(t, filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("file", strings.NewReader("authenticated data")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(filename, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	part := store.manifest.Entries["file"].Chunks[0]
	raw, err = os.ReadFile(chunkPath(store, part))
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	if err := os.WriteFile(chunkPath(store, part), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openTestStore(t, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ReadFile("file"); err == nil {
		t.Fatal("tampered chunk was accepted")
	}
}

func TestWriteReplacementAndRemovePreserveOtherFiles(t *testing.T) {
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "data.sandboxed"), WithChunkSize(minimumChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	first := bytes.Repeat([]byte("first"), 2000)
	second := bytes.Repeat([]byte("second"), 2000)
	if err := store.WriteFile("first", bytes.NewReader(first)); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("second", bytes.NewReader(second)); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("first", strings.NewReader("replacement")); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("first"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stat("first"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("removed file stat: %v", err)
	}
	actual, err := store.ReadFile("second")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, second) {
		t.Fatal("unrelated file changed")
	}
}

func TestDirectoriesMustBeEmptyBeforeRemoval(t *testing.T) {
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "data.sandboxed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MkdirAll("one/two"); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("one/two/file", strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("one"); err == nil {
		t.Fatal("removed non-empty directory")
	}
	if err := store.Remove("one/two/file"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("one/two"); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyFile(t *testing.T) {
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "data.sandboxed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("empty", bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	data, err := store.ReadFile("empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("empty file has %d bytes", len(data))
	}
}

func TestFailedStreamDoesNotPublishPartialFile(t *testing.T) {
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "data.sandboxed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("file", strings.NewReader("original")); err != nil {
		t.Fatal(err)
	}
	sourceError := errors.New("source failed")
	err = store.WriteFile("file", io.MultiReader(strings.NewReader("partial"), errorReader{sourceError}))
	if !errors.Is(err, sourceError) {
		t.Fatalf("unexpected write error: %v", err)
	}
	data, err := store.ReadFile("file")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("failed write published %q", data)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestOpenReaderKeepsAtomicSnapshot(t *testing.T) {
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "data.sandboxed"), WithChunkSize(minimumChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Repeat([]byte("old-value-"), 1000)
	if err := store.WriteFile("file", bytes.NewReader(original)); err != nil {
		t.Fatal(err)
	}
	opened, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := store.WriteFile("file", strings.NewReader("new value")); err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(opened)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, original) {
		t.Fatal("open reader did not retain its snapshot")
	}
}

func TestReadersKeepSnapshotsAcrossReplacementAndRemoval(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data.sandboxed")
	readerStore, err := openTestStore(t, filename, WithChunkSize(minimumChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	writerStore := readerStore

	// Open the original version before replacing it through the shared Store.
	original := bytes.Repeat([]byte("original-"), 1000)
	if err := writerStore.WriteFile("foo", bytes.NewReader(original)); err != nil {
		t.Fatal(err)
	}
	originalReader, err := readerStore.Open("foo")
	if err != nil {
		t.Fatal(err)
	}
	defer originalReader.Close()

	// A new reader sees the replacement while the existing reader keeps its snapshot.
	replacement := []byte("replacement")
	if err := writerStore.WriteFile("foo", bytes.NewReader(replacement)); err != nil {
		t.Fatal(err)
	}
	current, err := writerStore.ReadFile("foo")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, replacement) {
		t.Fatalf("current file = %q", current)
	}
	old, err := io.ReadAll(originalReader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, original) {
		t.Fatal("existing reader did not retain the original file")
	}

	// Removal hides the file from new readers without invalidating an open reader.
	removedReader, err := readerStore.Open("foo")
	if err != nil {
		t.Fatal(err)
	}
	defer removedReader.Close()
	if err := writerStore.Remove("foo"); err != nil {
		t.Fatal(err)
	}
	if _, err := writerStore.Open("foo"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("open removed file: %v", err)
	}
	removedSnapshot, err := io.ReadAll(removedReader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(removedSnapshot, replacement) {
		t.Fatal("reader did not finish the removed file snapshot")
	}
}

func TestDirectoryFileSupportsReadDir(t *testing.T) {
	store, err := openTestStore(t, filepath.Join(t.TempDir(), "data.sandboxed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("b", strings.NewReader("b")); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("a", strings.NewReader("a")); err != nil {
		t.Fatal(err)
	}
	root, err := store.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	directory := root.(fs.ReadDirFile)
	first, err := directory.ReadDir(1)
	if err != nil || len(first) != 1 || first[0].Name() != "a" {
		t.Fatalf("first ReadDir: %#v, %v", first, err)
	}
	second, err := directory.ReadDir(1)
	if err != nil || len(second) != 1 || second[0].Name() != "b" {
		t.Fatalf("second ReadDir: %#v, %v", second, err)
	}
	if _, err := directory.ReadDir(1); !errors.Is(err, io.EOF) {
		t.Fatalf("finished ReadDir error = %v", err)
	}
	info, err := root.Stat()
	if err != nil || !info.IsDir() {
		t.Fatalf("root stat: %#v, %v", info, err)
	}
	if _, err := root.Read(make([]byte, 1)); err == nil {
		t.Fatal("reading directory succeeded")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationAndMalformedStores(t *testing.T) {
	if _, err := openTestStore(t, filepath.Join(t.TempDir(), "small"), WithChunkSize(1)); err == nil {
		t.Fatal("accepted undersized chunks")
	}
	if _, err := openTestStore(t, filepath.Join(t.TempDir(), "key"), WithEncryption([]byte("short"))); err == nil {
		t.Fatal("accepted short key")
	}
	if _, err := openTestStore(t, filepath.Join(t.TempDir(), "mode"), WithFileMode(fs.ModeDir|0700)); err == nil {
		t.Fatal("accepted non-permission file mode bits")
	}
	directory := t.TempDir()
	filename := filepath.Join(directory, "bad.sandboxed")
	if err := os.WriteFile(filename, []byte("not a store"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTestStore(t, filename); err == nil {
		t.Fatal("opened truncated malformed store")
	}

	valid := filepath.Join(directory, "valid.sandboxed")
	validStore, err := openTestStore(t, valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := validStore.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(valid, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	if err := os.WriteFile(filepath.Join(valid, "manifest"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTestStore(t, valid); err == nil {
		t.Fatal("opened store with invalid magic")
	}
}

func TestBackingFileModeIsConfigurable(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data.sandboxed")
	store, err := openTestStore(t, filename, WithFileMode(0640))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(filename, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("initial mode = %04o", info.Mode().Perm())
	}
	if err := store.WriteFile("file", strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(filename, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("replacement mode = %04o", info.Mode().Perm())
	}
}

func TestStoreSerializesConcurrentMutations(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data.sandboxed")
	first, err := openTestStore(t, filename)
	if err != nil {
		t.Fatal(err)
	}
	second := first

	start := make(chan struct{})
	errors := make(chan error, 2)
	go func() {
		<-start
		errors <- first.WriteFile("first", strings.NewReader("written by first store"))
	}()
	go func() {
		<-start
		errors <- second.WriteFile("second", strings.NewReader("written by second store"))
	}()
	close(start)
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}

	// Both goroutines publish into the shared manifest without losing updates.
	for _, store := range []*Store{first, second} {
		for name, expected := range map[string]string{
			"first":  "written by first store",
			"second": "written by second store",
		} {
			data, err := store.ReadFile(name)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if string(data) != expected {
				t.Fatalf("%s = %q", name, data)
			}
		}
	}

	if _, err := os.Stat(filepath.Join(filename, "lock")); err != nil {
		t.Fatalf("coordination lock file: %v", err)
	}
}

func TestStoreRejectsUnsupportedFormatVersions(t *testing.T) {
	store := testStore(t)
	original := manifestBytes(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint16{0, formatVersion + 1, 65535} {
		raw := append([]byte(nil), original...)
		binary.BigEndian.PutUint16(raw[14:16], version)
		if err := os.WriteFile(filepath.Join(store.path, "manifest"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := openTestStore(t, store.path); err == nil {
			t.Fatalf("accepted format version %d", version)
		}
	}
}
