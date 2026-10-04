package sandboxed

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func FuzzDecodeHeader(f *testing.F) {
	valid := encodeHeader(header{ChunkSize: defaultChunkSize})
	f.Add(valid)
	f.Add([]byte("not a sandboxed header"))
	f.Add(make([]byte, headerSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Header parsing must reject arbitrary bytes without panicking.
		_, _ = decodeHeader(data)
	})
}

func FuzzDecodeAndValidateManifest(f *testing.F) {
	// Include valid sparse layouts so mutations reach index and span validation.
	for _, allocated := range []bool{false, true} {
		item := entry{Size: 1 << 30, Key: make([]byte, 32), Revision: make([]byte, 32)}
		if allocated {
			item.Chunks = []chunk{{Index: 17, Size: 7, ID: make([]byte, 32)}}
		}
		encoded, err := json.Marshal(manifest{Entries: map[string]entry{".": {Directory: true}, "sparse": item}})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded, defaultChunkSize)
	}

	f.Add([]byte(`{"entries":{".":{"directory":true}}}`), defaultChunkSize)
	f.Add([]byte(`{"entries":{".":{"directory":true},"file":{"size":1,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","chunks":[{"offset":0,"size":1}]}}}`), defaultChunkSize)
	f.Add([]byte(`{"entries":null}`), defaultChunkSize)

	f.Fuzz(func(t *testing.T, encoded []byte, chunkSize int) {
		// Keep fuzz-controlled bounds within the format's supported domain.
		if chunkSize < minimumChunkSize || chunkSize > maximumChunkSize {
			t.Skip()
		}

		// Decoding and validation may fail, but must never panic or hang.
		value, err := unmarshalManifest(header{ChunkSize: uint32(chunkSize)}, encoded, nil)
		if err != nil {
			return
		}
		_ = validateManifest(value, chunkSize)
	})
}

func FuzzOpenStore(f *testing.F) {
	// Seed the end-to-end target with both a valid manifest and malformed inputs.
	seedPath := filepath.Join(f.TempDir(), "seed.sandboxed")
	store, err := OpenStore(seedPath, WithChunkSize(minimumChunkSize))
	if err != nil {
		f.Fatal(err)
	}
	putFile(f, store, "file", bytes.Repeat([]byte("seed"), 2048))
	chunks := chunkFiles(f, store)
	if err := store.Close(); err != nil {
		f.Fatal(err)
	}
	valid, err := os.ReadFile(filepath.Join(seedPath, "manifest"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("not a store"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, encoded []byte) {
		filename := filepath.Join(t.TempDir(), "fuzz.sandboxed")
		if err := os.Mkdir(filename, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(filename, "chunks"), 0700); err != nil {
			t.Fatal(err)
		}
		for name, data := range chunks {
			if err := os.WriteFile(filepath.Join(filename, "chunks", name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(filename, "manifest"), encoded, 0600); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(filename, "wal"), nil, 0600); err != nil {
			t.Fatal(err)
		}

		// Exercise the public parser and every authenticated file stream it accepts.
		store, err := OpenStore(filename)
		if err != nil {
			return
		}
		defer store.Close()
		err = fs.WalkDir(store, ".", func(name string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil || item.IsDir() {
				return walkErr
			}
			file, err := store.Open(name)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(io.Discard, file)
			return err
		})
		_ = err
	})
}

// Exercise buffer reuse and staging-slot reuse against an independent byte model.
func FuzzFileEditsMatchBytes(f *testing.F) {
	f.Add([]byte{0, 255, 63, 7, 0, 0, 32, 9, 0, 130, 32, 5, 1, 10, 0, 0, 1, 200, 0, 0, 2, 130, 63, 0})
	f.Add([]byte{0, 0, 32, 7, 0, 100, 32, 9, 1, 0, 0, 0, 3, 100, 16, 3})
	f.Add([]byte{0, 0, 63, 1, 1, 1, 0, 0, 1, 100, 0, 0, 2, 0, 63, 0})

	f.Fuzz(func(t *testing.T, operations []byte) {
		if len(operations) > 256 {
			t.Skip()
		}
		store := testStore(t)
		file := createVirtual(t, store, "file")
		var expected []byte

		for i := 0; i+3 < len(operations); i += 4 {
			operation := operations[i] % 4
			offset := int(operations[i+1]) * 257
			length := int(operations[i+2] % 64)
			payload := bytes.Repeat([]byte{operations[i+3]}, length)

			switch operation {
			case 0, 3:
				var n int
				var err error
				if operation == 0 {
					n, err = file.WriteAt(payload, int64(offset))
				} else {
					if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
						t.Fatal(err)
					}
					n, err = file.Write(payload)
				}
				if err != nil || n != length {
					t.Fatalf("write: %d, %v", n, err)
				}
				if length != 0 {
					if offset+length > len(expected) {
						expected = append(expected, make([]byte, offset+length-len(expected))...)
					}
					copy(expected[offset:], payload)
				}
			case 1:
				if err := file.Truncate(int64(offset)); err != nil {
					t.Fatal(err)
				}
				if offset <= len(expected) {
					expected = expected[:offset]
				} else {
					expected = append(expected, make([]byte, offset-len(expected))...)
				}
			case 2:
				got := make([]byte, length)
				n, err := file.ReadAt(got, int64(offset))
				want := min(length, max(0, len(expected)-offset))
				if n != want || (want < length && err != io.EOF) || (want == length && err != nil) {
					t.Fatalf("read: %d/%d, %v", n, want, err)
				}
				if want > 0 && !bytes.Equal(got[:want], expected[offset:offset+want]) {
					t.Fatal("staged read mismatch")
				}
			}
		}

		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		assertFile(t, store, "file", expected)
	})
}

func FuzzWALChanges(f *testing.F) {
	f.Add([]byte(`[{"name":"directory","item":{"directory":true},"reset":true}]`))
	f.Add([]byte(`[{"name":".","item":null}]`))
	f.Add([]byte(`[{"name":"file","item":{"size":9},"put":[{"index":-1}]}]`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 64<<10 {
			t.Skip()
		}
		var changes []walChange
		if err := json.Unmarshal(encoded, &changes); err != nil {
			return
		}
		value := manifest{Entries: map[string]entry{".": {Directory: true}}}
		if err := applyChanges(&value, changes); err != nil {
			return
		}
		_ = validateManifest(value, minimumChunkSize)
	})
}
