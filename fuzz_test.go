package sandboxed

import (
	"bytes"
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
