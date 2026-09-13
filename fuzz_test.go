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
	f.Add([]byte(`{"entries":{".":{"directory":true}}}`), int64(0), defaultChunkSize)
	f.Add([]byte(`{"entries":{".":{"directory":true},"file":{"size":1,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","chunks":[{"offset":0,"size":1}]}}}`), int64(17), defaultChunkSize)
	f.Add([]byte(`{"entries":null}`), int64(0), defaultChunkSize)

	f.Fuzz(func(t *testing.T, encoded []byte, dataSize int64, chunkSize int) {
		// Keep fuzz-controlled bounds within the format's supported domain.
		if dataSize < 0 || dataSize > int64(len(encoded))+maximumChunkSize {
			t.Skip()
		}
		if chunkSize < minimumChunkSize || chunkSize > maximumChunkSize {
			t.Skip()
		}

		// Decoding and validation may fail, but must never panic or hang.
		value, err := unmarshalManifest(header{ChunkSize: uint32(chunkSize)}, encoded, nil)
		if err != nil {
			return
		}
		_ = validateManifest(value, dataSize, chunkSize)
	})
}

func FuzzOpenStore(f *testing.F) {
	// Seed the end-to-end target with both a valid blob and malformed inputs.
	seedPath := filepath.Join(f.TempDir(), "seed.sandboxed")
	store, err := OpenStore(seedPath, WithChunkSize(minimumChunkSize))
	if err != nil {
		f.Fatal(err)
	}
	if err := store.WriteFile("file", bytes.NewReader(bytes.Repeat([]byte("seed"), 2048))); err != nil {
		f.Fatal(err)
	}
	valid, err := os.ReadFile(seedPath)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("not a store"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, blob []byte) {
		filename := filepath.Join(t.TempDir(), "fuzz.sandboxed")
		if err := os.WriteFile(filename, blob, 0600); err != nil {
			t.Fatal(err)
		}

		// Exercise the public parser and every authenticated file stream it accepts.
		store, err := OpenStore(filename)
		if err != nil {
			return
		}
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
