package sandboxed

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"
)

// One parent fixture avoids repeating durable setup during read calibration.
func BenchmarkLookupScaling(b *testing.B) {
	for _, count := range []int{1, 64, 4096} {
		b.Run(fmt.Sprintf("chunks=%d", count), func(b *testing.B) {
			store := benchStore(b, minimumChunkSize, false)
			data := benchData(count * minimumChunkSize)
			putFile(b, store, "file", data)

			for _, index := range []int{0, count - 1} {
				b.Run(fmt.Sprintf("index=%d", index), func(b *testing.B) {
					file, err := store.Open("file")
					benchCheck(b, err)
					defer func() { benchCheck(b, file.Close()) }()
					seeker := file.(io.Seeker)
					buffer := make([]byte, 64)
					offset := int64(index * minimumChunkSize)
					_, err = seeker.Seek(offset, io.SeekStart)
					benchCheck(b, err)
					_, err = io.ReadFull(file, buffer)
					benchCheck(b, err)

					b.ReportAllocs()
					b.SetBytes(int64(len(buffer)))
					b.ResetTimer()
					for range b.N {
						if _, err := seeker.Seek(offset, io.SeekStart); err != nil {
							b.Fatal(err)
						}
						if _, err := io.ReadFull(file, buffer); err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
					if !bytes.Equal(buffer, data[offset:offset+64]) {
						b.Fatal("incorrect cached read")
					}
				})
			}
		})
	}
}

func BenchmarkRandomWriteBatch(b *testing.B) {
	for _, chunkSize := range []int{64 << 10, benchMiB} {
		for _, writes := range []int{1, 16} {
			b.Run(fmt.Sprintf("chunk=%d/writes=%d", chunkSize, writes), func(b *testing.B) {
				store := benchStore(b, chunkSize, false)
				data := benchData(16 * chunkSize)
				putFile(b, store, "file", data)
				patch := bytes.Repeat([]byte{0x79}, 64)

				b.ReportAllocs()
				b.SetBytes(int64(writes * len(patch)))
				b.ResetTimer()
				for range b.N {
					file, err := store.Update("file")
					benchCheck(b, err)
					for i := range writes {
						offset := ((i*7)%16)*chunkSize + 123
						if n, err := file.WriteAt(patch, int64(offset)); err != nil || n != len(patch) {
							file.Abort()
							b.Fatalf("patch: %d, %v", n, err)
						}
					}
					benchCheck(b, file.Close())
				}
				b.StopTimer()
				for i := range writes {
					copy(data[((i*7)%16)*chunkSize+123:], patch)
				}
				assertFile(b, store, "file", data)
				b.ReportMetric(float64(writes), "writes/op")
			})
		}
	}
}

func TestStagingSpaceTracksDistinctChunks(t *testing.T) {
	store := testStore(t)
	data := benchData(3 * minimumChunkSize)
	putFile(t, store, "file", data)
	file := openWritable(t, store, "file")
	defer file.Abort()

	for i := range 80 {
		index := i % 3
		offset := index*minimumChunkSize + 29
		patch := bytes.Repeat([]byte{byte(i)}, 64)
		previous := append([]byte(nil), file.item.Chunks[index].ID...)
		writeAt(t, file, patch, int64(offset))
		copy(data[offset:], patch)

		part := file.item.Chunks[index]
		if bytes.Equal(previous, part.ID) {
			t.Fatal("reused encryption identity")
		}
		ciphertext := make([]byte, part.Size+16)
		if _, err := file.file.ReadAt(ciphertext, part.Offset); err != nil {
			t.Fatal(err)
		}
		plain, err := decryptChunk(file.item.Key, index, part, ciphertext)
		if err != nil || !bytes.Equal(plain, data[index*minimumChunkSize:(index+1)*minimumChunkSize]) {
			t.Fatalf("write did not immediately stage authenticated ciphertext: %v", err)
		}
		info, err := file.file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 3*(minimumChunkSize+16) {
			t.Fatalf("staging grew to %d bytes", info.Size())
		}
	}

	// Repeated shrink/extension must reuse space without resurrecting discarded data.
	for range 20 {
		if err := file.Truncate(0); err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(int64(len(data))); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "file", make([]byte, len(data)))
}

func TestReaderReauthenticatesAfterFailedChunkLoad(t *testing.T) {
	store := testStore(t)
	data := benchData(2 * minimumChunkSize)
	putFile(t, store, "file", data)
	file, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seeker := file.(io.Seeker)
	buffer := make([]byte, 64)
	if _, err := io.ReadFull(file, buffer); err != nil {
		t.Fatal(err)
	}

	part := store.manifest.Entries["file"].Chunks[1]
	name := chunkPath(store, part)
	ciphertext, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	if err := os.WriteFile(name, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := seeker.Seek(minimumChunkSize, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Read(buffer); err == nil {
		t.Fatal("accepted tampered chunk")
	}

	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(file, buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, data[:len(buffer)]) {
		t.Fatal("failed read corrupted the cached window")
	}
}

func TestCleanupRetriesManifestSyncWithoutGarbage(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("published"))

	// Represent a manifest whose rename succeeded but directory sync failed.
	store.manifestDirty = true
	root := store.root
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(context.Background()); err == nil {
		t.Fatal("hid failed durability barrier")
	}
	if !store.manifestDirty {
		t.Fatal("forgot failed durability barrier")
	}

	var err error
	store.root, err = openDirectory(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.manifestDirty {
		t.Fatal("did not record successful retry")
	}
	assertFile(t, store, "file", []byte("published"))
}
