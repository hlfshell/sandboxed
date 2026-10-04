package sandboxed

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkSparseAllocation(b *testing.B) {
	for _, gap := range []int64{0, 1 << 20, 16 << 20, 1 << 30} {
		for _, operation := range []string{"write", "truncate"} {
			b.Run(fmt.Sprintf("gap=%d/%s", gap, operation), func(b *testing.B) {
				store := benchStore(b, 64<<10, true)
				payload := benchData(64)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					file, err := store.Create("file")
					benchCheck(b, err)
					if operation == "write" {
						if _, err := file.WriteAt(payload, gap); err != nil {
							file.Abort()
							b.Fatal(err)
						}
					} else if err := file.Truncate(gap); err != nil {
						file.Abort()
						b.Fatal(err)
					}
					benchCheck(b, file.Close())
				}
				b.StopTimer()
				info, err := store.Stat("file")
				benchCheck(b, err)
				want := gap
				if operation == "write" {
					want += int64(len(payload))
				}
				if info.Size() != want {
					b.Fatalf("size: %d, want %d", info.Size(), want)
				}
				file, err := store.Open("file")
				benchCheck(b, err)
				if operation == "write" {
					_, err := file.(io.Seeker).Seek(gap, io.SeekStart)
					benchCheck(b, err)
					got := make([]byte, len(payload))
					_, err = io.ReadFull(file, got)
					benchCheck(b, err)
					if !bytes.Equal(got, payload) {
						b.Fatal("incorrect distant payload")
					}
				}
				benchCheck(b, file.Close())
				var payloadBytes int64
				for _, part := range store.manifest.Entries["file"].Chunks {
					payloadBytes += int64(part.Size + 16)
				}
				manifest, err := os.Stat(filepath.Join(store.Path(), "manifest"))
				benchCheck(b, err)
				b.ReportMetric(float64(payloadBytes), "stored-payload-B")
				b.ReportMetric(float64(manifest.Size()), "manifest-B")
			})
		}
	}
}

func BenchmarkSparseRead(b *testing.B) {
	for _, pattern := range []string{"holes", "mixed"} {
		b.Run(pattern, func(b *testing.B) {
			store := benchStore(b, 64<<10, false)
			file, err := store.Create("file")
			benchCheck(b, err)
			const size = 16 * benchMiB
			if pattern == "mixed" {
				data := benchData(4096)
				for offset := 0; offset < size; offset += 4 * benchMiB {
					_, err := file.WriteAt(data, int64(offset))
					benchCheck(b, err)
				}
			}
			benchCheck(b, file.Truncate(size))
			benchCheck(b, file.Close())
			buffer := make([]byte, 64<<10)

			b.ReportAllocs()
			b.SetBytes(size)
			b.ResetTimer()
			for range b.N {
				reader, err := store.Open("file")
				benchCheck(b, err)
				n, err := io.CopyBuffer(struct{ io.Writer }{io.Discard}, struct{ io.Reader }{reader}, buffer)
				closeErr := reader.Close()
				benchCheck(b, err)
				benchCheck(b, closeErr)
				if n != size {
					b.Fatal("short sparse stream")
				}
			}
			b.StopTimer()
			if !bytes.Equal(buffer, make([]byte, len(buffer))) {
				b.Fatal("trailing hole was not zero-filled")
			}
		})
	}
}

func BenchmarkSparseRandomAllocation(b *testing.B) {
	for _, count := range []int{64, 512} {
		for _, order := range []string{"ascending", "permuted"} {
			b.Run(fmt.Sprintf("chunks=%d/%s", count, order), func(b *testing.B) {
				store := benchStore(b, 64<<10, false)
				data := benchData(64)
				b.ReportAllocs()
				b.SetBytes(int64(count * len(data)))
				b.ResetTimer()
				for range b.N {
					file, err := store.Create("file")
					benchCheck(b, err)
					for i := range count {
						index := i
						if order == "permuted" {
							index = (i*2053 + 17) % count
						}
						offset := int64(index*17+5)*int64(store.ChunkSize()) + 7
						if _, err := file.WriteAt(data, offset); err != nil {
							file.Abort()
							b.Fatal(err)
						}
					}
					benchCheck(b, file.Close())
				}
				b.StopTimer()
				item := store.manifest.Entries["file"]
				if len(item.Chunks) != count {
					b.Fatal("gap allocated payload")
				}
				for i, part := range item.Chunks {
					if part.Index != i*17+5 {
						b.Fatal("unsorted sparse layout")
					}
					plain, err := store.readChunk(item.Key, part.Index, part)
					benchCheck(b, err)
					if len(plain) != 71 || !bytes.Equal(plain[7:], data) || !bytes.Equal(plain[:7], make([]byte, 7)) {
						b.Fatal("incorrect sparse payload")
					}
				}
				b.ReportMetric(float64(count), "chunks/op")
			})
		}
	}
}

// Isolate lookup growth from disk access and cryptographic work.
func BenchmarkSparseIndex(b *testing.B) {
	for _, count := range []int{1, 64, 4096} {
		b.Run(fmt.Sprintf("chunks=%d", count), func(b *testing.B) {
			item := entry{Chunks: make([]chunk, count)}
			for i := range item.Chunks {
				item.Chunks[i].Index = i*2 + 1
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				index := int((uint64(i)*2053 + 17) % uint64(2*count))
				position, exists := item.chunkPosition(index)
				if exists != (index%2 == 1) || (exists && item.Chunks[position].Index != index) {
					b.Fatal("incorrect sparse lookup")
				}
			}
		})
	}
}
