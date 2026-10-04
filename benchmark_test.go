package sandboxed

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// All BenchmarkSuite cases exclude fixture creation and final verification.
// Mutations include Close (encryption, publication, and durable commit).
// Deferred cleanup can overlap measurements; fixture cleanup drains the remainder.
const benchMiB = 1 << 20

func benchData(n int) []byte {
	p := make([]byte, n)
	var x uint32 = 0x12345678
	for i := range p {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		p[i] = byte(x)
	}
	return p
}

func benchCheck(b *testing.B, err error) {
	b.Helper()
	if err != nil {
		b.Fatal(err)
	}
}

func benchStore(b *testing.B, chunk int, encrypted bool) *Store {
	b.Helper()
	options := []Option{WithChunkSize(chunk)}
	if encrypted {
		options = append(options, WithEncryption(bytes.Repeat([]byte{42}, 32)))
	}
	s, err := OpenStore(filepath.Join(b.TempDir(), "store"), options...)
	benchCheck(b, err)
	b.Cleanup(func() {
		// Catch leaked readers/writers and unreclaimed ciphertext after every case.
		benchCheck(b, s.Close())
		chunks, err := os.ReadDir(filepath.Join(s.Path(), "chunks"))
		benchCheck(b, err)
		live := 0
		for _, item := range s.manifest.Entries {
			live += len(item.Chunks)
		}
		if len(chunks) != live {
			b.Errorf("chunk leak: have %d, want %d", len(chunks), live)
		}
		entries, err := os.ReadDir(s.Path())
		benchCheck(b, err)
		if len(entries) != 4 {
			b.Errorf("unexpected staging files: %v", entries)
		}
	})
	return s
}

func BenchmarkSuiteWriteFile(b *testing.B) {
	for _, chunk := range []int{4096, 64 << 10, benchMiB} {
		for _, size := range []int{0, 4096, benchMiB, 16 * benchMiB} {
			for _, encrypted := range []bool{false, true} {
				b.Run(fmt.Sprintf("chunk=%d/bytes=%d/encrypted=%t", chunk, size, encrypted), func(b *testing.B) {
					s := benchStore(b, chunk, encrypted)
					data := benchData(size)
					putFile(b, s, "file", data)
					b.ReportAllocs()
					b.SetBytes(int64(size))
					b.ResetTimer()
					for range b.N {
						benchCheck(b, s.WriteFile("file", bytes.NewReader(data)))
					}
					b.StopTimer()
					assertFile(b, s, "file", data)
				})
			}
		}
	}
}

func BenchmarkSuiteRead(b *testing.B) {
	for _, chunk := range []int{4096, 64 << 10, benchMiB} {
		for _, size := range []int{benchMiB, 16 * benchMiB} {
			for _, buffer := range []int{4096, 64 << 10, 0} {
				b.Run(fmt.Sprintf("chunk=%d/bytes=%d/buffer=%d", chunk, size, buffer), func(b *testing.B) {
					s := benchStore(b, chunk, false)
					data := benchData(size)
					putFile(b, s, "file", data)
					buf := make([]byte, buffer)
					b.ReportAllocs()
					b.SetBytes(int64(size))
					b.ResetTimer()
					for range b.N {
						if buffer == 0 {
							got, err := s.ReadFile("file")
							benchCheck(b, err)
							if len(got) != size {
								b.Fatal("short ReadFile")
							}
						} else {
							f, err := s.Open("file")
							benchCheck(b, err)
							// Hide optional Copy optimizations so buffer size is actually exercised.
							n, err := io.CopyBuffer(struct{ io.Writer }{io.Discard}, struct{ io.Reader }{f}, buf)
							closeErr := f.Close()
							benchCheck(b, errors.Join(err, closeErr))
							if n != int64(size) {
								b.Fatal("short stream")
							}
						}
					}
					b.StopTimer()
					assertFile(b, s, "file", data)
				})
			}
		}
	}
}

func BenchmarkSuiteSeekRead(b *testing.B) {
	for _, chunks := range []int{1, 64, 4096} {
		for _, pattern := range []string{"cached-first", "cached-last", "random"} {
			b.Run(fmt.Sprintf("chunks=%d/%s", chunks, pattern), func(b *testing.B) {
				s := benchStore(b, 4096, false)
				data := benchData(chunks * 4096)
				putFile(b, s, "file", data)
				f, err := s.Open("file")
				benchCheck(b, err)
				defer func() { benchCheck(b, f.Close()) }()
				seek := f.(io.Seeker)
				buf := make([]byte, 64)
				// Prime the relevant chunk; random visits permute chunks deterministically.
				offset := 0
				if pattern == "cached-last" {
					offset = (chunks - 1) * 4096
				}
				_, err = seek.Seek(int64(offset), io.SeekStart)
				benchCheck(b, err)
				_, err = io.ReadFull(f, buf)
				benchCheck(b, err)
				b.ReportAllocs()
				b.SetBytes(64)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if pattern == "random" {
						offset = ((i*2053 + 17) % chunks) * 4096
					}
					_, err := seek.Seek(int64(offset), io.SeekStart)
					benchCheck(b, err)
					_, err = io.ReadFull(f, buf)
					benchCheck(b, err)
					if !bytes.Equal(buf, data[offset:offset+64]) {
						b.Fatal("seek returned wrong data")
					}
				}
				b.StopTimer()
			})
		}
	}
}

func BenchmarkSuitePatch(b *testing.B) {
	for _, chunk := range []int{4096, 64 << 10, benchMiB} {
		for _, cross := range []bool{false, true} {
			b.Run(fmt.Sprintf("chunk=%d/cross=%t", chunk, cross), func(b *testing.B) {
				s := benchStore(b, chunk, false)
				data := benchData(4 * chunk)
				putFile(b, s, "file", data)
				before := benchIDs(s, "file")
				patch := bytes.Repeat([]byte{0xa5}, 64)
				offset := chunk
				changed := 1
				if cross {
					offset -= 32
					changed = 2
				}
				b.ReportAllocs()
				b.SetBytes(64)
				b.ResetTimer()
				for range b.N {
					f, err := s.Update("file")
					benchCheck(b, err)
					n, err := f.WriteAt(patch, int64(offset))
					if err != nil {
						f.Abort()
						b.Fatal(err)
					}
					benchCheck(b, f.Close())
					if n != len(patch) {
						b.Fatal("short patch")
					}
				}
				b.StopTimer()
				copy(data[offset:], patch)
				assertFile(b, s, "file", data)
				after := benchIDs(s, "file")
				replacements := 0
				for i := range before {
					if before[i] != after[i] {
						replacements++
					}
				}
				if replacements != changed {
					b.Fatalf("changed %d chunks, want %d", replacements, changed)
				}
				b.ReportMetric(float64(changed), "chunks/op")
				b.ReportMetric(float64(changed*(chunk+16))/64, "payload-amplification")
			})
		}
	}
}

type chunkID string

func benchIDs(s *Store, name string) []chunkID {
	var ids []chunkID
	for _, c := range s.manifest.Entries[name].Chunks {
		ids = append(ids, chunkID(string(c.ID)))
	}
	return ids
}

func BenchmarkSuiteStagedWrites(b *testing.B) {
	for _, block := range []int{4096, 64 << 10, benchMiB} {
		b.Run(fmt.Sprintf("block=%d", block), func(b *testing.B) {
			s := benchStore(b, benchMiB, false)
			data := benchData(benchMiB)
			var staging int64
			b.ReportAllocs()
			b.SetBytes(benchMiB)
			b.ResetTimer()
			for range b.N {
				f, err := s.Create("file")
				benchCheck(b, err)
				for offset := 0; offset < len(data); offset += block {
					n, err := f.Write(data[offset : offset+block])
					if err != nil || n != block {
						f.Abort()
						b.Fatalf("write: %d %v", n, err)
					}
				}
				// Inspect one iteration outside timing, before Close removes staging.
				if staging == 0 {
					b.StopTimer()
					info, err := f.file.Stat()
					benchCheck(b, err)
					staging = info.Size()
					b.StartTimer()
				}
				benchCheck(b, f.Close())
			}
			b.StopTimer()
			assertFile(b, s, "file", data)
			b.ReportMetric(float64(staging)/benchMiB, "staging-size-ratio")
			// Each growing chunk is encrypted immediately. Slot reuse reduces
			// retained storage, but does not remove these logical write bytes.
			writes := benchMiB / block
			stagedBytes := int64(block)*int64(writes)*int64(writes+1)/2 + int64(16*writes)
			b.ReportMetric(float64(stagedBytes)/benchMiB, "staging-write-ratio")
		})
	}
}

func BenchmarkSuiteMetadata(b *testing.B) {
	for _, entries := range []int{1, 100, 1000} {
		for _, operation := range []string{"stat", "readdir", "commit", "reopen"} {
			b.Run(fmt.Sprintf("entries=%d/%s", entries, operation), func(b *testing.B) {
				s := benchStore(b, 4096, true)
				for i := 0; i < entries; i++ {
					putFile(b, s, fmt.Sprintf("file-%06d", i), []byte{byte(i)})
				}
				data := []byte{42}
				key := bytes.Repeat([]byte{42}, 32)
				if operation == "reopen" {
					benchCheck(b, s.Close())
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					switch operation {
					case "stat":
						info, err := s.Stat("file-000000")
						benchCheck(b, err)
						if info.Size() != 1 {
							b.Fatal("wrong stat")
						}
					case "readdir":
						list, err := s.ReadDir(".")
						benchCheck(b, err)
						if len(list) != entries {
							b.Fatal("wrong entry count")
						}
					case "commit":
						benchCheck(b, s.WriteFile("file-000000", bytes.NewReader(data)))
					case "reopen":
						next, err := OpenStore(s.Path(), WithEncryption(key))
						benchCheck(b, err)
						// Keep fixture ownership with the original pointer's cleanup by closing each opener.
						benchCheck(b, next.Close())
					}
				}
				b.StopTimer()
				if operation == "commit" {
					assertFile(b, s, "file-000000", data)
				}
				info, err := os.Stat(filepath.Join(s.Path(), "manifest"))
				benchCheck(b, err)
				b.ReportMetric(float64(info.Size()), "manifest-B")
			})
		}
	}
}

func BenchmarkSuiteLifecycle(b *testing.B) {
	for _, operation := range []string{"append", "truncate-shrink", "truncate-grow", "abort", "snapshot-remove"} {
		b.Run(operation, func(b *testing.B) {
			s := benchStore(b, 4096, false)
			data := benchData(64 << 10)
			putFile(b, s, "file", data)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				// Reset outside timing: each operation starts with the same file size.
				b.StopTimer()
				putFile(b, s, "file", data)
				b.StartTimer()
				if operation == "snapshot-remove" {
					f, err := s.Open("file")
					benchCheck(b, err)
					benchCheck(b, s.Remove("file"))
					b.StopTimer()
					got, err := io.ReadAll(f)
					benchCheck(b, err)
					if !bytes.Equal(got, data) {
						b.Fatal("snapshot invalidated")
					}
					b.StartTimer()
					benchCheck(b, f.Close()) // Includes deletion of retained chunks.
				} else {
					f, err := s.Update("file")
					benchCheck(b, err)
					var opErr error
					switch operation {
					case "append":
						_, opErr = f.WriteAt(data[:4096], int64(len(data)))
					case "truncate-shrink":
						opErr = f.Truncate(4097)
					case "truncate-grow":
						opErr = f.Truncate(int64(len(data) + 8192))
					case "abort":
						_, opErr = f.WriteAt(data[:4096], 0)
					}
					if opErr != nil {
						f.Abort()
						b.Fatal(opErr)
					}
					if operation == "abort" {
						benchCheck(b, f.Abort())
					} else {
						benchCheck(b, f.Close())
					}
				}
			}
			b.StopTimer()
			switch operation {
			case "append":
				assertFile(b, s, "file", append(data, data[:4096]...))
			case "truncate-shrink":
				assertFile(b, s, "file", data[:4097])
			case "truncate-grow":
				assertFile(b, s, "file", append(data, make([]byte, 8192)...))
			case "abort":
				assertFile(b, s, "file", data)
			case "snapshot-remove":
				_, err := s.Stat("file")
				if !errors.Is(err, os.ErrNotExist) {
					b.Fatalf("removed file: %v", err)
				}
			}
		})
	}
}

func BenchmarkSuiteParallel(b *testing.B) {
	for _, operation := range []string{"read", "write", "mixed"} {
		b.Run(operation, func(b *testing.B) {
			s := benchStore(b, 64<<10, false)
			data := benchData(64 << 10)
			// Fixed namespace prevents manifest size growing with b.N or worker count.
			for i := 0; i < 16; i++ {
				putFile(b, s, fmt.Sprintf("file-%d", i), data)
			}
			var sequence, conflicts atomic.Int64
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i := sequence.Add(1)
					name := fmt.Sprintf("file-%d", i%16)
					if operation == "read" || (operation == "mixed" && i%10 != 0) {
						got, err := s.ReadFile(name)
						if err != nil || !bytes.Equal(got, data) {
							b.Errorf("parallel read: %v", err)
							return
						}
					} else {
						err := s.WriteFile(name, bytes.NewReader(data))
						if errors.Is(err, ErrConflict) {
							conflicts.Add(1)
						} else if err != nil {
							b.Error(err)
							return
						}
					}
				}
			})
			b.StopTimer()
			// A conflict is an attempted operation, never counted as a successful write.
			b.ReportMetric(float64(conflicts.Load())/float64(b.N), "conflicts/op")
			if operation != "read" {
				b.SetBytes(0)
			}
			for i := 0; i < 16; i++ {
				assertFile(b, s, fmt.Sprintf("file-%d", i), data)
			}
		})
	}
}

func BenchmarkSuiteNative(b *testing.B) {
	for _, size := range []int{4096, benchMiB, 16 * benchMiB} {
		for _, operation := range []string{"read", "durable-replace"} {
			b.Run(fmt.Sprintf("bytes=%d/%s", size, operation), func(b *testing.B) {
				dir := b.TempDir()
				name := filepath.Join(dir, "file")
				data := benchData(size)
				benchCheck(b, os.WriteFile(name, data, 0600))
				root, err := os.Open(dir)
				benchCheck(b, err)
				defer func() { benchCheck(b, root.Close()) }()
				buf := make([]byte, 64<<10)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for range b.N {
					if operation == "read" {
						f, err := os.Open(name)
						benchCheck(b, err)
						n, err := io.CopyBuffer(struct{ io.Writer }{io.Discard}, struct{ io.Reader }{f}, buf)
						benchCheck(b, errors.Join(err, f.Close()))
						if n != int64(size) {
							b.Fatal("short read")
						}
					} else {
						f, err := os.CreateTemp(dir, ".replace-")
						benchCheck(b, err)
						n, err := f.Write(data)
						benchCheck(b, errors.Join(err, f.Sync(), f.Close()))
						if n != size {
							b.Fatal("short write")
						}
						benchCheck(b, os.Rename(f.Name(), name))
						benchCheck(b, root.Sync())
					}
				}
				b.StopTimer()
				got, err := os.ReadFile(name)
				benchCheck(b, err)
				if !bytes.Equal(got, data) {
					b.Fatal("native data mismatch")
				}
			})
		}
	}
}

// Separate cryptographic CPU/allocation cost from filesystem sync cost.
func BenchmarkSuiteCrypto(b *testing.B) {
	for _, size := range []int{4096, 64 << 10, benchMiB} {
		for _, operation := range []string{"seal", "decrypt"} {
			b.Run(fmt.Sprintf("bytes=%d/%s", size, operation), func(b *testing.B) {
				key := bytes.Repeat([]byte{42}, 32)
				data := benchData(size)
				part, ciphertext, err := sealChunk(key, 0, data)
				benchCheck(b, err)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for range b.N {
					if operation == "seal" {
						part, ciphertext, err = sealChunk(key, 0, data)
						benchCheck(b, err)
					} else {
						plain, err := decryptChunk(key, 0, part, ciphertext)
						benchCheck(b, err)
						if len(plain) != size {
							b.Fatal("short decrypted chunk")
						}
					}
				}
				b.StopTimer()
				plain, err := decryptChunk(key, 0, part, ciphertext)
				benchCheck(b, err)
				if !bytes.Equal(plain, data) {
					b.Fatal("crypto roundtrip mismatch")
				}
			})
		}
	}
}
