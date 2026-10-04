package sandboxed

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// Use the public API so the same workload measures both persistence paths.
func BenchmarkDurableSmallWrites(b *testing.B) {
	for _, entries := range []int{1, 128} {
		for _, workers := range []int{1, 8} {
			b.Run(fmt.Sprintf("entries=%d/workers=%d", entries, workers), func(b *testing.B) {
				store := benchStore(b, 64<<10, true)
				for i := range entries {
					benchCheck(b, store.Mkdir(fmt.Sprintf("directory-%d", i)))
				}
				data := bytes.Repeat([]byte{0x75}, 64)
				names := make([]string, workers)
				for i := range workers {
					names[i] = fmt.Sprintf("file-%d", i)
					putFile(b, store, names[i], data)
				}
				jobs := make(chan struct{})
				failures := make(chan error, workers)
				var group sync.WaitGroup
				latencies := make([][]int64, workers)
				for index, name := range names {
					latencies[index] = make([]int64, 0, min(b.N, 4096))
					group.Add(1)
					go func() {
						defer group.Done()
						for range jobs {
							start := time.Now()
							if err := store.WriteFile(name, bytes.NewReader(data)); err != nil {
								failures <- err
								// Drain jobs after failure to avoid blocking the benchmark producer.
								for range jobs {
								}
								return
							}
							if len(latencies[index]) < cap(latencies[index]) {
								latencies[index] = append(latencies[index], time.Since(start).Nanoseconds())
							}
						}
					}()
				}
				beforeBytes, beforeGroups := store.walBytes, store.walGroups
				b.ReportAllocs()
				b.SetBytes(int64(len(data)))
				b.ResetTimer()
				for range b.N {
					jobs <- struct{}{}
				}
				close(jobs)
				group.Wait()
				benchCheck(b, store.Cleanup(context.Background()))
				b.StopTimer()
				b.ReportMetric(float64(store.walBytes-beforeBytes)/float64(b.N), "wal-B/op")
				b.ReportMetric(float64(store.walGroups-beforeGroups)/float64(b.N), "wal-syncs/op")
				samples := make([]int64, 0)
				for _, worker := range latencies {
					samples = append(samples, worker...)
				}
				sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
				for _, percentile := range []int{50, 95, 99} {
					if len(samples) > 0 {
						b.ReportMetric(float64(samples[(len(samples)-1)*percentile/100]), fmt.Sprintf("p%d-ns", percentile))
					}
				}
				close(failures)
				for err := range failures {
					b.Fatal(err)
				}
				for _, name := range names {
					assertFile(b, store, name, data)
				}
			})
		}
	}
}

// These diagnostics expose actual WAL write volume and maintenance costs.
func BenchmarkWALDelta(b *testing.B) {
	for _, count := range []int{1, 128} {
		b.Run(fmt.Sprintf("chunks=%d", count), func(b *testing.B) {
			store := benchStore(b, minimumChunkSize, true)
			putFile(b, store, "file", benchData(count*minimumChunkSize))
			patch := bytes.Repeat([]byte{0x72}, 64)
			beforeBytes, beforeGroups := store.walBytes, store.walGroups
			b.ReportAllocs()
			b.SetBytes(64)
			b.ResetTimer()
			for range b.N {
				file, err := store.Update("file")
				benchCheck(b, err)
				_, err = file.WriteAt(patch, 17)
				benchCheck(b, err)
				benchCheck(b, file.Close())
			}
			benchCheck(b, store.Cleanup(context.Background()))
			b.StopTimer()
			b.ReportMetric(float64(store.walBytes-beforeBytes)/float64(b.N), "wal-B/op")
			b.ReportMetric(float64(store.walGroups-beforeGroups)/float64(b.N), "wal-syncs/op")
		})
	}
}

func BenchmarkWALCheckpoint(b *testing.B) {
	store := benchStore(b, minimumChunkSize, true)
	for i := range 128 {
		benchCheck(b, store.Mkdir(fmt.Sprintf("directory-%d", i)))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		store.lock.Lock()
		err := store.flushCheckpoint()
		store.lock.Unlock()
		benchCheck(b, err)
	}
}

func BenchmarkWALCleanup(b *testing.B) {
	for _, count := range []int{64, 256} {
		b.Run(fmt.Sprintf("chunks=%d", count), func(b *testing.B) {
			store := benchStore(b, minimumChunkSize, true)
			data := benchData(count * minimumChunkSize)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				putFile(b, store, "file", data)
				store.lock.Lock()
				next := cloneManifest(store.manifest)
				delete(next.Entries, "file")
				err := store.commit(next, "file")
				if err != nil {
					store.lock.Unlock()
					b.Fatal(err)
				}
				b.StartTimer()
				for len(store.garbage) != 0 {
					if err := store.collect(); err != nil {
						store.lock.Unlock()
						b.Fatal(err)
					}
				}
				b.StopTimer()
				store.lock.Unlock()
				b.StartTimer()
			}
			b.StopTimer()
			b.ReportMetric(float64(count), "deleted-chunks/op")
		})
	}
}
