# Benchmarking sandboxed

Run the correctness and race suites, then repeated performance measurements:

```sh
./scripts/benchmark.sh
```

The runner saves environment details, the source revision and dirty status, test
results, and Go benchmark output under `benchmark-results/<UTC timestamp>/`.
It defaults to five samples, one second per case, and 1 and 4 CPUs. The full
matrix can take tens of minutes: fixture setup performs real durable commits,
and each 16 MiB write with 4 KiB chunks syncs 4,096 separate chunk files.
Use an otherwise idle machine and enough free disk space. Cases clean up their
fixtures; they do not accumulate one file per benchmark iteration.

For a complete single-iteration smoke check:

```sh
GOCACHE=/tmp/sandboxed-go-cache go test -run '^$' -bench BenchmarkSuite \
  -benchmem -benchtime 1x -cpu 2 -timeout 15m
```

For focused measurements on the intended deployment filesystem:

```sh
BENCH_TMPDIR=/path/on/target/filesystem COUNT=5 CPU=1,4 \
  BENCH='BenchmarkSuite(Patch|SeekRead|Parallel)$' ./scripts/benchmark.sh
```

`BENCHTIME`, `COUNT`, `CPU`, `TIMEOUT`, and `BENCH` override the defaults. Pass an
output directory as the first argument. `BENCH_TMPDIR` controls fixtures for
both tests and benchmarks. Avoid tmpfs when evaluating durable writes. Run the
same command and Go version on two revisions and compare their `bench.txt`
files with Go's `benchstat` tool if installed. Preserve the raw samples; a
single run is insufficient for a regression threshold. Profiling a focused
case with `-cpuprofile` or `-memprofile` can explain a regression after timing
it without profiling.

## Coverage and expectations

| Family | What it measures and checks |
| --- | --- |
| `WriteFile` | Durable replacement of 0 B, 4 KiB, 1 MiB, and 16 MiB files; 4 KiB, 64 KiB, and 1 MiB chunks; plain versus encrypted manifests. Verifies final content. |
| `Read` | Fresh-handle streaming with 4 KiB and 64 KiB buffers, plus whole-file `ReadFile` (`buffer=0`). Checks byte counts and final content. |
| `SeekRead` | Cached first/last chunk and deterministic permuted chunk access across 1, 64, and 4,096 chunks. Checks every returned slice. Cached-last exposes offset lookup cost separately from decryption. |
| `Patch` | Committed 64-byte updates within one chunk and across a boundary. Checks content and exact changed chunk identities; reports published payload amplification. |
| `StagedWrites` | Creates a 1 MiB file through 4 KiB, 64 KiB, or 1 MiB `File.Write` calls. Reports retained staging size and calculated cumulative staging writes divided by logical bytes. |
| `Metadata` | Stat, listing, one-byte replacement, and reopening stores with 1, 100, and 1,000 one-chunk files and encrypted manifests. Reports manifest size. Reopen includes validation and close. |
| `Lifecycle` | Append, unaligned shrink, zero-filled growth, abort, and snapshot removal/final-reader cleanup. Resets the fixture outside timing; verifies final bytes or absence. |
| `Parallel` | Shared-store reads, writes, and a 90% read / 10% write mix over 16 fixed files. Reports optimistic conflicts separately and checks data. Use `-cpu` to vary contention. |
| `Native` | Native streaming reads and temporary-file write + file sync + rename + directory sync. Provides filesystem context; it has no encryption, chunk snapshots, or manifest semantics. |
| `LookupScaling` | Cached seek/read scaling with shared fixtures and minimal timing overhead. |
| `RandomWriteBatch` | One versus sixteen immediately encrypted random patches per committed handle. |
| `SparseAllocation` | Committed distant writes and metadata-only growth at 0, 1 MiB, 16 MiB, and 1 GiB; reports actual stored ciphertext bytes and manifest length. |
| `SparseRead` | Streams 16 MiB of holes or mixed allocated data and holes; generated-zero throughput is not disk bandwidth. |
| `SparseRandomAllocation` | Allocates 64 or 512 separated chunks in ascending or permuted order and verifies every committed payload. |
| `SparseIndex` | Isolates sparse lookup cost at 1, 64, and 4,096 allocated records. |
| `Crypto` | Chunk sealing (including random identity/key derivation) and authenticated decryption in memory. Separates CPU/allocation cost from filesystem cost. |

Every store fixture checks that all handles close, only live chunks remain,
and no staging files remain. Existing security, persistence, ownership, and
file-semantics tests remain the correctness gates; timing does not establish
security or crash durability. `BenchmarkPartialWrite` also
measures patching a small file alongside 1, 16, and 64 MiB of unrelated payload;
run it alone with `-bench '^BenchmarkPartialWrite$'`.

Expected behavior is based on the implementation and README, not an invented
latency SLA:

- A patch publishes exactly the touched chunks, regardless of unrelated payload.
  A 64-byte patch can still rewrite a whole 1 MiB chunk. The amplification metric
  includes the 16-byte authentication tag, excludes manifest and staging writes,
  and is a logical byte estimate, not device I/O instrumentation.
- Commit cost grows with manifest entries/chunks because it clones, validates,
  and encodes the full manifest. Unchanged chunk metadata is shared, and
  reference accounting visits only changed entries.
- Streaming bounds individual payload buffers by chunk size, but total `B/op`
  can grow with bytes processed. **Allocated bytes are not peak live memory.**
  `ReadFile` intentionally retains the entire plaintext. Use heap profiles or an
  external process memory sampler for peak-memory investigations.
- Repeated small `File.Write` calls still authenticate and encrypt on every
  edit, but reuse scratch buffers and the chunk's private staging slot.
  `staging-size-ratio` measures retained file length; `staging-write-ratio`
  estimates total bytes submitted to staging for this workload. Slot reuse
  reduces the first without reducing the second. Neither measures device I/O.
  `WriteFile` buffers small reader input into chunks; these APIs should not be
  assumed to have equal CPU cost.
- Chunk lookup uses direct arithmetic. Cached late reads should have similar
  cost to cached early reads; fresh handles still retain snapshot references.
- Commits serialize under the store mutex. Parallel write throughput need not
  scale with CPU count. `ns/op` includes failed conflicting attempts;
  `conflicts/op` must be considered when comparing throughput. Write/mixed cases
  deliberately omit MB/s rather than presenting failed writes as useful bytes.

## Measurement limits

Reads are warm OS-page-cache workloads, though streaming opens a fresh library
handle each iteration. The suite does not flush the host cache or simulate
power loss. Reported `ns/op` is average elapsed time per operation (aggregate
throughput for parallel cases), not p95/p99 request latency. Timing includes
normal API error checks and some in-loop read comparisons. Most content checks,
fixture generation, and final disk inventories are outside timing. Lifecycle
resets are untimed but still affect cache and disk state.

No universal pass/fail latency limit is imposed: sync latency, hardware, Go
version, filesystem, available space, and contention materially affect results.
Establish repeated baselines on the deployment hardware, then set workload-
specific budgets. A timing improvement that fails correctness checks is a
failure regardless of speed.

## Initial local results before optimization

Measured October 3, 2026 (Pacific time), Go 1.26.5, Intel i7-8650U,
Linux/ext4 on the local encrypted volume. These are exploratory results on a
shared development machine, not deployment guarantees. The complete 92-case
matrix passed at one iteration per case. Focused cases used three samples with
`-benchtime 100ms`; values below are medians of the one-CPU samples. Some slower
cases therefore have only one operation per sample.

| Workload | Median time | Observation |
| --- | ---: | --- |
| WriteFile, 1 MiB file / 1 MiB chunk | 14.62 ms | Approximately 72 MB/s, includes durable replacement. |
| WriteFile, 16 MiB file / 1 MiB chunks | 126.05 ms | Approximately 133 MB/s. |
| Native durable replacement, 1 MiB | 7.95 ms | Context for sync cost; fewer guarantees than the library. |
| 64-byte patch, one 1 MiB chunk | 13.58 ms | Exactly one chunk replaced. |
| 64-byte patch crossing two 1 MiB chunks | 23.07 ms | Exactly two chunks replaced. |
| Create 1 MiB through 4 KiB writes | 447.08 ms | 128.5× staging bytes, roughly 542 MB allocated per operation. |
| Create 1 MiB through 64 KiB writes | 47.20 ms | 8.5× staging bytes. |
| Create 1 MiB through one 1 MiB write | 14.02 ms | Approximately 1× staging bytes. |
| Small-file patch beside 1 / 16 / 64 MiB unrelated payload | 8.45 / 6.13 / 6.30 ms | No payload-proportional timing increase in these samples; allocation grows with metadata. |
| Cached first / last chunk read, 4,096 chunks | 0.803 / 10.418 µs | About 13× slower at the end despite cached plaintext; linear metadata scan. |
| Shared-store writes, 1 / 4 CPUs | 6.70 / 6.54 ms per attempt | Little throughput scaling; no conflicts observed in these samples. |

These measurements identified staging amplification and linear chunk lookup.
The subsequent implementation changes replace append-only staging edits with
reusable slots, reuse encryption buffers, and calculate chunk locations directly.
Chunk-local publication and cleanup checks passed. Full-manifest serialization
and immediate re-encryption remain costs to measure for the intended workload. This run does not establish peak-memory bounds
or tail-latency targets.

Local raw outputs are in `benchmark-results/local-baseline/` (ignored by Git):
`environment.txt`, `tests.txt`, `race.txt`, `smoke.txt`, `bench.txt`,
`stream-write.txt`, `unrelated-payload.txt`, `seek.txt`, and
`parallel-race.txt`. The parallel benchmark also passed 100 operations per case
under the race detector. Re-run on target hardware before
using these numbers as regression limits.

## Sparse allocation checks

```sh
BENCH='BenchmarkSparse' BENCHTIME=100ms COUNT=5 CPU=1,4 ./scripts/benchmark.sh
```

Sparse allocation should depend on the touched chunks, not the intervening gap.
A 64-byte write at any aligned offset stores 80 payload bytes including its tag;
metadata grows only slightly when the decimal offset or logical size gains digits.
Extending an empty file with Truncate stores no payload bytes. Physical filesystem
block allocation and directory overhead are not included in `stored-payload-B`.
Dense workloads remain in the suite to detect lookup, metadata, and commit
regressions. Sparse random allocation includes sorting at commit; lookup-only
measurements expose binary-search scaling separately from encryption and syncs.
