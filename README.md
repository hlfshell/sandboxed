# sandboxed

<p align="center">
  <img src="imgs/sandboxed.png" width="420">
</p>

`sandboxed` is a Go filesystem for storing untrusted data as encrypted chunks. Each store owns a private directory containing a checkpoint manifest, a write-ahead log (WAL), and randomly named chunk files. Only committed virtual paths exist in the virtual filesystem; callers cannot use it to access the manifest, lock, chunk files, or other host files.

```go
store, err := sandboxed.OpenStore("uploads", sandboxed.WithChunkSize(1024*1024))
if err != nil {
    return err
}
defer store.Close()

if err := store.WriteFile("photo.jpg", upload); err != nil {
    return err
}

file, err := store.Open("photo.jpg")
if err != nil {
    return err
}
defer file.Close()

_, err = io.Copy(destination, file)
```

## Reading and writing

All files exist within a virtual file system - you can only reference or affect files within the store's virtual file system.

- `Open(name)` reads an existing file or directory.
- `Create(name)` creates or replaces a file.
- `Update(name)` modifies an existing file without clearing it.
- `WriteFile(name, reader)` streams a complete replacement.

`Create` and `Update` return the same file handle, supporting `Read`, `Write`, `Seek`, `ReadAt`, `WriteAt`, and `Truncate`. Chunk encryption is automatic. To append, seek to the end before writing.

```go
file, err := store.Update("photo.jpg")
if err != nil {
    return err
}
defer file.Abort()

if _, err := file.Seek(offset, io.SeekStart); err != nil {
    return err
}
if _, err := file.Write(patch); err != nil {
    return err
}
return file.Close()
```

Changes become visible when `Close` durably commits them; always check its error. A successful `Write` or `WriteAt` encrypts and stages data but does not commit it. `Abort` discards changes and is safe to defer. Reads on the same writable handle see its staged changes. If another writer changes that file before it commits, `Close` returns `ErrConflict`; reopen the file to retry. `WriteFile` follows the same rule.

Files support sparse allocation automatically. Seeking beyond EOF does not change the size. Writing there, or extending with `Truncate`, creates a logical zero-filled gap without storing encrypted chunks for the gap:

```go
file, err := store.Create("sparse.bin")
if err != nil {
    return err
}
defer file.Abort()

// Encrypt and stage only the chunk containing this payload.
if _, err := file.WriteAt([]byte("tail"), 1<<30); err != nil {
    return err
}

// Extend the logical size to 2 GiB without allocating more payload.
if err := file.Truncate(2 << 30); err != nil {
    return err
}
return file.Close()
```

`Stat` reports logical size, including holes. Reads return zeros for holes and EOF at the logical end. `ReadAt` on a writable handle sees its staged layout; other readers see it after `Close`, while already-open readers keep their original snapshot. Shrinking and then extending a file never restores discarded data. `ReadFile`, `io.ReadAll`, and copying a file include its logical zero-filled contents, so their output size still includes the holes.

`Store` implements `fs.FS`, `fs.ReadFileFS`, `fs.ReadDirFS`, and `fs.StatFS`. Standard helpers such as `io.Copy`, `io.ReadAll`, and `fs.WalkDir` work normally. Virtual permissions are fixed and non-executable, and host filesystem handles are never exposed.

## Chunk storage and cleanup

A fully written 5 MB file with 1 MB chunks (assuming default settings) creates 5 encrypted chunk files. Changing part of a file that affects only a single chunk encrypts and writes that whole chunk under a fresh random name. Unchanged chunks remain untouched. Each dirty chunk uses a reusable private ciphertext file. Publication links that same inode under its immutable chunk identity and removes the private name, without copying ciphertext. Up to four workers sync and publish independent dirty chunks; a commit syncs their directory, then appends and syncs a WAL record containing only changed metadata and chunk references. Full manifests are written at checkpoints, rather than on each file commit.

Sparse manifests record only allocated chunks and their logical positions. Gap length does not increase the number of chunk records. A short stored chunk may be followed by implicit zeros; a write inside a chunk can still encrypt leading zeros within that chunk. Explicitly writing zero bytes allocates chunks normally. Every write encrypts its affected payload immediately, and several writes on one handle share a single commit at `Close`.

A missing or damaged ciphertext file referenced by the manifest is an error, never a hole. Snapshots and cleanup track allocated chunks only. Random sparse inserts use a private index; committed records are sorted, with direct lookup for dense prefixes and binary search for sparse positions.

Open readers hold in-memory references to their snapshot's chunks. Writers also retain their source snapshot and keep encrypted staging files private until commit. Replacing or removing a file cannot invalidate those handles. A chunk is deleted only when neither the current manifest nor any open handle references it. Shared chunks survive until every reference is released.

A background worker defers cleanup for about 20 ms and attempts at most 64 obsolete chunk deletions per pass. New commit groups apply backpressure when reclaimable garbage reaches 1,024 chunks or 64 MiB; one transaction may exceed those thresholds, and the next group waits for cleanup. These limits exclude live data, staged transactions, and reader-pinned snapshots. `store.Cleanup(ctx)` drains outstanding deletions in bounded passes, checking cancellation between passes and reporting errors. At startup, the store replays the WAL and validates the recovered layout and live chunk lengths before any orphan cleanup. Cleanup does not require copying live chunks.

Close or abort every file handle. `Store.Close()` returns `ErrBusy` while handles remain open; release them and retry. Closing an already closed store is safe. Store close checkpoints committed metadata and drains cleanup before releasing ownership. A WAL append or sync error leaves the commit outcome uncertain and stops further commits and deletions until the store is closed and reopened. Recovery may include a complete unacknowledged record; callers should inspect the recovered file before retrying. Background deletion errors are retried and can be observed through `Cleanup`, cleanup backpressure, or store close.

## Durable commits and recovery

`Close` is the commit boundary. When multiple writers are open, concurrent file closes wait up to 1 ms to form a group of at most 64 transactions. The submission queue holds at most 64 requests; additional callers wait. Groups target at most 4 MiB of encoded metadata deltas; a larger individual transaction runs alone, subject to the 64 MiB record limit. Payload buffers belong to each open writer and are not accumulated in the commit queue. The collection window is not an end-to-end latency guarantee: I/O, checkpointing, and cleanup backpressure can take longer.

A successful close means the encrypted payload, chunk-directory entries, and WAL record have all passed their required filesystem syncs. Only then does the in-memory view advance and waiting closes return. Reads on a writer see its staged changes. Existing readers retain their snapshot; new readers see the committed state. Conflicting writers still return `ErrConflict`. Batching shares durability work across independent transactions; it does not add a caller-controlled multi-file transaction API. Directory changes also use the WAL, without the file-close collection delay.

Before a commit appends to a WAL that has reached 8 MiB, the store writes and syncs a checkpoint, atomically replaces the manifest, syncs its directory, and only then truncates and syncs the WAL. Recovery accepts retained log records covered by a checkpoint, replays subsequent records in sequence, and discards an incomplete trailing record. A complete record with a bad checksum, failed authentication, invalid sequence, or invalid metadata causes recovery to fail before cleanup. Referenced payloads are length-checked during recovery and authenticated on access.

Acknowledged commits survive process crashes when the filesystem and storage honor successful sync operations. Writes on a handle that never successfully closes are not promised durable. A crash during close can leave the transaction either committed or absent. Media corruption is reported, not silently treated as an absent transaction. Long-lived snapshots can retain obsolete payload indefinitely until their handles close.

## Store ownership

One `Store` instance in one process owns a directory. Share it between goroutines. A second opener receives `ErrBusy` until the owner closes. Cross-process access is not supported; in-memory references are intentionally not shared between processes.

Ownership uses an OS-managed advisory lock held for the store's lifetime. The OS releases it automatically when the process exits or crashes, including `SIGKILL`. The `lock` file may remain on disk, but its existence does not indicate ownership. A live but paused process keeps ownership; terminate it before handing the store to another process. Do not delete the lock file or modify internal files while a store is owned.

## Encryption and isolation

Payloads and staging files contain ciphertext only. Each file has a random 256-bit key, and each newly encrypted chunk has a random 256-bit identity. HMAC-SHA256 derives a separate AES-256-GCM key for that chunk; its position and plaintext size are authenticated. The chunk identity also supplies its opaque filename, without revealing a hash of the plaintext.

Without a store key, the manifest and WAL contain readable virtual paths, metadata, and file keys. Neither contains plaintext file payloads. Pass a 32-byte key to hide them too:

```go
store, err := sandboxed.OpenStore("private", sandboxed.WithEncryption(key))
```

The private directory layout looks like this:

```text
uploads/
  manifest
  wal
  lock
  chunks/
    <random 64-character hex ID>
    <random 64-character hex ID>
```

Internal file access is relative to pinned directory descriptors and rejects symlinks and nonregular chunk files. Virtual paths are never used as host paths. The manifest and WAL records have bounded lengths and checksums; with `WithEncryption`, both metadata formats are also encrypted and authenticated. The host can still observe chunk counts and sizes. This is not protection against an administrator controlling the process or rolling the store back, and applications must preserve the boundary when exporting plaintext.

Directories default to mode `0700`; manifests, WAL files, chunks, and temporary files default to `0600`. `WithFileMode` changes permissions on data files, while the directories and ownership lock remain private. `WithChunkSize` configures new stores from 4 KB to 64 MB. Reads and writes use bounded chunk buffers; metadata memory scales with entries and chunks. Encoded manifests are limited to 64 MB. Logical file size is limited to 524,288 chunk positions (32 GiB with 64 KiB chunks, or 512 GiB with the default 1 MiB chunks). Sparse gaps consume no payload chunks; metadata memory scales with allocated chunks, and checkpoints serialize the full manifest. Normal commits encode only changed metadata and chunk references; they still copy and validate in-memory metadata, and partial writes still authenticate and encrypt the affected chunk.

## Benchmarks

Run `./scripts/benchmark.sh` for correctness checks, race detection, and repeated
performance measurements. See [BENCHMARKS.md](BENCHMARKS.md) for the workload
matrix, focused runs, native-file baselines, and interpretation of results.
