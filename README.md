# sandboxed

<p align="center">
  <img src="imgs/sandboxed.png" width="420">
</p>

`sandboxed` is a Go filesystem for storing untrusted data as encrypted chunks. Each store owns a private directory containing a manifest and randomly named chunk files. Only paths recorded in the manifest exist in the virtual filesystem; callers cannot use it to access the manifest, lock, chunk files, or other host files.

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

Changes become visible when `Close` commits them; always check its error. `Abort` discards changes and is safe to defer. Reads on the same writable handle see its staged changes. If another writer changes that file before it commits, `Close` returns `ErrConflict`; reopen the file to retry. `WriteFile` follows the same rule.

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

A fully written 5 MB file with 1 MB chunks (assuming default settings) creates 5 encrypted chunk files. Changing part of a file that affects only a single chunk encrypts and writes that whole chunk under a fresh random name. Unchanged chunks remain untouched. A commit syncs its new chunks, then atomically replaces the private manifest. It never copies unrelated payloads, though it still writes a full manifest.

Sparse manifests record only allocated chunks and their logical positions. Gap length does not increase the number of chunk records. A short stored chunk may be followed by implicit zeros; a write inside a chunk can still encrypt leading zeros within that chunk. Explicitly writing zero bytes allocates chunks normally. Every write encrypts its affected payload immediately, and several writes on one handle share a single manifest publication at `Close`.

A missing or damaged ciphertext file referenced by the manifest is an error, never a hole. Snapshots and cleanup track allocated chunks only. Random sparse inserts use a private index; committed records are sorted, with direct lookup for dense prefixes and binary search for sparse positions.

Open readers hold in-memory references to their snapshot's chunks. Writers also retain their source snapshot and keep encrypted staging files private until commit. Replacing or removing a file cannot invalidate those handles. A chunk is deleted only when neither the current manifest nor any open handle references it. Shared chunks survive until every reference is released.

Cleanup runs on commits and handle closes, without a background daemon. `store.Cleanup(ctx)` retries any outstanding chunk deletions. At startup, the store validates its manifest and live chunks before removing orphan chunks and abandoned temporary files. There is no whole-store compaction step.

Close or abort every file handle. `Store.Close()` returns `ErrBusy` while handles remain open; release them and retry. Closing an already closed store is safe. Cleanup and final sync errors are returned to the caller; a commit error after manifest replacement may mean the change was published, so inspect the current file before retrying.

## Store ownership

One `Store` instance in one process owns a directory. Share it between goroutines. A second opener receives `ErrBusy` until the owner closes. Cross-process access is not supported; in-memory references are intentionally not shared between processes.

Ownership uses an OS-managed advisory lock held for the store's lifetime. The OS releases it automatically when the process exits or crashes, including `SIGKILL`. The `lock` file may remain on disk, but its existence does not indicate ownership. A live but paused process keeps ownership; terminate it before handing the store to another process. Do not delete the lock file or modify internal files while a store is owned.

## Encryption and isolation

Payloads and staging files contain ciphertext only. Each file has a random 256-bit key, and each newly encrypted chunk has a random 256-bit identity. HMAC-SHA256 derives a separate AES-256-GCM key for that chunk; its position and plaintext size are authenticated. The chunk identity also supplies its opaque filename, without revealing a hash of the plaintext.

Without a store key, the manifest contains readable virtual paths, metadata, and file keys. Pass a 32-byte key to hide them too:

```go
store, err := sandboxed.OpenStore("private", sandboxed.WithEncryption(key))
```

The private directory layout looks like this:

```text
uploads/
  manifest
  lock
  chunks/
    <random 64-character hex ID>
    <random 64-character hex ID>
```

Internal file access is relative to pinned directory descriptors and rejects symlinks and nonregular chunk files. Virtual paths are never used as host paths. The manifest has a bounded length and checksum; encrypted manifests are also authenticated. The host can still observe chunk counts and sizes. This is not protection against an administrator controlling the process or rolling the store back, and applications must preserve the boundary when exporting plaintext.

Directories default to mode `0700`; manifests, chunks, and temporary files default to `0600`. `WithFileMode` changes permissions on data files, while the directories and ownership lock remain private. `WithChunkSize` configures new stores from 4 KB to 64 MB. Reads and writes use bounded chunk buffers; metadata memory scales with entries and chunks. Encoded manifests are limited to 64 MB. Logical file size is limited to 524,288 chunk positions (32 GiB with 64 KiB chunks, or 512 GiB with the default 1 MiB chunks). Sparse gaps consume no payload chunks; metadata memory scales with allocated chunks, and each changed commit still writes the full manifest.

## Benchmarks

Run `./scripts/benchmark.sh` for correctness checks, race detection, and repeated
performance measurements. See [BENCHMARKS.md](BENCHMARKS.md) for the workload
matrix, focused runs, native-file baselines, and interpretation of results.
