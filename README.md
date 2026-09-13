# sandboxed

<p align="center">
  <img src="imgs/sandboxed.png" width="420">
</p>

`sandboxed` is a Go module that presents sandboxed file storage for untrusted binary data as an `io/fs`. All data is stored in a single opaque file; all original payload bytes are chunked and encrypted before being written to disk. Virtual paths are never joined to host paths. Stored content is never executed and does not expose executable mode bits, symlinks, device files, or host filesystem handles.

Implementing applications must preserve that boundary when copying data elsewhere.

## Safety Warning

The purpose of this library is to provide some level of sandbox isolation, but is no way a guarentee of safety. Consider your applications **carefully**.


## Platform support

`sandboxed` currently supports Linux, macOS, and other POSIX-style systems. Its virtual paths always use platform-independent `io/fs` naming conventions.

Native Windows storage is not currently supported. Windows file-sharing and replacement semantics differ when the backing blob has open readers, so compaction may return a sharing or rename error. Commit durability and crash recovery have not been verified on Windows. Use WSL when running on a Windows host.

## Usage

```go
store, err := sandboxed.OpenStore("store.sandboxed",
	sandboxed.WithChunkSize(1024 * 1024), // Encrypt files in 1 MiB chunks
	sandboxed.WithFileMode(0640),         // Optional; defaults to 0600
)
if err != nil {
	return err
}

if err := store.MkdirAll("incoming/images"); err != nil {
	return err
}
if err := store.WriteFile("incoming/images/photo.jpg", upload); err != nil {
	return err
}

file, err := store.Open("incoming/images/photo.jpg")
if err != nil {
	return err
}
defer file.Close()

_, err = io.Copy(destination, file)
```

`Store` implements `fs.FS`, `fs.ReadFileFS`, `fs.ReadDirFS`, and `fs.StatFS`.

## Manifest encryption

Without a store key, paths and file metadata remain readable in the blob while payloads remain encrypted. Pass a 32-byte key to encrypt the manifest too:

```go
store, err := sandboxed.OpenStore("private.dat",
	sandboxed.WithEncryption(key),
)
```

## Reading and writing files

Choose the operation by what you want to do:

- `Open(name)` reads an existing file or directory.
- `Create(name)` creates or replaces a file.
- `Update(name)` opens an existing file for changes without clearing it.
- `WriteFile(name, reader)` streams a complete replacement from a reader.

`Create` and `Update` return the same file handle, supporting `Read`, `Write`, `Seek`, `ReadAt`, `WriteAt`, and `Truncate`. Chunk encryption is automatic. To append, seek to the end before writing.

```go
file, err := store.Update("incoming/images/photo.jpg")
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

Changes become visible when `Close` succeeds; always check its error. `Abort` discards changes and is safe to defer. Reads on the same writable handle see its changes, while other readers retain their snapshots. All writes use the same conflict rule: if another writer changes the same file before you commit, the commit returns `ErrConflict`. Reopen the file to retry.

Updating a file writes only the affected chunks and a new manifest. Replacing a file writes its new contents and a new manifest. Neither operation copies unrelated files. The existing `io/fs` interfaces remain supported, and the writable handle works with standard helpers such as `io.Copy`.

## Storage behavior

- Each file receives an independent random 256-bit AES key.
- Every blob begins with a 16-byte structured identifier: the 9-byte `SANDBOXED` signature, a 2-byte configuration bitfield, 3 reserved bytes, and a 2-byte format version. Encrypted manifests authenticate this complete identifier as associated data.
- Payloads are split into configurable 4 KB - 64 MB chunks.
- Each new chunk encryption receives a random 256-bit identity. HMAC-SHA256 derives its AES-256-GCM key from the file key and that identity; its chunk position and plaintext size are authenticated. Repeated edits use fresh identities, including edits that are aborted.
- Mutations append changed ciphertext and a complete manifest to the same blob. Unchanged ciphertext stays at its existing offsets. Metadata-only operations append a manifest without copying payloads.
- Payloads and metadata are synced before publishing one of two alternating, checksummed commit records, stored in separate 4 KiB regions. The commit record is then synced. Recovery selects the newest complete record and ignores an uncommitted tail. A damaged committed manifest fails to open.
- As with other durable file operations, a final sync error can leave the commit outcome uncertain. Reopen the virtual file to inspect its current state.
- A stable `*.lock` coordination file serializes metadata operations across goroutines, independently opened `Store` values, and cooperating processes. Locks are released after an immutable read snapshot is opened and after each mutation commits; an open content stream does not retain the lock.
- Reads decrypt at most one configured chunk at a time. Writes use a bounded number of chunk buffers and stage only ciphertext. Metadata memory scales with the number of entries and chunks; encoded manifests are limited to 64 MiB.
- The backing blob and temporary replacement default to mode `0600`. Use `WithFileMode` when the deployment needs different permission bits.

## Chunk updates and compaction

Changing even part of a chunk produces new ciphertext for that chunk, so the whole affected chunk must be encrypted and written again. Unchanged chunks stay where they are; updating a file does not rewrite the entire file or store. Each commit also writes the full manifest describing where the current chunks live.

New chunks are appended so existing readers can finish reading the old copies. Call `store.Compact(ctx)` when you want to reclaim space: it copies the live chunks into a replacement store and removes the unused copies. Compaction needs temporary space for that replacement and blocks other commits while it runs; existing readers can continue.
