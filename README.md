# sandboxed

<p align="center">
  <img src="imgs/sandboxed.png" width="420">
</p>

`sandboxed` is a Go module that presents sandboxed file storage for untrusted binary data as an `io/fs`. All data is stored in a single opaque file; all original payload bytes are chunked and encrypted such that no harmful payload is ever written to disk. Virtual paths are never joined to host paths. Stored content is never executed and does not expose executable mode bits, symlinks, device files, or host filesystem handles.

Implementing applications must preserve that boundary when copying data elsewhere.

## Platform support

`sandboxed` currently supports Linux, macOS, and other POSIX-style systems.
Its virtual paths always use platform-independent `io/fs` naming conventions.

Native Windows storage is not currently supported but could work. Windows file-sharing and replacement semantics differ when the backing blob has open readers, so mutating an existing store may return a sharing or rename error. The module returns that error rather than intentionally publishing a partial replacement, but atomic replacement and crash-recovery guarantees have not been verified on Windows. Use WSL when running on a Windows host.

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

Without a store key, paths and file metadata remain readable in the blob while
payloads remain encrypted. Pass a 32-byte key to encrypt the manifest too:

```go
store, err := sandboxed.OpenStore("private.dat",
	sandboxed.WithEncryption(key),
)
```

## Storage behavior

- Each file receives an independent random 256-bit AES key.
- Every blob begins with a 16-byte structured identifier: the 9-byte
  `SANDBOXED` signature, a 2-byte configuration bitfield, 3 reserved bytes,
  and a 2-byte format version. Encrypted manifests authenticate this complete
  identifier as associated data.
- Payloads are split into configurable 4 KB - 64 MB chunks.
- Each chunk uses AES-256-GCM. Its file key, chunk position, and plaintext size
  determine or authenticate its cryptographic context.
- Mutations build and sync a replacement blob, then atomically rename it over
  the old blob. Open readers continue using their already-open snapshot.
- A stable `*.lock` coordination file serializes metadata operations across
  goroutines, independently opened `Store` values, and cooperating processes.
  Locks are released after an immutable read snapshot is opened and after each
  mutation commits; an open content stream does not retain the lock.
- Reads decrypt at most one configured chunk at a time. Writes retain at most
  one plaintext chunk before encrypting it into a temporary staging file.
- The backing blob and temporary replacement default to mode `0600`. Use
  `WithFileMode` when the deployment needs different permission bits.
