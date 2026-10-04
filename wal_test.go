package sandboxed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// Drop process state without checkpointing; the subprocess crash test separately
// verifies recovery after SIGKILL with both acknowledged and unfinished writes.
func abandonStore(t testing.TB, store *Store) {
	t.Helper()
	store.lock.Lock()
	if store.handles != 0 {
		t.Fatal("open handles in recovery fixture")
	}
	store.closed = true
	close(store.stop)
	store.lock.Unlock()
	store.workers.Wait()
	if err := errors.Join(store.wal.Close(), store.chunks.Close(), store.root.Close(), store.owner.Close()); err != nil {
		t.Fatal(err)
	}
}

func TestWALCommitsDeltasAndPromotesCiphertextWithoutCopy(t *testing.T) {
	store := testStore(t)
	initial := manifestBytes(t, store)
	file := createVirtual(t, store, "file")
	data := bytes.Repeat([]byte("payload marker must stay encrypted"), 20)
	writeAt(t, file, data, 0)
	staged, err := os.Stat(filepath.Join(store.Path(), file.staging[0]))
	if err != nil {
		t.Fatal(err)
	}
	part := file.item.Chunks[0]
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	published, err := os.Stat(chunkPath(store, part))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(staged, published) {
		t.Fatal("publication copied ciphertext")
	}
	if !bytes.Equal(initial, manifestBytes(t, store)) {
		t.Fatal("commit rewrote checkpoint")
	}
	update := openWritable(t, store, "file")
	writeAt(t, update, []byte("next"), 3*minimumChunkSize)
	if err := update.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("file"); err != nil {
		t.Fatal(err)
	}
	if err := store.Mkdir("directory"); err != nil {
		t.Fatal(err)
	}
	putFile(t, store, "directory/kept", data)
	abandonStore(t, store)
	recovered, err := openTestStore(t, store.Path())
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, recovered, "directory/kept", data)
	if _, err := recovered.Stat("file"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("recovered removed file", err)
	}
}

func TestConcurrentClosesShareDurableCommits(t *testing.T) {
	store := testStore(t)
	const count = 32
	files := make([]*File, count)
	for i := range count {
		file := createVirtual(t, store, string(rune('A'+i)))
		writeAt(t, file, []byte{byte(i)}, 1<<20)
		files[i] = file
	}
	start := make(chan struct{})
	failures := make(chan error, count)
	var workers sync.WaitGroup
	for _, file := range files {
		workers.Add(1)
		go func() { defer workers.Done(); <-start; failures <- file.Close() }()
	}
	close(start)
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if store.walGroups >= count {
		t.Fatalf("did not batch commits: %d", store.walGroups)
	}
	abandonStore(t, store)
	recovered, err := openTestStore(t, store.Path())
	if err != nil {
		t.Fatal(err)
	}
	for i := range count {
		reader, err := recovered.Open(string(rune('A' + i)))
		if err != nil {
			t.Fatal(err)
		}
		assertSparseWindow(t, reader.(*openFile), (1<<20)-1, (1<<20)+1, []sparsePatch{{1 << 20, []byte{byte(i)}}})
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWALRecoveryIgnoresIncompleteTailAndRejectsCorruption(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		options := []Option{}
		if encrypted {
			options = append(options, WithEncryption(bytes.Repeat([]byte{7}, 32)))
		}
		store := testStore(t, options...)
		putFile(t, store, "kept", []byte("durable"))
		wal, err := os.ReadFile(filepath.Join(store.Path(), "wal"))
		if err != nil {
			t.Fatal(err)
		}
		next := cloneManifest(store.manifest)
		next.Entries["unacknowledged"] = entry{Directory: true}
		record, err := store.encodeRecord(changesBetween(store.manifest, next, []string{"unacknowledged"}), store.manifest.Sequence+1)
		if err != nil {
			t.Fatal(err)
		}
		abandonStore(t, store)
		for _, length := range []int{0, 1, walHeaderSize - 1, walHeaderSize, len(record) - 1, len(record)} {
			if err := os.WriteFile(filepath.Join(store.Path(), "wal"), append(append([]byte(nil), wal...), record[:length]...), 0600); err != nil {
				t.Fatal(err)
			}
			recovered, err := OpenStore(store.Path(), options...)
			if err != nil {
				t.Fatalf("tail length %d: %v", length, err)
			}
			assertFile(t, recovered, "kept", []byte("durable"))
			_, err = recovered.Stat("unacknowledged")
			if (err == nil) != (length == len(record)) {
				t.Fatalf("partial record became visible: %d, %v", length, err)
			}
			abandonStore(t, recovered)
		}
		// A complete corrupted record is an error; recovery must not silently lose it.
		damaged := append([]byte(nil), wal...)
		damaged[walHeaderSize] ^= 1
		if err := os.WriteFile(filepath.Join(store.Path(), "wal"), damaged, 0600); err != nil {
			t.Fatal(err)
		}
		orphan := filepath.Join(store.Path(), "chunks", string(bytes.Repeat([]byte{'f'}, 64)))
		if err := os.WriteFile(orphan, []byte{0}, 0600); err != nil {
			t.Fatal(err)
		}
		if recovered, err := OpenStore(store.Path(), options...); err == nil {
			recovered.Close()
			t.Fatal("accepted corrupted WAL")
		}
		if _, err := os.Stat(orphan); err != nil {
			t.Fatal("cleanup ran before WAL validation")
		}
	}
}

func TestCheckpointCanRecoverWithRetainedWALPrefix(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("first"))
	store.lock.Lock()
	if err := store.checkpoint(store.manifest); err != nil {
		t.Fatal(err)
	}
	store.lock.Unlock()
	// Simulate a crash after durable checkpoint replacement but before log reset.
	putFile(t, store, "file", []byte("second"))
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	abandonStore(t, store)
	recovered, err := openTestStore(t, store.Path())
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, recovered, "file", []byte("second"))
	recovered.lock.Lock()
	if err := recovered.flushCheckpoint(); err != nil {
		t.Fatal(err)
	}
	if recovered.walSize != 0 {
		t.Fatal("checkpoint did not retire log")
	}
	recovered.lock.Unlock()
	putFile(t, recovered, "next", []byte("third"))
	abandonStore(t, recovered)
	final, err := openTestStore(t, store.Path())
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, final, "file", []byte("second"))
	assertFile(t, final, "next", []byte("third"))
}

func TestWALFailureStopsWritesAndPreservesRecoverablePayloads(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	putFile(t, store, "file", []byte("old"))
	store.lock.Lock()
	if err := store.wal.Close(); err != nil {
		t.Fatal(err)
	}
	store.wal, err = openInternal(store.root, "wal", unix.O_RDONLY, 0)
	store.lock.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile("file", bytes.NewReader([]byte("new"))); err == nil {
		t.Fatal("acknowledged failed WAL write")
	}
	assertFile(t, store, "file", []byte("old"))
	if err := store.WriteFile("another", bytes.NewReader([]byte("other"))); err == nil {
		t.Fatal("accepted write after WAL failure")
	}
	if err := store.Cleanup(context.Background()); err == nil {
		t.Fatal("cleaned uncertain payloads")
	}
	if err := store.Close(); err == nil {
		t.Fatal("hid WAL error on close")
	}
	recovered, err := openTestStore(t, store.Path())
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, recovered, "file", []byte("old"))
}

func TestCleanupPassIsBoundedAndProtectsLiveChunks(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "live", []byte("live"))
	store.lock.Lock()
	for range cleanupBatch + 3 {
		id, err := randomKey()
		if err != nil {
			t.Fatal(err)
		}
		part := chunk{ID: id}
		file, err := openInternal(store.chunks, chunkName(part), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		store.queueGarbage([32]byte(id), 0)
	}
	if err := store.collect(); err != nil {
		t.Fatal(err)
	}
	if len(store.garbage) != 3 {
		t.Fatalf("unbounded cleanup: %d remaining", len(store.garbage))
	}
	store.lock.Unlock()
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "live", []byte("live"))
}

func TestPayloadNeverReachesDiskUnencryptedWithWAL(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		options := []Option{}
		if encrypted {
			options = append(options, WithEncryption(bytes.Repeat([]byte{9}, 32)))
		}
		store := testStore(t, options...)
		secret := bytes.Repeat([]byte("unique binary payload\x00\xff\x80"), 100)
		file := createVirtual(t, store, "secret-path")
		writeAt(t, file, secret, 7)
		check := func() {
			t.Helper()
			store.lock.Lock()
			defer store.lock.Unlock()
			err := filepath.WalkDir(store.Path(), func(name string, item fs.DirEntry, err error) error {
				if err != nil || item.IsDir() {
					return err
				}
				raw, err := os.ReadFile(name)
				if err != nil {
					return err
				}
				if bytes.Contains(raw, secret[:64]) {
					t.Fatalf("plaintext payload in %s", name)
				}
				if encrypted && bytes.Contains(raw, []byte("secret-path")) {
					t.Fatalf("plaintext path in %s", name)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		check()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		check()
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		check()
	}
}

func TestWALRejectsMissingLogAndInvalidSequence(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("durable"))
	abandonStore(t, store)
	name := filepath.Join(store.Path(), "wal")
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(data[12:20], 9)
	digest := sha256.Sum256(data[:len(data)-sha256.Size])
	copy(data[len(data)-sha256.Size:], digest[:])
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenStore(store.Path()); err == nil {
		reopened.Close()
		t.Fatal("accepted missing sequence")
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenStore(store.Path()); err == nil {
		reopened.Close()
		t.Fatal("accepted missing WAL")
	}
}

type failingJournal struct {
	journalFile
	partial bool
	syncErr bool
	entered chan struct{}
	proceed chan struct{}
}

func (f *failingJournal) WriteAt(data []byte, offset int64) (int, error) {
	if f.partial {
		n, err := f.journalFile.WriteAt(data[:len(data)/2], offset)
		if err != nil {
			return n, err
		}
		return n, errors.New("injected partial append")
	}
	return f.journalFile.WriteAt(data, offset)
}
func (f *failingJournal) Sync() error {
	if f.entered != nil {
		close(f.entered)
		<-f.proceed
	}
	if f.syncErr {
		return errors.New("injected sync failure")
	}
	return f.journalFile.Sync()
}

func TestPartialAppendAndUncertainSyncNeverAcknowledgeOrDeletePayloads(t *testing.T) {
	for _, partial := range []bool{false, true} {
		store, err := OpenStore(filepath.Join(t.TempDir(), "store"))
		if err != nil {
			t.Fatal(err)
		}
		putFile(t, store, "file", []byte("old"))
		store.lock.Lock()
		store.wal = &failingJournal{journalFile: store.wal, partial: partial, syncErr: !partial}
		store.lock.Unlock()
		if err := store.WriteFile("file", bytes.NewReader([]byte("new"))); err == nil {
			t.Fatal("acknowledged incomplete durability")
		}
		assertFile(t, store, "file", []byte("old"))
		if err := store.Close(); err == nil {
			t.Fatal("hid failed journal")
		}
		recovered, err := openTestStore(t, store.Path())
		if err != nil {
			t.Fatal(err)
		}
		// A complete but unacknowledged frame may survive an uncertain sync.
		want := "new"
		if partial {
			want = "old"
		}
		assertFile(t, recovered, "file", []byte(want))
		putFile(t, recovered, "another", []byte("recovered"))
	}
}

func TestCloseWaitsForDurabilityAndPreservesExistingReaders(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("old"))
	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	writer := createVirtual(t, store, "file")
	writeAt(t, writer, []byte("new"), 0)
	entered, proceed := make(chan struct{}), make(chan struct{})
	store.lock.Lock()
	original := store.wal
	store.wal = &failingJournal{journalFile: original, entered: entered, proceed: proceed}
	store.lock.Unlock()
	done := make(chan error, 1)
	go func() { done <- writer.Close() }()
	<-entered
	select {
	case err := <-done:
		t.Fatalf("Close returned before sync: %v", err)
	default:
	}
	data := make([]byte, 3)
	if _, err := reader.Read(data); err != nil || string(data) != "old" {
		t.Fatalf("old snapshot: %q %v", data, err)
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	store.lock.Lock()
	store.wal = original
	store.lock.Unlock()
	assertFile(t, store, "file", []byte("new"))
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWALAutomaticallyCheckpointsAtBoundedSize(t *testing.T) {
	store := testStore(t)
	// Large virtual names exercise real byte thresholds without huge payloads.
	name := string(bytes.Repeat([]byte{'x'}, 1<<20))
	for range 10 {
		putFile(t, store, name, nil)
	}
	if store.checkpointCount == 0 {
		t.Fatal("WAL never checkpointed")
	}
	if store.walSize > checkpointBytes+2<<20 {
		t.Fatal("unbounded WAL growth")
	}
	abandonStore(t, store)
	recovered, err := openTestStore(t, store.Path())
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, recovered, name, nil)
}

func TestCleanupBackpressureStopsNewCommitsOnDeletionFailure(t *testing.T) {
	store := testStore(t)
	putFile(t, store, "file", []byte("old"))
	id, err := randomKey()
	if err != nil {
		t.Fatal(err)
	}
	name := chunkPath(store, chunk{ID: id})
	store.lock.Lock()
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	store.queueGarbage([32]byte(id), 64<<20)
	before := store.manifest.Sequence
	store.lock.Unlock()
	if err := store.WriteFile("file", bytes.NewReader([]byte("new"))); err == nil {
		t.Fatal("ignored cleanup backpressure")
	}
	if store.manifest.Sequence != before {
		t.Fatal("committed despite failed cleanup pressure")
	}
	assertFile(t, store, "file", []byte("old"))
	store.lock.Lock()
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	store.lock.Unlock()
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	putFile(t, store, "file", []byte("recovered"))
	assertFile(t, store, "file", []byte("recovered"))
}

func TestRecoverInterruptedEmptyInitialization(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "wal"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := openTestStore(t, directory)
	if err != nil {
		t.Fatal(err)
	}
	putFile(t, store, "file", []byte("after initialization"))
	assertFile(t, store, "file", []byte("after initialization"))
}

func TestReadOnlyStoreCloseDoesNotRewriteCheckpoint(t *testing.T) {
	store := testStore(t, WithEncryption(bytes.Repeat([]byte{6}, 32)))
	putFile(t, store, "file", []byte("committed"))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before := manifestBytes(t, store)
	reopened, err := openTestStore(t, store.Path(), WithEncryption(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, reopened, "file", []byte("committed"))
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, manifestBytes(t, reopened)) {
		t.Fatal("read-only close rewrote checkpoint")
	}
}
