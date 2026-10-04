package sandboxed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCrashOwnerHelper(t *testing.T) {
	directory := os.Getenv("SANDBOXED_CRASH_STORE")
	if directory == "" {
		t.Skip("subprocess helper")
	}
	store, err := OpenStore(directory, WithChunkSize(minimumChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	putFile(t, store, "file", []byte("old"))
	// Keep the old version pinned and leave an unfinished encrypted staging file.
	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	putFile(t, store, "file", []byte("new"))
	writer, err := store.Create("unfinished")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("staged")); err != nil {
		t.Fatal(err)
	}
	// Persist a sparse layout, then leave a conflicting staged layout behind.
	sparse, err := store.Create("sparse")
	if err != nil {
		t.Fatal(err)
	}
	writeAt(t, sparse, []byte("committed"), 1<<30)
	if err := sparse.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := store.Update("sparse")
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	writeAt(t, pending, []byte("unfinished"), 1<<19)
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestProcessCrashReleasesOwnershipAndRecoversOrphans(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "store")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashOwnerHelper$")
	command.Env = append(os.Environ(), "SANDBOXED_CRASH_STORE="+directory)
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err == nil && line != "ready\n" {
			err = fmt.Errorf("unexpected helper output: %q", line)
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			command.Process.Kill()
			command.Wait()
			t.Fatal(err)
		}
	case <-ctx.Done():
		command.Wait()
		t.Fatal(ctx.Err())
	}
	if store, err := OpenStore(directory); !errors.Is(err, ErrBusy) {
		if store != nil {
			store.Close()
		}
		t.Fatalf("second process acquired ownership: %v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("helper was not killed")
	}
	// The lock file is still present. Ownership is released by the kernel, not
	// by deleting that file or waiting for its timestamp to expire.
	if _, err := os.Stat(filepath.Join(directory, "lock")); err != nil {
		t.Fatal(err)
	}
	store, err := openTestStore(t, directory)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, store, "file", []byte("new"))
	if len(chunkFiles(t, store)) != 2 {
		t.Fatal("crashed reader's old chunks survived startup")
	}
	if _, err := store.Stat("unfinished"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("abandoned writer was published", err)
	}
	sparse, err := store.Open("sparse")
	if err != nil {
		t.Fatal(err)
	}
	defer sparse.Close()
	info, err := sparse.Stat()
	if err != nil || info.Size() != 1<<30+9 {
		t.Fatal("uncommitted sparse size survived crash", info, err)
	}
	assertSparseWindow(t, sparse.(io.ReadSeeker), 1<<30-2, info.Size(), []sparsePatch{{1 << 30, []byte("committed")}})
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("abandoned staging survived: %v", entries)
	}
}
