package instancelock

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
)

const (
	helperEnv = "INSTANCELOCK_TEST_HELPER"
	pathEnv   = "INSTANCELOCK_TEST_PATH"
)

// TestMain doubles as the second process: holding a lock across processes is
// the whole point, and a lock in this process would prove less.
func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "hold":
		hold(false)
	case "hold-with-child":
		hold(true)
	case "outlive":
		// Tied to nothing of its parent's, so it's still running after the
		// parent dies. The test kills it; the sleep only bounds a leak.
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

func hold(withChild bool) {
	lock, err := Acquire(os.Getenv(pathEnv), 0)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	defer lock.Release()
	if withChild {
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), helperEnv+"=outlive")
		if err := child.Start(); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		fmt.Println("child", child.Process.Pid)
	}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

type helper struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	childPID int
	killOnce sync.Once
}

func startHelper(t *testing.T, mode, path string) *helper {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+mode, pathEnv+"="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &helper{cmd: cmd, stdin: stdin}
	t.Cleanup(h.kill)
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "ready" {
			return h
		}
		if pid, ok := strings.CutPrefix(line, "child "); ok {
			if h.childPID, err = strconv.Atoi(pid); err != nil {
				t.Fatal(err)
			}
			continue
		}
		t.Fatalf("helper said %q", line)
	}
	t.Fatalf("helper ended without getting ready: %v", scanner.Err())
	return nil
}

func (h *helper) kill() {
	h.killOnce.Do(func() {
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	})
}

func lockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "daemon.lock")
}

func TestAcquireIsRefusedWhileAnotherProcessHoldsIt(t *testing.T) {
	path := lockPath(t)
	holder := startHelper(t, "hold", path)

	lock, err := Acquire(path, 0)
	if err == nil {
		lock.Release()
		t.Fatal("second process got the lock")
	}
	var held *HeldError
	if !errors.As(err, &held) {
		t.Fatalf("err = %v, want HeldError", err)
	}
	if held.PID != holder.cmd.Process.Pid {
		t.Errorf("PID = %d, want the holder's %d", held.PID, holder.cmd.Process.Pid)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(holder.cmd.Process.Pid)) {
		t.Errorf("the message doesn't name the holder: %v", err)
	}
}

func TestAKilledHolderFreesTheLock(t *testing.T) {
	path := lockPath(t)
	holder := startHelper(t, "hold", path)
	holder.kill()

	lock, err := Acquire(path, 5*time.Second)
	if err != nil {
		t.Fatalf("lock of a killed process stayed held: %v", err)
	}
	lock.Release()
}

// A child that kept the lock alive would stop every later daemon, for as long
// as whatever the daemon started keeps running.
func TestAChildDoesNotKeepTheLockAlive(t *testing.T) {
	path := lockPath(t)
	holder := startHelper(t, "hold-with-child", path)
	if holder.childPID == 0 {
		t.Fatal("helper started no child")
	}
	t.Cleanup(func() {
		if child, err := os.FindProcess(holder.childPID); err == nil {
			_ = child.Kill()
		}
	})
	holder.kill()

	lock, err := Acquire(path, 5*time.Second)
	if err != nil {
		t.Fatalf("the child kept the lock: %v", err)
	}
	lock.Release()
}

func TestAcquireWaitsForAHolderThatIsLeaving(t *testing.T) {
	path := lockPath(t)
	holder := startHelper(t, "hold", path)
	time.AfterFunc(200*time.Millisecond, holder.kill)

	lock, err := Acquire(path, 20*time.Second)
	if err != nil {
		t.Fatalf("the wait didn't get the lock: %v", err)
	}
	lock.Release()
}

func TestAcquireGivesUpAfterItsWait(t *testing.T) {
	path := lockPath(t)
	startHelper(t, "hold", path)

	const wait = 300 * time.Millisecond
	started := time.Now()
	_, err := Acquire(path, wait)
	var held *HeldError
	if !errors.As(err, &held) {
		t.Fatalf("err = %v, want HeldError", err)
	}
	if elapsed := time.Since(started); elapsed < wait {
		t.Errorf("gave up after %v, before its wait of %v", elapsed, wait)
	}
}

func TestReleaseFreesTheLockAndKeepsTheFile(t *testing.T) {
	path := lockPath(t)
	first, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Acquire(path, 0); err == nil {
		second.Release()
		t.Fatal("a second open in this process got the lock")
	}
	first.Release()
	first.Release() // Harmless a second time.
	// Removing the file on release would let two processes hold "the" lock on
	// two different files.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the lock file went away: %v", err)
	}
	second, err := Acquire(path, 0)
	if err != nil {
		t.Fatalf("after a release: %v", err)
	}
	second.Release()
}

func TestAcquireWritesItsOwnPID(t *testing.T) {
	path := lockPath(t)
	lock, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	// The holder's PID has to stay readable while the lock is held, including
	// on Windows, where a locked range can't be read.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != strconv.Itoa(os.Getpid()) {
		t.Errorf("file holds %q, want %d", got, os.Getpid())
	}
}

func TestAcquireOverwritesALongerPID(t *testing.T) {
	path := lockPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("99999999999999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != strconv.Itoa(os.Getpid()) {
		t.Errorf("file holds %q, want %d", got, os.Getpid())
	}
}

func TestAcquireLeavesWhatALinkPointsAt(t *testing.T) {
	hermetic.Symlinks(t)
	path := lockPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "precious")
	if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if lock, err := Acquire(path, 0); err == nil {
		lock.Release()
		t.Error("took a lock through a link")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep me" {
		t.Errorf("target = %q, %v", data, err)
	}
}

// A link to nothing would otherwise have the open create the file it names.
func TestAcquireCreatesNothingThroughALink(t *testing.T) {
	hermetic.Symlinks(t)
	path := lockPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "not-there-yet")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if lock, err := Acquire(path, 0); err == nil {
		lock.Release()
		t.Error("took a lock through a link")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the open created the link's target: %v", err)
	}
}

// The same socket through a linked folder, as with /tmp and /private/tmp on
// macOS, has to be the same lock: the file is, whatever its name says.
func TestALockHoldsThroughALinkedFolder(t *testing.T) {
	hermetic.Symlinks(t)
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	direct, err := Acquire(PathForSocket(filepath.Join(real, "s.sock")), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Release()
	through, err := Acquire(PathForSocket(filepath.Join(link, "s.sock")), 0)
	var held *HeldError
	if !errors.As(err, &held) {
		if through != nil {
			through.Release()
		}
		t.Errorf("through the link: err = %v, want HeldError", err)
	}
}

func TestPathForSocket(t *testing.T) {
	dir := t.TempDir()
	one, two := filepath.Join(dir, "one.sock"), filepath.Join(dir, "two.sock")
	if PathForSocket(one) == PathForSocket(two) {
		t.Errorf("two sockets in one folder share the lock %s", PathForSocket(one))
	}
	// Beside the socket: its folder's owner check is what protects the lock.
	if got := filepath.Dir(PathForSocket(one)); got != dir {
		t.Errorf("lock is in %s, not beside its socket in %s", got, dir)
	}
}

// macOS deletes regular files under /tmp that nothing touched for three days,
// even one a running daemon has locked. The next daemon would then lock a new file.
func TestAHeldLockKeepsItsFileFresh(t *testing.T) {
	previous := refreshInterval
	refreshInterval = 10 * time.Millisecond
	t.Cleanup(func() { refreshInterval = previous })
	path := lockPath(t)
	lock, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()

	old := time.Now().Add(-96 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.ModTime().After(time.Now().Add(-time.Hour)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the file still reads %v", info.ModTime())
		}
		time.Sleep(5 * time.Millisecond)
	}

	lock.Release()
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().After(time.Now().Add(-time.Hour)) {
		t.Error("a released lock still touches its file")
	}
}

func TestAcquireLeavesAMissingFolderMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-there")
	if lock, err := Acquire(filepath.Join(dir, "daemon.lock"), 0); err == nil {
		lock.Release()
		t.Error("took a lock in a folder nobody checked")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the folder was created: %v", err)
	}
}
