package instancelock

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/platform"
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
	return filepath.Join(t.TempDir(), "locks", "daemon.lock")
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

func TestPathForSocketIsTheSameThroughALink(t *testing.T) {
	hermetic.Symlinks(t)
	hermetic.Home(t)
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	direct, err := PathForSocket(filepath.Join(real, "s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	through, err := PathForSocket(filepath.Join(link, "s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if direct != through {
		t.Errorf("one socket has two locks: %s and %s", direct, through)
	}
}

func TestMachineKey(t *testing.T) {
	previous := hostname
	t.Cleanup(func() { hostname = previous })
	hostname = func() (string, error) { return "one", nil }

	if got := machineKey("linux"); got != "one" {
		t.Errorf("Linux: key = %q, want the hostname", got)
	}
	for _, goos := range []string{"darwin", "windows"} {
		if got := machineKey(goos); got != "" {
			t.Errorf("%s: key = %q, want none", goos, got)
		}
	}
	hostname = func() (string, error) { return "", errors.New("no hostname") }
	if got := machineKey("linux"); got != "" {
		t.Errorf("without a hostname: key = %q", got)
	}
}

func TestPathForSocketDiffersByMachineOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the key is empty elsewhere; TestMachineKey covers that")
	}
	hermetic.Home(t)
	socket := filepath.Join(t.TempDir(), "s.sock")
	previous := hostname
	t.Cleanup(func() { hostname = previous })

	paths := map[string]string{}
	for _, host := range []string{"one", "two"} {
		hostname = func() (string, error) { return host, nil }
		path, err := PathForSocket(socket)
		if err != nil {
			t.Fatal(err)
		}
		paths[host] = path
	}
	if paths["one"] == paths["two"] {
		t.Errorf("two machines share the lock %s", paths["one"])
	}
}

func TestPathForSocket(t *testing.T) {
	hermetic.Home(t)
	one, err := PathForSocket(filepath.Join(t.TempDir(), "one.sock"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := PathForSocket(filepath.Join(filepath.Dir(one), "..", "unrelated.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if one == again {
		t.Errorf("two sockets share the lock %s", one)
	}
	if !filepath.IsAbs(one) {
		t.Errorf("lock path %q is relative", one)
	}

	socket := filepath.Join(t.TempDir(), "same.sock")
	first, err := PathForSocket(socket)
	if err != nil {
		t.Fatal(err)
	}
	spelled, err := PathForSocket(filepath.Join(filepath.Dir(socket), ".", "same.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if first != spelled {
		t.Errorf("one socket has two locks: %s and %s", first, spelled)
	}
	// Beside the socket is under /tmp on Unix, where another user can get first.
	state, err := platform.UserStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, state+string(filepath.Separator)) {
		t.Errorf("lock %s isn't in the user's state folder %s", first, state)
	}
}
