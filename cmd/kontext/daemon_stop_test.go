package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
)

const daemonHelperEnv = "KONTEXT_DAEMON_STOP_TEST_HELPER"

// TestDaemonCommandHelper is the process TestDaemonCommandStopsCleanlyOnASignal
// stops. It isn't a test.
func TestDaemonCommandHelper(t *testing.T) {
	if os.Getenv(daemonHelperEnv) == "" {
		t.Skip("runs only as a helper process")
	}
	root := newRootCmd()
	root.SetArgs([]string{"managed-observe-daemon", "--no-codex-route"})
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// The real command, so this fails if the signal handling isn't wired to it.
// Without it the signal kills the process and leaves the socket behind.
func TestDaemonCommandStopsCleanlyOnASignal(t *testing.T) {
	home := hermetic.Home(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(config, []byte(`{
  "version": "managed-install-v1",
  "cloud_url": "https://kx.invalid",
  "mode": "observe",
  "agent": "claude",
  "credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"},
  "device": {"label": "test"}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(hermetic.SocketDir(t), "kontext.sock")

	cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonCommandHelper$")
	cmd.Env = append(os.Environ(),
		daemonHelperEnv+"=1",
		"HOME="+home,
		"USERPROFILE="+home,
		"LOCALAPPDATA="+filepath.Join(home, "local"),
		"KONTEXT_INSTALL_TOKEN=fake-not-a-token",
		"KONTEXT_MANAGED_CONFIG="+config,
		"KONTEXT_INSTALLATION_STATE="+filepath.Join(dir, "installation.json"),
		"KONTEXT_MANAGED_OBSERVE_DB="+filepath.Join(dir, "guard.db"),
		"KONTEXT_MANAGED_OBSERVE_SOCKET="+socket,
		"KONTEXT_STEP_SAFETY_SHADOW=false",
	)
	prepareDaemonHelper(cmd)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", socket, time.Second)
		if err == nil {
			conn.Close()
			break
		}
		select {
		case err := <-exited:
			t.Fatalf("the daemon ended before it was up: %v\n%s", err, stderr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon never answered on its socket")
		}
		time.Sleep(20 * time.Millisecond)
	}

	sendDaemonStop(t, cmd)
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("the daemon didn't exit cleanly: %v\n%s", err, stderr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the daemon didn't stop")
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket is still there, so the daemon didn't shut down: %v", err)
	}
}
