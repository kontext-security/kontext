package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
)

const startStatusPrefix = "model status at start: "

// Runs in a process of its own, because the model loads once per process and
// another test may already have loaded it. The load never finishes here, so the
// answer doesn't depend on which of it and Start is quicker.
func TestStartStatusHelper(t *testing.T) {
	dir := os.Getenv("KONTEXT_TEST_START_STATUS_DIR")
	if dir == "" {
		t.Skip("helper for TestStartDoesNotWaitForTheRealModel")
	}
	t.Setenv("KONTEXT_STEP_SAFETY_SHADOW", "")
	stepsafety.HoldNativeLoad(make(chan struct{}))
	ctx := context.Background()
	host, err := Start(ctx, Options{AgentName: "claude", CWD: dir, DBPath: filepath.Join(dir, "guard.db")})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(startStatusPrefix + host.stepSafety.Health(ctx).Status)
	_ = host.Close(ctx)
}

// The tests with a stand-in model hand the host an evaluator, so they don't cover
// what the host builds by itself.
func TestStartDoesNotWaitForTheRealModel(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartStatusHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "KONTEXT_TEST_START_STATUS_DIR="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, output)
	}
	_, rest, found := strings.Cut(string(output), startStatusPrefix)
	if !found {
		t.Fatalf("helper said nothing about the model:\n%s", output)
	}
	status, _, _ := strings.Cut(rest, "\n")
	if strings.TrimSpace(status) != "loading" {
		t.Errorf("the model was %q when Start returned, so Start waited for it", status)
	}
}

// heldLog holds the line that reports a failed load until the test lets go.
type heldLog struct {
	reached, release chan struct{}
}

func (l *heldLog) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "shadow unavailable") {
		close(l.reached)
		<-l.release
	}
	return len(p), nil
}

// A log that blocks can't hold up a stop or the cleanup after a failed start.
func TestStuckLogDoesNotHoldUpClose(t *testing.T) {
	log := &heldLog{reached: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(log.release) })
	ctx := context.Background()
	evaluator := stepsafety.NewWithLoader(ctx, stepsafety.Config{Enabled: true}, func(context.Context) (stepsafety.Backend, error) {
		return nil, errors.New("no weights")
	})
	host, err := Start(ctx, Options{
		AgentName:  "claude",
		CWD:        t.TempDir(),
		DBPath:     filepath.Join(t.TempDir(), "guard.db"),
		Diagnostic: diagnostic.New(log, true),
		StepSafety: evaluator,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-log.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the failed load wasn't reported")
	}
	closed := make(chan struct{})
	go func() {
		_ = host.Close(ctx)
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close is waiting for the log")
	}
}
