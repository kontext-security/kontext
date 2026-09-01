package stepsafety

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

const restartTestWorker = `
import argparse
import json
import os
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--model-dir", required=True)
parser.add_argument("--model-version", required=True)
parser.add_argument("--device")
args = parser.parse_args()
marker = os.path.join(args.model_dir, "timed-out-once")

def write(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()

write({"id": 0, "type": "ready", "status": "ready", "model_version": args.model_version, "device": "cpu"})
for line in sys.stdin:
    request = json.loads(line)
    if request["type"] == "health":
        write({"id": request["id"], "type": "health", "status": "ready", "model_version": args.model_version, "device": "cpu"})
        continue
    if not os.path.exists(marker):
        open(marker, "w").close()
        time.sleep(5)
    write({"id": request["id"], "type": "result", "logits": [0.0, 1.0]})
`

func TestPythonBackendRestartsAfterTimedOutResponse(t *testing.T) {
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	cfg := normalizeConfig(Config{
		ModelDir:       t.TempDir(),
		Python:         pythonPath,
		Device:         "cpu",
		StartupTimeout: 2 * time.Second,
		ModelVersion:   ModelVersion,
	})
	startCtx, cancel := context.WithTimeout(context.Background(), cfg.StartupTimeout)
	process, ready, err := launchPythonWorker(startCtx, cfg, pythonPath, restartTestWorker)
	cancel()
	if err != nil {
		t.Fatalf("launch test worker: %v", err)
	}
	if err := validateReadyResponse(ready, cfg.ModelVersion); err != nil {
		t.Fatal(err)
	}
	backend := &pythonBackend{
		operation:    make(chan struct{}, 1),
		cfg:          cfg,
		pythonPath:   pythonPath,
		workerSource: restartTestWorker,
		worker:       process,
		device:       ready.Device,
	}
	t.Cleanup(func() { _ = backend.Close() })

	inferCtx, cancelInfer := context.WithTimeout(context.Background(), 30*time.Millisecond)
	started := time.Now()
	_, err = backend.Infer(inferCtx, Input{ToolName: "Read", ToolArguments: map[string]any{}})
	elapsed := time.Since(started)
	cancelInfer()
	if err == nil || errorCode(err) != ErrorTimeout {
		t.Fatalf("first Infer() error = %v, want timeout", err)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("timed-out Infer() returned after %s; worker reaping leaked into hook budget", elapsed)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		healthCtx, cancelHealth := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, healthErr := backend.Health(healthCtx)
		cancelHealth()
		if healthErr == nil {
			break
		}
		if !errors.Is(healthErr, context.DeadlineExceeded) && time.Now().After(deadline) {
			t.Fatalf("worker did not recover: %v", healthErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker recovery timed out: %v", healthErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	logits, err := backend.Infer(secondCtx, Input{ToolName: "Read", ToolArguments: map[string]any{}})
	cancelSecond()
	if err != nil {
		t.Fatalf("Infer() after restart error = %v", err)
	}
	if logits != [2]float64{0, 1} {
		t.Fatalf("Infer() after restart logits = %v", logits)
	}
}
