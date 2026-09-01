package stepsafety

import (
	"os/exec"
	"testing"
)

func TestWorkerPackingContract(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	cmd := exec.Command(python, "worker_test.py")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("worker packing contract: %v\n%s", err, output)
	}
}
