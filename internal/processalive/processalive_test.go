package processalive

import (
	"os"
	"os/exec"
	"testing"
)

func TestAliveTellsARunningProcessFromAnEndedOne(t *testing.T) {
	if !Alive(os.Getpid()) {
		t.Fatal("this process does not count as alive")
	}
	for _, pid := range []int{0, -1} {
		if Alive(pid) {
			t.Fatalf("pid %d counts as alive", pid)
		}
	}
	child := exec.Command(os.Args[0], "-test.run=^$")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	if err := child.Wait(); err != nil {
		t.Fatalf("the child did not exit cleanly: %v", err)
	}
	if Alive(pid) {
		t.Fatalf("pid %d of a child that has exited and been waited for counts as alive", pid)
	}
}
