package agentinventory

import (
	"os"
	"testing"
)

// Keep the machine's own apps and CLIs out of every fixture.
func TestMain(m *testing.M) {
	SystemAppDirs = nil
	SystemCLIDirs = nil
	os.Setenv("PATH", "")
	os.Exit(m.Run())
}
