package hookinstall

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// A user install is told how to switch Kontext off. The promise that removed
// hooks are restored belongs to a Homebrew install and is not made on Windows.
func TestDiagnoseNamesHookRepairOnlyWhereItExists(t *testing.T) {
	for goos, wantRepair := range map[string]bool{"windows": false, "darwin": true} {
		t.Run(goos, func(t *testing.T) {
			previous := runtimeGOOS
			runtimeGOOS = goos
			t.Cleanup(func() { runtimeGOOS = previous })

			var out bytes.Buffer
			Diagnose(&out, User, hermetic.Home(t), nil)
			if !strings.Contains(out.String(), "`kontext setup --uninstall` switches Kontext off") {
				t.Errorf("no word on switching off:\n%s", out.String())
			}
			if got := strings.Contains(out.String(), "Homebrew"); got != wantRepair {
				t.Errorf("speaks of Homebrew: %v, want %v:\n%s", got, wantRepair, out.String())
			}
		})
	}
}
