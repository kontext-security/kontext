package cli

import (
	"bytes"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

func TestManagedHookStatusReportsEveryAgent(t *testing.T) {
	// Agent presence is host-dependent here; the isolated health cases live in
	// hookinstall. This verifies both entry points share the full definition.
	for _, system := range []bool{false, true} {
		var out bytes.Buffer
		if system {
			PrintOrganizationManagedHookStatus(&out)
		} else {
			PrintManagedHookStatus(&out)
		}
		for _, name := range []string{"Claude Code hooks:", "Codex hooks:"} {
			if !bytes.Contains(out.Bytes(), []byte(name)) {
				t.Fatalf("missing %s: %s", name, &out)
			}
		}
	}
}

// A machine-wide diagnosis as root with an empty environment (an MDM) has no
// home folder and needs none; the user's own installation cannot be found
// without one.
func TestOrganizationHookStatusNeedsNoHome(t *testing.T) {
	hermetic.SetHome(t, "")
	var out bytes.Buffer
	PrintOrganizationManagedHookStatus(&out)
	if !bytes.Contains(out.Bytes(), []byte("Claude Code hooks:")) {
		t.Fatalf("system scope did not diagnose without a home folder: %s", &out)
	}
	out.Reset()
	if PrintManagedHookStatus(&out).Healthy || bytes.Contains(out.Bytes(), []byte("Claude Code hooks:")) {
		t.Fatalf("user scope diagnosed without a home folder: %s", &out)
	}
}
