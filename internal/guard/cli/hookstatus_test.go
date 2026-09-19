package cli

import (
	"bytes"
	"testing"
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
