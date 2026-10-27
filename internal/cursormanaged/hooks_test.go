package cursormanaged

import (
	"encoding/json"
	"strings"
	"testing"
)

// Ways the hooks.json edit can fail, from review: an administrator's hook is
// dropped or claimed as ours, a file without our hooks is emptied on removal,
// a version Cursor rejects survives, and validation calls a broken set wired.
func TestMergeRemoveValidate(t *testing.T) {
	const binary = "/usr/local/bin/kontext"
	admin := `{"version":null,"hooks":{
		"preToolUse":[{"command":"/opt/audit/hook"}],
		"stop":[{"command":"audit;/usr/local/bin/kontext hook --agent cursor stop"}]}}`
	settings := decode(t, admin)
	if err := MergeManagedHooks(settings, binary); err != nil {
		t.Fatal(err)
	}
	merged := encode(t, settings)
	if _, err := ValidateInstalled(merged); err != nil {
		t.Fatalf("ValidateInstalled(merged) = %v\n%s", err, merged)
	}
	for _, keep := range []string{"/opt/audit/hook", "audit;/usr/local/bin/kontext"} {
		if !strings.Contains(string(merged), keep) {
			t.Fatalf("merge dropped %q:\n%s", keep, merged)
		}
	}

	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatal(err)
	}
	removed := encode(t, settings)
	if strings.Contains(string(removed), "hook --agent 'cursor'") ||
		!strings.Contains(string(removed), "/opt/audit/hook") ||
		!strings.Contains(string(removed), "audit;/usr/local/bin/kontext") {
		t.Fatalf("remove left:\n%s", removed)
	}

	foreign := decode(t, `{"version":1,"hooks":{}}`)
	if err := RemoveManagedHooks(foreign); err != nil {
		t.Fatal(err)
	}
	if len(foreign) == 0 {
		t.Fatal("remove emptied a file that held no Kontext hooks, so the installer would delete it")
	}

	// An array an administrator left empty is theirs: removal must not touch
	// it, or the installer asks for sudo to rewrite a file with no Kontext hooks.
	emptyArray := decode(t, `{"version":1,"hooks":{"beforeShellExecution":[]}}`)
	if err := RemoveManagedHooks(emptyArray); err != nil {
		t.Fatal(err)
	}
	if got := string(encode(t, emptyArray)); !strings.Contains(got, "beforeShellExecution") {
		t.Fatalf("remove dropped a foreign empty array:\n%s", got)
	}

	// A quoted binary path is ours, so a rerun replaces the set instead of
	// adding a second one.
	quoted := map[string]any{}
	for range 2 {
		if err := MergeManagedHooks(quoted, "/Applications/Kontext (Dev)/kontext"); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(quoted["hooks"].(map[string]any)["preToolUse"].([]any)); n != 1 {
		t.Fatalf("two installs left %d preToolUse hooks, want 1", n)
	}

	for _, broken := range []string{
		`{"version":1,"hooks":{}}`,
		strings.Replace(string(merged), `"version": 1`, `"version": 0`, 1),
		strings.Replace(string(merged), `"timeout": 20`, `"timeout": 0`, 1),
	} {
		if _, err := ValidateInstalled([]byte(broken)); err == nil {
			t.Fatalf("ValidateInstalled accepted:\n%s", broken)
		}
	}
}

func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var settings map[string]any
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		t.Fatal(err)
	}
	return settings
}

func encode(t *testing.T, settings map[string]any) []byte {
	t.Helper()
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}
