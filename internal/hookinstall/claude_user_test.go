package hookinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/claudemanaged"
)

func TestClaudeUserInstallPreservesSymlinkAndForeignSettings(t *testing.T) {
	opts, defs := fixture(t, User)
	path := defs[0].Files[1].Path
	target := filepath.Join(t.TempDir(), "dotfiles.json")
	original := `{"env":{"PERSONAL":"keep"},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo personal"}]}]}}`
	write(t, target, original, 0640)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := runDefinitions(opts, defs, false); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("settings symlink lost: %v", err)
	}
	if !claudemanaged.CanonicalManagedHooks([]byte(read(t, target)), opts.Binary) {
		t.Fatal("user handlers differ from managed handlers")
	}
	backups, _ := filepath.Glob(path + "." + BackupLabel + "-backup-*")
	if len(backups) != 1 || read(t, backups[0]) != original {
		t.Fatalf("backup was lost or duplicated: %v", backups)
	}
	info, _ = os.Stat(target)
	if info.Mode().Perm() != 0640 {
		t.Fatal("target permissions changed")
	}
	if err := runDefinitions(opts, defs, true); err != nil {
		t.Fatal(err)
	}
	got := read(t, target)
	if strings.Contains(got, "kontext") || !strings.Contains(got, "echo personal") || !strings.Contains(got, "PERSONAL") {
		t.Fatalf("uninstall changed foreign settings: %s", got)
	}
}

func TestSystemInstallDoesNotTouchUserClaudeSettings(t *testing.T) {
	opts, defs := fixture(t, System)
	user := filepath.Join(t.TempDir(), "settings.json")
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Dir(user))
	write(t, user, "{broken personal JSON", 0600)
	if len(defs[0].Files) != 1 {
		t.Fatal("system installation gained a user layer")
	}
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	if err := runDefinitions(opts, defs, true); err != nil {
		t.Fatal(err)
	}
	if read(t, user) != "{broken personal JSON" {
		t.Fatal("system installer changed user settings")
	}
}

func TestClaudeUserPlanRejectsMalformedSettingsBeforeWriting(t *testing.T) {
	for _, raw := range []string{"{", "null", `{"hooks":[]}`} {
		t.Run(raw, func(t *testing.T) {
			opts, defs := fixture(t, User)
			write(t, defs[0].Files[1].Path, raw, 0600)
			if err := runDefinitions(opts, defs, false); err == nil {
				t.Fatal("accepted invalid user settings")
			}
			if _, err := os.Stat(defs[0].Files[0].Path); !os.IsNotExist(err) {
				t.Fatal("managed file changed before user settings validated")
			}
		})
	}
}

func TestClaudeUserPlanRejectsDanglingSymlinkBeforeWriting(t *testing.T) {
	opts, defs := fixture(t, User)
	path := defs[0].Files[1].Path
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing.json"), path); err != nil {
		t.Fatal(err)
	}
	if err := runDefinitions(opts, defs, false); err == nil {
		t.Fatal("accepted dangling user settings symlink")
	}
	if _, err := os.Stat(defs[0].Files[0].Path); !os.IsNotExist(err) {
		t.Fatal("changed managed hooks before resolving user settings")
	}
}

func TestDoctorDetectsUserDriftWithoutChangingSettings(t *testing.T) {
	opts, defs := fixture(t, User)
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	path := defs[0].Files[1].Path
	original := strings.Replace(read(t, path), `"timeout": 20`, `"timeout": 21`, 1)
	write(t, path, original, 0600)
	var out bytes.Buffer
	if diagnose(&out, User, defs[:1], func(string) bool { return true }, "", "") || !strings.Contains(out.String(), "execute twice") {
		t.Fatalf("drift was not diagnosed: %s", &out)
	}
	if read(t, path) != original {
		t.Fatal("doctor modified user settings")
	}
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	if !diagnose(&out, User, defs[:1], func(string) bool { return true }, "", "") {
		t.Fatalf("repair did not synchronize layers: %s", &out)
	}
}

func TestDoctorScansSiblingPoliciesAndTreatsRemoteCacheAsUnverified(t *testing.T) {
	opts, defs := fixture(t, User)
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	dropin, user := defs[0].Files[0].Path, defs[0].Files[1].Path
	write(t, filepath.Join(filepath.Dir(filepath.Dir(dropin)), "managed-settings.json"), "\n", 0644)
	sibling := filepath.Join(filepath.Dir(dropin), "99-policy.json")
	write(t, sibling, `{"disableAllHooks":true}`, 0644)
	write(t, filepath.Join(filepath.Dir(user), "remote-settings.json"), `{"cleanupPeriodDays":30}`, 0600)
	var out bytes.Buffer
	if diagnoseClaudeSources(&out, dropin, user) {
		t.Fatal("ignored sibling disableAllHooks")
	}
	for _, expected := range []string{"99-policy.json", "disableAllHooks=true", "cache presence alone does not prove", "activation: unverified", "`/status`"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("missing %q: %s", expected, &out)
		}
	}
	// Last file wins for scalars; don't treat every lower true as effective.
	write(t, filepath.Join(filepath.Dir(dropin), "zz-policy.json"), `{"disableAllHooks":false,"allowManagedHooksOnly":true}`, 0644)
	out.Reset()
	if !diagnoseClaudeSources(&out, dropin, user) || strings.Contains(out.String(), "disableAllHooks=true") || !strings.Contains(out.String(), "fallback: restricted") {
		t.Fatalf("incorrect source merge: %s", &out)
	}
	write(t, sibling, "{", 0644)
	if diagnoseClaudeSources(&out, dropin, user) {
		t.Fatal("ignored malformed sibling")
	}
	write(t, sibling, `{"disableAllHooks":"true"}`, 0644)
	if diagnoseClaudeSources(&out, dropin, user) || !strings.Contains(out.String(), "must be a Boolean") {
		t.Fatal("ignored invalid policy flag type")
	}
}

func TestRefreshClaudeUserRefusesUnsynchronizedManagedCopy(t *testing.T) {
	path, binary, _ := refreshFixture(t)
	user := filepath.Join(t.TempDir(), "settings.json")
	if err := RefreshClaudeUser(path, user, binary); err == nil {
		t.Fatal("introduced user hooks before managed migration")
	}
	if _, err := os.Stat(user); !os.IsNotExist(err) {
		t.Fatal("created user hooks on failed migration")
	}
	canonical, _ := claudemanaged.TemplateJSON(binary)
	write(t, path, string(canonical), 0644)
	if err := RefreshClaudeUser(path, user, binary); err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(read(t, user)), &settings); err != nil {
		t.Fatal(err)
	}
	if !claudemanaged.CanonicalManagedHooks([]byte(read(t, user)), binary) {
		t.Fatal("user migration installed different handlers")
	}
}
