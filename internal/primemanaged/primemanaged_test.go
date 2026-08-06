package primemanaged

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestRenderInjectsBinaryAndKeepsMarker(t *testing.T) {
	data, err := Render("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, `"/opt/homebrew/bin/kontext"`) {
		t.Fatal("rendered extension does not contain the kontext binary path")
	}
	if strings.Contains(content, binaryPlaceholder) {
		t.Fatal("rendered extension still contains the binary placeholder")
	}
	if !IsManaged(data) {
		t.Fatal("rendered extension is missing the managed marker")
	}
	if !strings.Contains(content, `"--agent", AGENT`) {
		t.Fatal("rendered extension does not invoke the hook with an agent flag")
	}
}

func TestRenderRejectsUnsafeBinaryPaths(t *testing.T) {
	for _, binary := range []string{"", `/tmp/"quote"/kontext`, "/tmp/line\nbreak"} {
		if _, err := Render(binary); err == nil {
			t.Fatalf("Render(%q) succeeded, want error", binary)
		}
	}
}

func TestInstallWritesManagedExtension(t *testing.T) {
	home := withTempHome(t)

	path, err := Install("/usr/local/bin/kontext")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	want := filepath.Join(home, ".prime", "agent", "extensions", ExtensionFileName)
	if path != want {
		t.Fatalf("install path = %q, want %q", path, want)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read installed extension: %v", err)
	}
	if !IsManaged(data) {
		t.Fatal("installed extension is missing the managed marker")
	}

	// Reinstall over a managed file succeeds.
	if _, err := Install("/usr/local/bin/kontext"); err != nil {
		t.Fatalf("reinstall over managed extension: %v", err)
	}
}

func TestInstallRefusesToOverwriteUnmanagedExtension(t *testing.T) {
	home := withTempHome(t)
	dir := filepath.Join(home, ".prime", "agent", "extensions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ExtensionFileName)
	if err := os.WriteFile(path, []byte("// user-owned extension"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Install("/usr/local/bin/kontext"); err == nil {
		t.Fatal("Install overwrote an unmanaged extension, want error")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "// user-owned extension" {
		t.Fatal("unmanaged extension contents were modified")
	}
}

func TestRemoveDeletesOnlyManagedExtension(t *testing.T) {
	withTempHome(t)

	// Nothing installed: no-op.
	removed, err := Remove()
	if err != nil {
		t.Fatalf("Remove with nothing installed: %v", err)
	}
	if removed {
		t.Fatal("Remove reported a removal with nothing installed")
	}

	if _, err := Install("/usr/local/bin/kontext"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	removed, err = Remove()
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !removed {
		t.Fatal("Remove did not report removing the managed extension")
	}

	path, err := ExtensionPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("// user-owned extension"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(); err == nil {
		t.Fatal("Remove deleted an unmanaged extension, want error")
	}
}

func TestAgentInstalledDetectsConfigDir(t *testing.T) {
	home := withTempHome(t)

	installed, err := AgentInstalled()
	if err != nil {
		t.Fatalf("AgentInstalled: %v", err)
	}
	if installed {
		t.Fatal("AgentInstalled reported true without a config dir")
	}

	if err := os.MkdirAll(filepath.Join(home, ".prime", "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	installed, err = AgentInstalled()
	if err != nil {
		t.Fatalf("AgentInstalled: %v", err)
	}
	if !installed {
		t.Fatal("AgentInstalled reported false with a config dir present")
	}
}
