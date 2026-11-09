package agenthooks

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsKontextBinary(t *testing.T) {
	for path, want := range map[string]bool{
		"/usr/local/bin/kontext":                       true,
		"kontext":                                      true,
		`C:\Program Files\Kontext\kontext.exe`:         true,
		`C:\Users\t\kontext.exe`:                       true,
		`C:\Program Files\Kontext\KONTEXT.EXE`:         true,
		"C:/Program Files/Kontext/Kontext.Exe":         true,
		"/usr/local/bin/kontext-dev":                   false,
		"/usr/local/bin/Kontext":                       false,
		`C:\Program Files\Kontext\kontext.exe.bak`:     false,
		`C:\Program Files\Kontext\kontext.cmd`:         false,
		`'C:\K\kontext.exe' hook 'pre-tool-use'`:       false,
		"'/usr/local/bin/kontext' hook 'pre-tool-use'": false,
		"": false,
	} {
		if got := IsKontextBinary(path); got != want {
			t.Errorf("IsKontextBinary(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsExecutableOn(t *testing.T) {
	dir := t.TempDir()
	file := func(name string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, nil, mode); err != nil {
			t.Fatal(err)
		}
		// WriteFile honours the umask; set the mode the case names.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	exe := file("kontext.exe", 0o644)
	upper := file("KONTEXT.EXE", 0o644)
	script := file("kontext", 0o755)
	plain := file("kontext-data", 0o644)
	for _, tt := range []struct {
		goos, path string
		want       bool
	}{
		// Go reports no execute bit for any Windows file, so the extension decides.
		{"windows", exe, true},
		{"windows", upper, true},
		{"windows", script, false},
		{"windows", dir, false},
		{"windows", filepath.Join(dir, "missing.exe"), false},
		{"darwin", script, true},
		{"darwin", exe, false},
		{"darwin", plain, false},
		{"darwin", dir, false},
	} {
		if tt.goos != "windows" && runtime.GOOS == "windows" {
			continue // a Windows host holds no POSIX execute bit
		}
		if got := isExecutableOn(tt.goos, tt.path); got != tt.want {
			t.Errorf("isExecutableOn(%s, %s) = %v, want %v", tt.goos, filepath.Base(tt.path), got, tt.want)
		}
	}
}
