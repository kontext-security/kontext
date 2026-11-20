//go:build kontext_browser_dev

package browserhost

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLinuxManifestFollowsXDGConfigHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG_CONFIG_HOME is a Linux path")
	}
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	dir, err := manifestDir(DevRegistration{Browser: "chrome"})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(config, "google-chrome", "NativeMessagingHosts"); dir != want {
		t.Fatalf("dir = %s, want %s", dir, want)
	}
}
