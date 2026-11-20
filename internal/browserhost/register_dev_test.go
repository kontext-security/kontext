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

func TestLinuxManifestFollowsChromeOverrides(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("CHROME_CONFIG_HOME and CHROME_USER_DATA_DIR are Linux overrides")
	}
	config, data := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CHROME_CONFIG_HOME", config)
	dir, err := manifestDir(DevRegistration{Browser: "chromium"})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(config, "chromium", "NativeMessagingHosts"); dir != want {
		t.Fatalf("CHROME_CONFIG_HOME: dir = %s, want %s", dir, want)
	}
	t.Setenv("CHROME_USER_DATA_DIR", data)
	if dir, _ = manifestDir(DevRegistration{Browser: "chrome"}); dir != filepath.Join(data, "NativeMessagingHosts") {
		t.Fatalf("CHROME_USER_DATA_DIR: dir = %s", dir)
	}
	explicit := t.TempDir()
	if dir, _ = manifestDir(DevRegistration{Browser: "chrome", UserDataDir: explicit}); dir != filepath.Join(explicit, "NativeMessagingHosts") {
		t.Fatalf("--user-data-dir: dir = %s", dir)
	}
}

func TestWindowsRegistrationFailsEvenWithAFolder(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows finds native hosts in the registry")
	}
	if _, err := manifestDir(DevRegistration{Browser: "chrome", UserDataDir: t.TempDir()}); err == nil {
		t.Fatal("registered into a folder Windows never reads")
	}
}
