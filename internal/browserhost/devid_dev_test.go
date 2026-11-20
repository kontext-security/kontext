//go:build kontext_browser_dev

package browserhost

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func devIDForTest() string { return DevExtensionID }

func TestRegisterDevWritesTheManifestIntoAProfile(t *testing.T) {
	dir := t.TempDir()
	path, err := RegisterDev(DevRegistration{Browser: "chromium", UserDataDir: dir, Executable: "/usr/local/bin/kontext"})
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "NativeMessagingHosts", Name+".json") {
		t.Fatalf("path = %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest hostManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Path != "/usr/local/bin/kontext" || manifest.Type != "stdio" ||
		len(manifest.AllowedOrigins) != 1 || manifest.AllowedOrigins[0] != "chrome-extension://"+DevExtensionID+"/" {
		t.Fatalf("manifest = %+v", manifest)
	}
}
