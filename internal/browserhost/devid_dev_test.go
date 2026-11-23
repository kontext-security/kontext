//go:build kontext_browser_dev

package browserhost

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// Pinned as a literal, so a changed DevExtensionID fails the tests.
func devIDForTest() string { return "jbfhbfeilekhmfekihompjpmkecgpfgn" }

func TestRegisterDevWritesTheManifestIntoAProfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows finds native hosts in the registry")
	}
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
	want := []string{"chrome-extension://jdakicfhknddbigfcfgfmhoabhgpjega/", "chrome-extension://jbfhbfeilekhmfekihompjpmkecgpfgn/"}
	if manifest.Path != "/usr/local/bin/kontext" || manifest.Type != "stdio" ||
		!slices.Equal(manifest.AllowedOrigins, want) {
		t.Fatalf("manifest = %+v, want origins %q", manifest, want)
	}
}
