//go:build kontext_browser_dev

package browserhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DevRegistration says where `kontext browser-host register` writes the
// host's manifest. Releases are registered machine-wide by the installers;
// this per-user registration exists only in dev builds.
type DevRegistration struct {
	// Browser is chrome, edge or chromium.
	Browser string
	// UserDataDir, when set, is a browser profile folder such as the one a
	// test starts the browser with; the manifest goes into it.
	UserDataDir string
	// Executable is the kontext binary the browser should start.
	Executable string
}

type hostManifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

// RegisterDev writes the manifest and returns its path.
func RegisterDev(reg DevRegistration) (string, error) {
	if reg.Executable == "" || !filepath.IsAbs(reg.Executable) {
		return "", errors.New("browser host: the executable path must be absolute")
	}
	dir, err := manifestDir(reg)
	if err != nil {
		return "", err
	}
	origins := make([]string, 0, len(AllowedExtensionIDs()))
	for _, id := range AllowedExtensionIDs() {
		origins = append(origins, "chrome-extension://"+id+"/")
	}
	data, err := json.MarshalIndent(hostManifest{
		Name:           Name,
		Description:    "Kontext browser host (dev build)",
		Path:           reg.Executable,
		Type:           "stdio",
		AllowedOrigins: origins,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, Name+".json")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func manifestDir(reg DevRegistration) (string, error) {
	if reg.UserDataDir != "" {
		return filepath.Join(reg.UserDataDir, "NativeMessagingHosts"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	folders := map[string]map[string]string{
		"darwin": {
			"chrome":   "Library/Application Support/Google/Chrome",
			"edge":     "Library/Application Support/Microsoft Edge",
			"chromium": "Library/Application Support/Chromium",
		},
		"linux": {
			"chrome":   ".config/google-chrome",
			"edge":     ".config/microsoft-edge",
			"chromium": ".config/chromium",
		},
	}
	byBrowser, ok := folders[runtime.GOOS]
	if !ok {
		return "", fmt.Errorf("browser host: dev registration is not supported on %s", runtime.GOOS)
	}
	folder, ok := byBrowser[reg.Browser]
	if !ok {
		return "", fmt.Errorf("browser host: unknown browser %q", reg.Browser)
	}
	return filepath.Join(home, folder, "NativeMessagingHosts"), nil
}
