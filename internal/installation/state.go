package installation

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

const (
	DefaultPath = "/Library/Application Support/Kontext/installation.json"
	EnvPath     = "KONTEXT_INSTALLATION_STATE"
)

var ErrNotFound = errors.New("installation state not found")

type State struct {
	InstallationID string `json:"installation_id"`
}

func PathFromEnv() string {
	if path := strings.TrimSpace(os.Getenv(EnvPath)); path != "" {
		return path
	}
	return DefaultPath
}

// UserPath is the self-serve installation identity location (paired with the
// user-scope managed config), or "" when the home directory cannot be
// resolved. The system DefaultPath stays the default so enterprise daemons
// keep creating identity under /Library exactly as before.
//
// Identity is per-profile: the same Mac enrolled in two workspaces must not
// present one shared installation id to both. Resolution mirrors
// managedconfig.UserPath — active profile when there is one, legacy path
// otherwise.
func UserPath() string {
	if path, err := profile.ActiveInstallationPath(); err == nil {
		return path
	}
	return LegacyUserPath()
}

// LegacyUserPath is the pre-profile self-serve identity location.
func LegacyUserPath() string {
	return profile.LegacyPath(profile.InstallationFile)
}

func LoadFile(path string) (State, error) {
	if err := validateStateFile(path); err != nil {
		return State{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, ErrNotFound
		}
		return State{}, err
	}
	return parse(data)
}

func EnsureFile(path string) (State, error) {
	state, err := LoadFile(path)
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return State{}, err
	}

	state, err = newState()
	if err != nil {
		return State{}, err
	}
	data, err := encode(state)
	if err != nil {
		return State{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return State{}, err
	}

	temp, err := writeTempState(filepath.Dir(path), data)
	if err != nil {
		return State{}, err
	}
	defer os.Remove(temp)

	if err := os.Link(temp, path); err == nil {
		if err := syncDir(filepath.Dir(path)); err != nil {
			return State{}, err
		}
		return state, nil
	} else if errors.Is(err, os.ErrExist) {
		return LoadFile(path)
	} else {
		return State{}, err
	}
}

func validateStateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("installation state must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return errors.New("installation state must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return errors.New("installation state must have 0600 permissions")
	}
	return nil
}

func parse(data []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, errors.New("unexpected trailing JSON value")
	}
	if err := validate(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func encode(state State) ([]byte, error) {
	if err := validate(state); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writeTempState(dir string, data []byte) (string, error) {
	file, err := os.CreateTemp(dir, ".installation-*.tmp")
	if err != nil {
		return "", err
	}
	path := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			file.Close()
			os.Remove(path)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return path, nil
}

func syncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func newState() (State, error) {
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return State{}, err
	}
	return State{
		InstallationID: "ins_" + base64.RawURLEncoding.EncodeToString(random[:]),
	}, nil
}

func validate(state State) error {
	if !strings.HasPrefix(state.InstallationID, "ins_") {
		return fmt.Errorf("installation_id must start with %q", "ins_")
	}
	encoded := strings.TrimPrefix(state.InstallationID, "ins_")
	if len(encoded) != 32 {
		return errors.New("installation_id must be a generated installation id")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 24 {
		return errors.New("installation_id must be a generated installation id")
	}
	return nil
}
