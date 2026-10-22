package installation

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/kontext-security/kontext/internal/fsperm"
)

func TestLoadFileMissingReturnsErrNotFound(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadFile() error = %v, want ErrNotFound", err)
	}
}

func TestLoadFileExistingState(t *testing.T) {
	state := mustNewState(t)
	path := writeState(t, state)

	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if loaded.InstallationID != state.InstallationID {
		t.Fatalf("InstallationID = %q", loaded.InstallationID)
	}
}

func TestLoadFileRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	if err := writePrivateFile(path, []byte(`{"installation_id":`)); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatalf("LoadFile() error = nil, want failure")
	}
}

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	state := mustNewState(t)
	if err := writePrivateFile(path, []byte(`{"installation_id":"`+state.InstallationID+`","hostname":"mac"}`)); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err := loadFileError(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("LoadFile() error = %v, want unknown field", err)
	}
}

func TestLoadFileRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	state := mustNewState(t)
	if err := writePrivateFile(path, []byte(`{"installation_id":"`+state.InstallationID+`"}{}`)); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err := loadFileError(path)
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("LoadFile() error = %v, want trailing JSON", err)
	}
}

func TestEnsureFileCreatesIDWithPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "installation.json")

	state, err := EnsureFile(path)
	if err != nil {
		t.Fatalf("EnsureFile() error = %v", err)
	}
	if !strings.HasPrefix(state.InstallationID, "ins_") {
		t.Fatalf("InstallationID = %q, want ins_ prefix", state.InstallationID)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if private, err := fsperm.PrivateFile(path, info); err != nil || !private {
		t.Fatalf("state file not private to its owner (mode %o, err %v), want %s", info.Mode().Perm(), err, fsperm.Requirement)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if loaded.InstallationID != state.InstallationID {
		t.Fatalf("persisted ID = %q, want %q", loaded.InstallationID, state.InstallationID)
	}
}

func TestLoadFileRejectsMalformedInstallationID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	if err := writePrivateFile(path, []byte(`{"installation_id":"ins_x"}`)); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatalf("LoadFile() error = nil, want malformed ID failure")
	}
}

func TestLoadFileRejectsUnsafeMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on Windows; TestLoadFileRejectsStateOthersCanRead covers the DACL")
	}
	path := writeState(t, mustNewState(t))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatalf("LoadFile() error = nil, want unsafe mode failure")
	}
}

func TestLoadFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := writePrivateFile(target, []byte(`{"installation_id":"ins_x"}`)); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	link := filepath.Join(dir, "installation.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := LoadFile(link); err == nil {
		t.Fatalf("LoadFile() error = nil, want symlink failure")
	}
}

func TestEnsureFilePreservesExistingID(t *testing.T) {
	existing := mustNewState(t)
	path := writeState(t, existing)

	state, err := EnsureFile(path)
	if err != nil {
		t.Fatalf("EnsureFile() error = %v", err)
	}
	if state.InstallationID != existing.InstallationID {
		t.Fatalf("InstallationID = %q, want existing", state.InstallationID)
	}
}

func TestEnsureFileConcurrentFirstRunReturnsPersistedID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	const workers = 32

	var wg sync.WaitGroup
	results := make(chan State, workers)
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, err := EnsureFile(path)
			if err != nil {
				errs <- err
				return
			}
			results <- state
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("EnsureFile() concurrent error = %v", err)
	}
	persisted, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	for state := range results {
		if state.InstallationID != persisted.InstallationID {
			t.Fatalf("concurrent ID = %q, want persisted %q", state.InstallationID, persisted.InstallationID)
		}
	}
}

func TestPathFromEnvHonorsOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	t.Setenv(EnvPath, " "+path+" ")
	if got := PathFromEnv(); got != path {
		t.Fatalf("PathFromEnv() = %q, want %q", got, path)
	}
}

func TestLoadFileRejectsStateOthersCanRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	data, err := encode(mustNewState(t))
	if err != nil {
		t.Fatalf("encode() error = %v", err)
	}
	// 0644 on Unix; on Windows the directory's inherited DACL, which grants other principals access.
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // past the umask
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), fsperm.Requirement) {
		t.Fatalf("LoadFile() error = %v, want the %s refusal", err, fsperm.Requirement)
	}
}

// writePrivateFile writes a fixture the way EnsureFile writes state: private to its owner.
func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := fsperm.RestrictFile(file); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func writeState(t *testing.T, state State) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "installation.json")
	data, err := encode(state)
	if err != nil {
		t.Fatalf("encode() error = %v", err)
	}
	if err := writePrivateFile(path, data); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func mustNewState(t *testing.T) State {
	t.Helper()
	state, err := newState()
	if err != nil {
		t.Fatalf("newState() error = %v", err)
	}
	return state
}

func loadFileError(path string) error {
	_, err := LoadFile(path)
	return err
}
