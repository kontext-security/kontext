package managedobserve

import (
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthErrorRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	if got := LoadAuthError(dbPath); got != nil {
		t.Fatalf("LoadAuthError before write = %v, want nil", got)
	}

	if err := WriteAuthError(dbPath, http.StatusUnauthorized); err != nil {
		t.Fatal(err)
	}
	got := LoadAuthError(dbPath)
	if got == nil || got.Status != http.StatusUnauthorized || got.Kind != "auth" || got.At == "" {
		t.Fatalf("LoadAuthError = %+v", got)
	}

	if err := ClearAuthError(dbPath); err != nil {
		t.Fatal(err)
	}
	if got := LoadAuthError(dbPath); got != nil {
		t.Fatalf("LoadAuthError after clear = %v, want nil", got)
	}
	// Clearing again is a no-op.
	if err := ClearAuthError(dbPath); err != nil {
		t.Fatal(err)
	}
}

func TestStartupErrorRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "guard.db") // dir created on demand

	if err := WriteStartupError(dbPath, "resolve install token: keychain locked"); err != nil {
		t.Fatal(err)
	}
	got := LoadAuthError(dbPath)
	if got == nil || got.Kind != "startup" || got.Message == "" || got.At == "" {
		t.Fatalf("LoadAuthError = %+v", got)
	}

	if err := ClearAuthError(dbPath); err != nil {
		t.Fatal(err)
	}
	if LoadAuthError(dbPath) != nil {
		t.Fatal("startup breadcrumb not cleared")
	}
}

func TestClearAuthErrorSurfacesRemoveFailure(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "guard.db")
	breadcrumbPath := AuthErrorPath(dbPath)
	if err := os.Mkdir(breadcrumbPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(breadcrumbPath, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ClearAuthError(dbPath); err == nil {
		t.Fatal("ClearAuthError() error = nil, want remove failure")
	}
}

func TestLoadAuthErrorToleratesCorruptBreadcrumb(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	if err := os.WriteFile(AuthErrorPath(dbPath), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Doctor reporting must never fail on a corrupt file, and must not turn a
	// local breadcrumb problem into a false revoked-token warning.
	if got := LoadAuthError(dbPath); got == nil || got.Kind != authErrorKindCorrupt || got.Message == "" {
		t.Fatalf("LoadAuthError(corrupt) = %+v", got)
	}
}

// The daemon replaces the breadcrumb while doctor reads it. On Windows a file
// that is open cannot be replaced, and one that is being replaced cannot be
// opened, for a moment each. Neither may show as a lost write or as a corrupt
// breadcrumb.
func TestAuthErrorReadWhileItIsReplaced(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	if err := WriteAuthError(dbPath, http.StatusUnauthorized); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	writeErr := make(chan error, 1)
	go func() {
		for !stop.Load() {
			if err := WriteAuthError(dbPath, http.StatusUnauthorized); err != nil {
				writeErr <- err
				return
			}
			// The daemon writes the breadcrumb now and then, not in a loop
			// that never lets go of it.
			time.Sleep(time.Millisecond)
		}
		writeErr <- nil
	}()
	reads := 0
	for end := time.Now().Add(500 * time.Millisecond); time.Now().Before(end); reads++ {
		if got := LoadAuthError(dbPath); got == nil || got.Kind != "auth" || got.Status != http.StatusUnauthorized {
			stop.Store(true)
			<-writeErr
			t.Fatalf("read %d while the breadcrumb was being replaced = %+v, want the auth breadcrumb", reads, got)
		}
	}
	stop.Store(true)
	if err := <-writeErr; err != nil {
		t.Fatalf("a replacement failed while the breadcrumb was being read: %v", err)
	}
}
