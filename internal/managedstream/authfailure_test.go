package managedstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

// A store with one decision so every Flush actually posts — an empty store
// short-circuits before hitting the server, which would reset the
// auth-failure counter without exercising it.
func seededStore(t *testing.T) string {
	t.Helper()
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "sess-auth-test", "tool-use-auth-test")
	return dbPath
}

func TestFlushDoesNotFireOnFlushSuccessWithoutPosting(t *testing.T) {
	// An empty flush never contacts the server and therefore proves nothing
	// about the token — it must not clear a "token rejected" breadcrumb on an
	// idle machine whose token is still revoked.
	_, dbPath := testStore(t)
	statePath := filepath.Join(filepath.Dir(dbPath), "state.json")
	if err := SaveState(statePath, State{
		LastHeartbeatAttemptAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	fired := false
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       "https://unreachable.invalid",
		InstallationID: "ins_test",
		InstallToken:   "any",
		Diagnostic:     diagnostic.New(nil, false),
		OnFlushSuccess: func() { fired = true },
	})
	if err != nil {
		t.Fatalf("Flush(empty store) error = %v", err)
	}
	if fired {
		t.Fatal("OnFlushSuccess fired for an empty flush that never posted")
	}
}

func TestAuthFailureStatusReportsHostedAuthError(t *testing.T) {
	dbPath := seededStore(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(filepath.Dir(dbPath), "state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_test",
		InstallToken:   "revoked-token",
		HTTPClient:     server.Client(),
		Diagnostic:     diagnostic.New(nil, false),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted auth error")
	}
	status, ok := AuthFailureStatus(err)
	if !ok || status != http.StatusUnauthorized {
		t.Fatalf("AuthFailureStatus() = %d, %v; want 401, true", status, ok)
	}
}

func TestShouldReportAuthFailureThreshold(t *testing.T) {
	if ShouldReportAuthFailure(authFailureThreshold - 1) {
		t.Fatal("reported before auth failure threshold")
	}
	if !ShouldReportAuthFailure(authFailureThreshold) {
		t.Fatal("did not report at auth failure threshold")
	}
	if !ShouldReportAuthFailure(authFailureRefire) {
		t.Fatal("did not report at auth failure refire interval")
	}
}
