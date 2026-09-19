package managedstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestFlushReportsCLIVersionOnLedgerBatchesAndHeartbeats(t *testing.T) {
	for _, ledger := range []bool{false, true} {
		name := "heartbeat"
		if ledger {
			name = "ledger"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				cli        string
				deployment string
				wantCLI    string
			}{
				{name: "release alone", cli: " 1.5.2 ", wantCLI: "1.5.2"},
				{name: "self-serve install", cli: "1.5.2", deployment: "cli-1.5.2", wantCLI: "1.5.2"},
				{name: "development build", cli: "dev", deployment: "1.5.1", wantCLI: "dev"},
				{name: "missing version", deployment: "1.5.1"},
				{name: "blank version", cli: " \t\n", deployment: "1.5.1"},
				{name: "no device facts"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					store, dbPath := testStore(t)
					if ledger {
						saveTestDecision(t, store, "session-version", "tool-version")
					}
					type wirePayload struct {
						Device  map[string]string `json:"device"`
						Actions []json.RawMessage `json:"authorization_actions"`
					}
					requests := make(chan wirePayload, 1)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						var payload wirePayload
						if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
							t.Errorf("decode batch: %v", err)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						requests <- payload
						w.WriteHeader(http.StatusAccepted)
					}))
					t.Cleanup(server.Close)

					if err := Flush(context.Background(), Options{
						DBPath:            dbPath,
						StatePath:         filepath.Join(t.TempDir(), "stream-state.json"),
						CloudURL:          server.URL,
						InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
						InstallToken:      "test-install-token",
						CLIVersion:        tc.cli,
						DeploymentVersion: func() string { return tc.deployment },
						HTTPClient:        server.Client(),
					}); err != nil {
						t.Fatalf("Flush() error = %v", err)
					}
					var got wirePayload
					select {
					case got = <-requests:
					default:
						t.Fatal("Flush() did not post a batch")
					}
					if (len(got.Actions) > 0) != ledger {
						t.Fatalf("actions = %d, want ledger batch: %t", len(got.Actions), ledger)
					}
					if value, present := got.Device["cli_version"]; value != tc.wantCLI || present != (tc.wantCLI != "") {
						t.Fatalf("cli_version = %q (present %t), want %q (present %t)", value, present, tc.wantCLI, tc.wantCLI != "")
					}
					if got.Device["deployment_version"] != tc.deployment {
						t.Fatalf("deployment_version = %q, want %q", got.Device["deployment_version"], tc.deployment)
					}
					if tc.wantCLI == "" && tc.deployment == "" && got.Device != nil {
						t.Fatalf("device = %+v, want omitted", got.Device)
					}
				})
			}
		})
	}
}
