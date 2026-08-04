package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/managedobserve"
	"github.com/kontext-security/kontext-cli/internal/setup"
)

// The `--json` outputs are consumed by tooling built OUTSIDE this repository, so
// their key sets are pinned here.
//
// These tests exist because relying on "both sides live in one repo" did not
// work: `allow_http_loopback` was added to the doctor report and the consumer's
// model silently never decoded it. Nothing failed — decoders are lenient by
// design, so a missing field is invisible. A pinned key set turns that into a
// failing test at the moment the field changes.
//
// Values are deliberately not pinned: paths, pids, and versions are all
// machine-specific. The SHAPE is the contract.
//
// To change a contract: update the golden file in the same commit, and treat it
// as a breaking change for consumers unless the change is purely additive.

// keysOf marshals v and returns its top-level JSON keys, sorted.
func keysOf(t *testing.T, v any) []string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := make([]string, 0, len(decoded))
	for key := range decoded {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func compareWithGolden(t *testing.T, name string, keys []string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	got := strings.Join(keys, "\n") + "\n"

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\n\nIf this contract is new, create it with:\n  UPDATE_GOLDEN=1 go test ./cmd/kontext/ -run JSONContract", path, err)
	}
	if got != string(want) {
		t.Errorf(`%s JSON contract changed.

got:
%s
want:
%s
This output is consumed by tooling outside this repository (docs/json-contract.md).
If the change is intended, update the golden file in the same commit:
  UPDATE_GOLDEN=1 go test ./cmd/kontext/ -run JSONContract
and note whether it is additive (safe) or breaking (consumers need updating).`,
			name, got, want)
	}
}

// fullyPopulatedReport sets every field, so `omitempty` cannot hide part of the
// surface from the contract.
func fullyPopulatedReport() managedobserve.Report {
	age := 12.5
	pending := 7
	return managedobserve.Report{
		Healthy:              true,
		Configured:           true,
		SelfServe:            true,
		Repairable:           true,
		ActiveProfile:        "staging",
		LegacyInstall:        true,
		ConfigPath:           "/path/to/managed.json",
		ConfigScope:          "user",
		CloudURL:             "https://api.kontext.security",
		Mode:                 "remote",
		AllowHTTPLoopback:    true,
		InstallationID:       "ins_example",
		InstallTokenReadable: true,
		DaemonRunning:        true,
		DaemonVersion:        "1.2.3",
		DaemonPID:            4242,
		InstalledVersion:     "1.2.3",
		HeartbeatAgeSeconds:  &age,
		ExportPending:        &pending,
		Warnings:             []string{"example warning"},
	}
}

func TestDoctorJSONContract(t *testing.T) {
	payload := doctorJSONPayload{
		Report:              fullyPopulatedReport(),
		ManagedHooksHealthy: true,
		LocalHooksHealthy:   true,
	}
	compareWithGolden(t, "doctor-json-keys.txt", keysOf(t, payload))
}

func TestProfileListJSONContract(t *testing.T) {
	inventory := setup.Inventory{
		Active:        "staging",
		LegacyInstall: true,
		Profiles:      []setup.ProfileStatus{},
	}
	compareWithGolden(t, "profile-ls-json-keys.txt", keysOf(t, inventory))
}

func TestProfileStatusJSONContract(t *testing.T) {
	status := setup.ProfileStatus{
		Name:             "staging",
		Active:           true,
		CloudURL:         "https://api.staging.kontext.security",
		Mode:             "remote",
		Workspace:        "Acme Corp (org_1)",
		OrganizationName: "Acme Corp",
		OrganizationID:   "org_1",
		InstallTokenRef:  "keychain:kontext-install-token.staging",
		InstallationID:   "ins_example",
		Error:            "example error",
	}
	compareWithGolden(t, "profile-status-json-keys.txt", keysOf(t, status))
}

// The doctor payload embeds Report, so a field added to Report appears in the
// payload automatically. Assert that explicitly: it is the mechanism by which a
// change in one package alters a contract documented in another.
func TestDoctorPayloadIncludesEveryReportField(t *testing.T) {
	reportKeys := keysOf(t, fullyPopulatedReport())
	payloadKeys := keysOf(t, doctorJSONPayload{Report: fullyPopulatedReport()})

	inPayload := map[string]bool{}
	for _, key := range payloadKeys {
		inPayload[key] = true
	}
	for _, key := range reportKeys {
		if !inPayload[key] {
			t.Errorf("Report field %q does not reach the doctor JSON payload", key)
		}
	}
}
