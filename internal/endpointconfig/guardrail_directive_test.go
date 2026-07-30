package endpointconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

func guardrailResponse(t *testing.T, mode payloadcapture.Mode, enabled *bool) Response {
	t.Helper()
	config := Config{PayloadCaptureMode: mode, GuardrailLLMEnabled: enabled}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}

func boolPtr(value bool) *bool { return &value }

// A response that omits the flag must not undo a deliberate disable. This is the
// rollback case: the org turns the guardrail off, then a server build without the
// field answers, and resolving absence as enabled would quietly switch it back on
// with nobody told.
func TestOmittedDirectiveDoesNotClearAnExplicitDisable(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	now := time.Now().UTC()

	disable := guardrailResponse(t, payloadcapture.ModeSummary, boolPtr(false))
	if err := cache.Apply(FetchResult{Response: &disable, ETag: disable.ConfigIdentity}, now); err != nil {
		t.Fatalf("apply disable: %v", err)
	}
	directive := cache.Current().GuardrailLLMDirective
	if directive == nil || *directive {
		t.Fatalf("explicit disable not recorded: %v", directive)
	}

	// A later response says nothing about the guardrail at all.
	silent := guardrailResponse(t, payloadcapture.ModeFull, nil)
	if err := cache.Apply(FetchResult{Response: &silent, ETag: silent.ConfigIdentity}, now.Add(time.Minute)); err != nil {
		t.Fatalf("apply silent: %v", err)
	}
	snapshot := cache.Current()
	if snapshot.GuardrailLLMDirective == nil || *snapshot.GuardrailLLMDirective {
		t.Errorf("silence cleared the disable: %v", snapshot.GuardrailLLMDirective)
	}
	// The rest of the configuration must still track the new response.
	if snapshot.Config.PayloadCaptureMode != payloadcapture.ModeFull {
		t.Errorf("payload capture did not follow the new response: %q", snapshot.Config.PayloadCaptureMode)
	}
}

// Clearing a disable takes an explicit true. Silence is not a directive.
func TestExplicitEnableClearsADisable(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	now := time.Now().UTC()

	disable := guardrailResponse(t, payloadcapture.ModeSummary, boolPtr(false))
	if err := cache.Apply(FetchResult{Response: &disable, ETag: disable.ConfigIdentity}, now); err != nil {
		t.Fatalf("apply disable: %v", err)
	}
	enable := guardrailResponse(t, payloadcapture.ModeSummary, boolPtr(true))
	if err := cache.Apply(FetchResult{Response: &enable, ETag: enable.ConfigIdentity}, now.Add(time.Minute)); err != nil {
		t.Fatalf("apply enable: %v", err)
	}
	directive := cache.Current().GuardrailLLMDirective
	if directive == nil || !*directive {
		t.Errorf("explicit enable was not adopted: %v", directive)
	}
}

// The remembered directive has to survive a restart, since a kill switch that
// forgets on restart fails in the state it exists for.
func TestRememberedDirectiveSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	now := time.Now().UTC()

	first := NewCache(path)
	disable := guardrailResponse(t, payloadcapture.ModeSummary, boolPtr(false))
	if err := first.Apply(FetchResult{Response: &disable, ETag: disable.ConfigIdentity}, now); err != nil {
		t.Fatalf("apply disable: %v", err)
	}

	reloaded := NewCache(path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	directive := reloaded.Current().GuardrailLLMDirective
	if directive == nil || *directive {
		t.Errorf("disable did not survive the reload: %v", directive)
	}
}

// A cache written before the directive was remembered must still load, carrying
// no directive rather than failing.
func TestVersionOneCacheStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	response := testResponse(t, payloadcapture.ModeFull)
	writeCacheFileForTest(t, path, cacheFile{
		Version:   1,
		FetchedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Response:  &response,
	})

	cache := NewCache(path)
	if err := cache.Load(); err != nil {
		t.Fatalf("load version 1: %v", err)
	}
	if directive := cache.Current().GuardrailLLMDirective; directive != nil {
		t.Errorf("version 1 cache produced a directive: %v", *directive)
	}
}

func writeCacheFileForTest(t *testing.T, path string, file cacheFile) {
	t.Helper()
	encoded, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
