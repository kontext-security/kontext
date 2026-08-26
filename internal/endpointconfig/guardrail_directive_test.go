package endpointconfig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func guardrailResponse(t *testing.T, mode payloadcapture.Mode, enabled *bool) Response {
	t.Helper()
	promptPolicyEnabled := false
	config := Config{PayloadCaptureMode: mode, GuardrailLLMEnabled: enabled, PromptPolicyEnabled: &promptPolicyEnabled}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}

func boolPtr(value bool) *bool { return &value }

func TestPromptPolicyDirectiveSurvivesRefreshFailure(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	now := time.Now().UTC()
	response := guardrailResponse(t, payloadcapture.ModeSummary, boolPtr(true))
	response.Config.PromptPolicyEnabled = boolPtr(true)
	identity, err := ComputeIdentity(response.Config)
	if err != nil {
		t.Fatal(err)
	}
	response.ConfigIdentity = identity
	if err := cache.Apply(FetchResult{Response: &response, ETag: identity}, now); err != nil {
		t.Fatal(err)
	}
	cache.MarkFailed(errors.New("offline"), now.Add(time.Minute))
	directive := cache.Current().PromptPolicyDirective
	if directive == nil || !*directive {
		t.Fatalf("prompt-policy barrier failed open after refresh failure: %v", directive)
	}
}

// Under v2 the flag is required, so the rollback case that motivated remembering
// it cannot even reach the cache: a response without the flag is rejected rather
// than resolved as enabled. This is the contract-level version of that guarantee.
func TestResponseWithoutTheFlagIsRejected(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	now := time.Now().UTC()

	disable := guardrailResponse(t, payloadcapture.ModeSummary, boolPtr(false))
	if err := cache.Apply(FetchResult{Response: &disable, ETag: disable.ConfigIdentity}, now); err != nil {
		t.Fatalf("apply disable: %v", err)
	}

	silent := Response{
		ResponseVersion: ResponseVersion,
		Config:          Config{PayloadCaptureMode: payloadcapture.ModeFull},
		ConfigIdentity:  disable.ConfigIdentity,
	}
	if err := cache.Apply(FetchResult{Response: &silent, ETag: silent.ConfigIdentity}, now.Add(time.Minute)); err == nil {
		t.Fatal("a response without the guardrail flag was accepted")
	}

	// And the disable is untouched by the rejected attempt.
	directive := cache.Current().GuardrailLLMDirective
	if directive == nil || *directive {
		t.Errorf("rejected response disturbed the disable: %v", directive)
	}
}

// The remembered directive also has to survive a response-version upgrade. A
// cache written under an older version cannot be revalidated — its identity was
// computed over a different preimage — so it is discarded, and without the
// remembered value a deliberate disable would be lost at exactly that moment.
func TestRememberedDirectiveSurvivesAResponseVersionUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	stale := guardrailResponse(t, payloadcapture.ModeSummary, boolPtr(false))
	stale.ResponseVersion = ResponseVersion - 1
	writeCacheFileForTest(t, path, cacheFile{
		Version:               cacheFileVersion,
		FetchedAt:             time.Now().UTC().Format(time.RFC3339Nano),
		Response:              &stale,
		GuardrailLLMDirective: boolPtr(false),
	})

	cache := NewCache(path)
	if err := cache.Load(); err != nil {
		t.Fatalf("load across a version upgrade should not fail: %v", err)
	}
	snapshot := cache.Current()
	if snapshot.GuardrailLLMDirective == nil || *snapshot.GuardrailLLMDirective {
		t.Errorf("disable lost across the upgrade: %v", snapshot.GuardrailLLMDirective)
	}
	if snapshot.Confirmed {
		t.Error("a discarded cache must not read as confirmed")
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
