package endpointconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/payloadcapture"
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
	directive := cache.Current().Configured.GuardrailLLMEnabled
	if directive == nil || *directive {
		t.Errorf("rejected response disturbed the disable: %v", directive)
	}
}

// An older response version is discarded without failing cache load.
func TestOlderResponseVersionIsDiscarded(t *testing.T) {
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
	if snapshot.Confirmed {
		t.Error("a discarded cache must not read as confirmed")
	}
}

// Version one cache files must still load.
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
	if cache.Current().Configured.PayloadCaptureMode != payloadcapture.ModeFull {
		t.Error("version 1 cache lost its configured capture mode")
	}
}

// Existing cache files may contain the retired directive beside the response.
func TestLegacyDirectiveCacheLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	now := time.Now().UTC()

	response := guardrailResponse(t, payloadcapture.ModeSummary, boolPtr(false))
	writeCacheFileForTest(t, path, cacheFile{
		Version:               cacheFileVersion,
		FetchedAt:             now.Format(time.RFC3339Nano),
		Response:              &response,
		GuardrailLLMDirective: boolPtr(false),
	})

	reloaded := NewCache(path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	directive := reloaded.Current().Configured.GuardrailLLMEnabled
	if directive == nil || *directive {
		t.Errorf("stored contract value did not survive the reload: %v", directive)
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
