package endpointconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func workTypeResponse(t *testing.T, mode payloadcapture.Mode, enabled *bool) Response {
	t.Helper()
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: enabled, ToolOutputCompaction: boolPtr(false), CodexProxy: boolPtr(true)}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}

func boolPtr(value bool) *bool { return &value }

// The switch is required under v5: a response without it is rejected rather
// than resolved either way, and leaves the confirmed value untouched.
func TestResponseWithoutTheSwitchIsRejected(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	now := time.Now().UTC()

	off := workTypeResponse(t, payloadcapture.ModeSummary, boolPtr(false))
	if err := cache.Apply(FetchResult{Response: &off, ETag: off.ConfigIdentity}, now); err != nil {
		t.Fatalf("apply switch off: %v", err)
	}

	silent := Response{
		ResponseVersion: ResponseVersion,
		Config:          Config{PayloadCaptureMode: payloadcapture.ModeFull, ToolOutputCompaction: boolPtr(false), CodexProxy: boolPtr(true)},
		ConfigIdentity:  off.ConfigIdentity,
	}
	if err := cache.Apply(FetchResult{Response: &silent, ETag: silent.ConfigIdentity}, now.Add(time.Minute)); err == nil {
		t.Fatal("a response without the work-type switch was accepted")
	}

	snapshot := cache.Current()
	if snapshot.Configured.WorkTypeClassification == nil || snapshot.Config.WorkTypeClassificationEnabled() {
		t.Errorf("rejected response disturbed the switch: %+v", snapshot.Configured)
	}
}

// The switch stays off until a directive is validated. A validated cache
// preserves the same directive across restarts.
func TestWorkTypeSwitchOffUntilConfirmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	cache := NewCache(path)
	if cache.Current().Config.WorkTypeClassificationEnabled() {
		t.Fatal("switch on without any directive")
	}
	on := workTypeResponse(t, payloadcapture.ModeSummary, boolPtr(true))
	if err := cache.Apply(FetchResult{Response: &on, ETag: on.ConfigIdentity}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if !cache.Current().Config.WorkTypeClassificationEnabled() {
		t.Fatal("confirmed switch-on not applied")
	}
	reloaded := NewCache(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	snapshot := reloaded.Current()
	if !snapshot.Config.WorkTypeClassificationEnabled() || !snapshot.Confirmed || !snapshot.Status.Stale {
		t.Fatalf("a validated directive must remain effective across restarts: %+v", snapshot)
	}
}

// A cache persisted by an earlier build holds a config shape the strict
// decoder would reject: v2's retired guardrail flag, or v3 without the
// compaction switch. It is discarded, not reported invalid.
func TestPreviousVersionCacheIsDiscarded(t *testing.T) {
	fetchedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for name, cached := range map[string]string{
		"v2": `{"version":2,"fetchedAt":"` + fetchedAt + `","response":{"responseVersion":2,` +
			`"config":{"payloadCaptureMode":"full","guardrailLlmEnabled":false},"configIdentity":"` + strings.Repeat("a", 64) + `"},"guardrailLlmDirective":false}`,
		"v3": `{"version":2,"fetchedAt":"` + fetchedAt + `","response":{"responseVersion":3,` +
			`"config":{"payloadCaptureMode":"full","workTypeClassification":true},"configIdentity":"` + strings.Repeat("a", 64) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "endpoint-config.json")
			if err := os.WriteFile(path, []byte(cached), 0o600); err != nil {
				t.Fatal(err)
			}

			cache := NewCache(path)
			if err := cache.Load(); err != nil {
				t.Fatalf("load across a version upgrade should not fail: %v", err)
			}
			snapshot := cache.Current()
			if snapshot.Confirmed || snapshot.Status.Invalid || snapshot.LastKnownGood != nil {
				t.Errorf("a discarded cache must read as unconfirmed, valid and empty: %+v", snapshot)
			}
			if snapshot.Config.PayloadCaptureMode != payloadcapture.ModeSummary || snapshot.Config.WorkTypeClassificationEnabled() || snapshot.Config.ToolOutputCompactionEnabled() {
				t.Errorf("discarded cache must leave the privacy-safe default: %+v", snapshot.Config)
			}
		})
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
	response := workTypeResponse(t, payloadcapture.ModeSummary, boolPtr(false))
	writeCacheFileForTest(t, path, cacheFile{
		Version:               cacheFileVersion,
		FetchedAt:             time.Now().UTC().Format(time.RFC3339Nano),
		Response:              &response,
		GuardrailLLMDirective: boolPtr(false),
	})

	reloaded := NewCache(path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	directive := reloaded.Current().Configured.WorkTypeClassification
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

// A cache holding the fallback version's response loads like one of
// ResponseVersion: its identity is the conditional value for a server that
// still predates v5.
func TestFallbackVersionCacheLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	response := fallbackResponse(t, payloadcapture.ModeFull, true)
	writeCacheFileForTest(t, path, cacheFile{
		Version:   cacheFileVersion,
		FetchedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Response:  &response,
	})
	cache := NewCache(path)
	if err := cache.Load(); err != nil {
		t.Fatal(err)
	}
	if snapshot := cache.Current(); !snapshot.Confirmed || !snapshot.Status.Stale || snapshot.Status.Invalid || snapshot.LastKnownGood == nil {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if cache.ConditionalIdentity() != response.ConfigIdentity {
		t.Fatalf("conditional identity = %q", cache.ConditionalIdentity())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "codexProxy") {
		t.Fatalf("a v4 response was saved with the Codex proxy switch: %s", data)
	}
}
