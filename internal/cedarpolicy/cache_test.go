package cedarpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
)

func TestCachePersistsDeploymentAndRestoresStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cedar-policy.json")
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	deployment := testDeployment(t, cedareval.RolloutModeObserve)
	cache := NewCache(path, time.Hour)
	cache.now = func() time.Time { return now }
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &deployment, ETag: deployment.DeploymentIdentity}, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %o", info.Mode().Perm())
	}

	restored := NewCache(path, time.Hour)
	restored.now = func() time.Time { return now.Add(time.Minute) }
	if err := restored.Load(); err != nil {
		t.Fatal(err)
	}
	snapshot := restored.Current()
	if snapshot.Deployment == nil || snapshot.LastKnownGood == nil || !snapshot.Status.Stale {
		t.Fatalf("restored snapshot = %#v", snapshot)
	}
}

func TestCacheRestoresVersionOneDeploymentDuringUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	now := time.Now().UTC()
	legacy := testLegacyDeployment(t, cedareval.RolloutModeEnforce)
	data, err := json.Marshal(legacyCacheFile{
		Version: 1, State: StateSuccess, FetchedAt: now.Format(time.RFC3339Nano), Deployment: &legacy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cache := NewCache(path, time.Hour)
	if err := cache.Load(); err != nil {
		t.Fatal(err)
	}
	snapshot := cache.Current()
	if snapshot.LegacyDeployment == nil || !DeploymentClaimsEnforce(snapshot) {
		t.Fatalf("legacy snapshot = %#v, want evaluable enforce deployment", snapshot)
	}
}

func TestCacheRejectsInvalidReplacementWithoutMutatingKnownGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	now := time.Now().UTC()
	cache := NewCache(path, time.Hour)
	good := testDeployment(t, cedareval.RolloutModeObserve)
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &good}, now); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.PolicySet.SourceHash = "invalid"
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &bad}, now.Add(time.Minute)); err == nil {
		t.Fatal("Apply() error = nil")
	}
	if got := cache.Current().Deployment; got == nil || got.DeploymentIdentity != good.DeploymentIdentity {
		t.Fatalf("known good changed: %#v", got)
	}
}

func TestCacheExplicitStateThenMatchingNotModifiedRestoresPolicy(t *testing.T) {
	tests := []struct {
		name     string
		response StateResponse
	}{
		{name: "disabled", response: StateResponse{ResponseVersion: ResponseVersion, RequestContractVersion: RequestContractVersion, State: StateDisabled, RolloutMode: "disabled"}},
		{name: "no active policy", response: StateResponse{ResponseVersion: ResponseVersion, RequestContractVersion: RequestContractVersion, State: StateNoActivePolicy}},
		{name: "principal unavailable", response: StateResponse{ResponseVersion: ResponseVersion, RequestContractVersion: RequestContractVersion, State: StatePrincipalUnavailable}},
		{name: "unauthorized", response: StateResponse{ResponseVersion: ResponseVersion, RequestContractVersion: RequestContractVersion, State: StateUnauthorized}},
		{name: "unsupported version", response: StateResponse{
			ResponseVersion:                  1,
			RequestContractVersion:           1,
			State:                            StateUnsupportedVersion,
			SupportedResponseVersions:        []int{1, ResponseVersion},
			SupportedRequestContractVersions: []int{1, RequestContractVersion},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			cache := NewCache(filepath.Join(t.TempDir(), "cache.json"), time.Hour)
			good := testDeployment(t, cedareval.RolloutModeObserve)
			if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &good}, now); err != nil {
				t.Fatal(err)
			}
			if err := cache.Apply(FetchResult{State: test.response.State, Response: &test.response}, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if got := cache.Current(); got.Deployment != nil || got.LastKnownGood == nil || got.State != test.response.State {
				t.Fatalf("non-ready snapshot = %#v", got)
			}
			if err := cache.Apply(FetchResult{State: StateNotModified, ETag: good.DeploymentIdentity}, now.Add(2*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if got := cache.Current(); got.Deployment == nil || got.State != StateSuccess || got.Deployment.DeploymentIdentity != good.DeploymentIdentity {
				t.Fatalf("restored snapshot = %#v", got)
			}
		})
	}
}

func TestCacheUnavailableThenMatchingNotModifiedKeepsPolicy(t *testing.T) {
	now := time.Now().UTC()
	cache := NewCache(filepath.Join(t.TempDir(), "cache.json"), time.Hour)
	good := testDeployment(t, cedareval.RolloutModeObserve)
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &good}, now); err != nil {
		t.Fatal(err)
	}
	cache.MarkFailed(errors.New("temporarily unavailable"), now.Add(time.Minute))
	if err := cache.Apply(FetchResult{State: StateNotModified, ETag: good.DeploymentIdentity}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := cache.Current(); got.Deployment == nil || got.State != StateSuccess || got.Status.Stale {
		t.Fatalf("restored snapshot = %#v", got)
	}
}

func TestCacheKeepsValidPolicyWhileOffline(t *testing.T) {
	now := time.Now().UTC()
	cache := NewCache(filepath.Join(t.TempDir(), "cache.json"), 10*time.Minute)
	cache.now = func() time.Time { return now }
	good := testDeployment(t, cedareval.RolloutModeEnforce)
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &good}, now); err != nil {
		t.Fatal(err)
	}
	cache.now = func() time.Time { return now.Add(11 * time.Minute) }
	snapshot := cache.Current()
	if snapshot.Deployment == nil || snapshot.LastKnownGood == nil || snapshot.Status.Expired {
		t.Fatalf("offline snapshot = %#v", snapshot)
	}
}

func TestCacheCorruptPersistedFileDoesNotLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"state":"success"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := NewCache(path, time.Hour)
	if err := cache.Load(); err == nil {
		t.Fatal("Load() error = nil")
	} else {
		cache.MarkInvalid(err)
	}
	if snapshot := cache.Current(); snapshot.Deployment != nil || !snapshot.Status.Invalid {
		t.Fatalf("corrupt cache snapshot = %#v", snapshot)
	}
}

// A daemon restart after a CLI or cloud upgrade must keep enforcing the
// persisted policy even when its tool catalog digest no longer matches this
// binary: the skew is flagged, not turned into a load failure that would
// either deny every hook or drop the enforce claim.
func TestCacheLoadsEnforcingDeploymentWhenCatalogChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	now := time.Now().UTC()
	deployment := testDeployment(t, cedareval.RolloutModeEnforce)
	deployment.ToolCatalogDigest = strings.Repeat("0", 64)
	deployment.DeploymentIdentity = testDeploymentIdentity(t, deployment)
	data, err := json.Marshal(cacheFile{Version: cacheFileVersion, State: StateSuccess, FetchedAt: now.Format(time.RFC3339Nano), Deployment: &deployment})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cache := NewCache(path, time.Hour)
	if err := cache.Load(); err != nil {
		t.Fatalf("Load() error = %v, want catalog skew tolerated", err)
	}
	snapshot := cache.Current()
	if snapshot.Deployment == nil || snapshot.Deployment.DeploymentIdentity != deployment.DeploymentIdentity {
		t.Fatalf("snapshot = %#v, want the persisted deployment active", snapshot)
	}
	if !snapshot.PersistedEnforce || !DeploymentClaimsEnforce(snapshot) {
		t.Fatalf("snapshot = %#v, want persisted enforce claim", snapshot)
	}
	if snapshot.Status.Invalid || !snapshot.Status.Stale || !snapshot.Status.CatalogMismatch {
		t.Fatalf("status = %#v, want stale catalog-mismatch without invalid", snapshot.Status)
	}
	if !strings.Contains(snapshot.Status.LastError, "tool catalog") {
		t.Fatalf("LastError = %q, want catalog skew explanation", snapshot.Status.LastError)
	}
}

func TestCacheApplyFlagsCatalogMismatchWithoutRejecting(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "cache.json"), time.Hour)
	deployment := testDeployment(t, cedareval.RolloutModeEnforce)
	deployment.ToolCatalogDigest = strings.Repeat("0", 64)
	deployment.DeploymentIdentity = testDeploymentIdentity(t, deployment)
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &deployment}, time.Now().UTC()); err != nil {
		t.Fatalf("Apply() error = %v, want skewed catalog accepted", err)
	}
	snapshot := cache.Current()
	if snapshot.Deployment == nil || !snapshot.Status.CatalogMismatch || snapshot.Status.Stale {
		t.Fatalf("snapshot = %#v, want active deployment flagged as catalog mismatch", snapshot)
	}

	matching := testDeployment(t, cedareval.RolloutModeEnforce)
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &matching}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if status := cache.Current().Status; status.CatalogMismatch {
		t.Fatalf("status = %#v, want mismatch cleared by a matching deployment", status)
	}
}

func TestCacheStillRejectsCorruptDeploymentWithSkewedCatalog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	deployment := testDeployment(t, cedareval.RolloutModeEnforce)
	deployment.ToolCatalogDigest = strings.Repeat("0", 64)
	deployment.PolicySet.Source += " forbid(principal, action, resource);"
	data, err := json.Marshal(cacheFile{Version: cacheFileVersion, State: StateSuccess, FetchedAt: time.Now().UTC().Format(time.RFC3339Nano), Deployment: &deployment})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := NewCache(path, time.Hour)
	if err := cache.Load(); err == nil {
		t.Fatal("Load() error = nil, want tampered policy rejected")
	} else {
		cache.MarkInvalid(err)
	}
	if snapshot := cache.Current(); snapshot.Deployment != nil || !snapshot.Status.Invalid || !snapshot.PersistedEnforce {
		t.Fatalf("snapshot = %#v, want invalid cache that still claims enforce", snapshot)
	}
}

func TestRefresherMarksFailureWithoutDroppingKnownGood(t *testing.T) {
	now := time.Now().UTC()
	cache := NewCache(filepath.Join(t.TempDir(), "cache.json"), time.Hour)
	good := testDeployment(t, cedareval.RolloutModeObserve)
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &good}, now); err != nil {
		t.Fatal(err)
	}
	refresher := Refresher{
		Cache: cache,
		TokenSource: func(context.Context) (string, error) {
			return "", errors.New("token unavailable")
		},
	}
	if err := refresher.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil")
	}
	if snapshot := cache.Current(); snapshot.Deployment == nil || !snapshot.Status.Stale {
		t.Fatalf("failed refresh discarded known good: %#v", snapshot)
	}
}

func TestRefresherRecordsCacheApplyFailure(t *testing.T) {
	now := time.Now().UTC()
	notDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDirectory, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := NewCache(filepath.Join(notDirectory, "cache.json"), time.Hour)
	state := StateResponse{
		ResponseVersion:        ResponseVersion,
		RequestContractVersion: RequestContractVersion,
		State:                  StateDisabled,
		RolloutMode:            "disabled",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	refresher := Refresher{
		Client:         client,
		Cache:          cache,
		InstallationID: testInstallationID,
		Now:            func() time.Time { return now },
		TokenSource: func(context.Context) (string, error) {
			return "token", nil
		},
	}
	if err := refresher.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil, want cache persistence failure")
	}
	snapshot := cache.Current()
	if !snapshot.Status.Stale || snapshot.Status.LastError == "" || !snapshot.Status.LastAttemptAt.Equal(now) {
		t.Fatalf("failed apply status = %#v", snapshot.Status)
	}
}

func TestRefresherRunStopsOnCancellation(t *testing.T) {
	cache := NewCache("", time.Hour)
	refresher := Refresher{
		Cache:    cache,
		Interval: time.Hour,
		TokenSource: func(context.Context) (string, error) {
			return "", errors.New("token unavailable")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		refresher.Run(ctx)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after cancellation")
	}
}
