package cedarpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/diagnostic"
)

func unauthorizedRefresher(t *testing.T, cache *Cache, fetches *atomic.Int64) *Refresher {
	t.Helper()
	return refresherReplying(t, cache, fetches, func() int { return http.StatusUnauthorized })
}

func refresherReplying(t *testing.T, cache *Cache, fetches *atomic.Int64, reply func() int) *Refresher {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fetches != nil {
			fetches.Add(1)
		}
		if status := reply(); status == http.StatusNotModified {
			w.Header().Set("ETag", `"`+cache.ConditionalIdentity()+`"`)
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"responseVersion":2,"requestContractVersion":2,"state":"unauthorized"}`))
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return &Refresher{
		Client:         client,
		Cache:          cache,
		InstallationID: testInstallationID,
		TokenSource:    func(context.Context) (string, error) { return "token", nil },
	}
}

func enforcingCache(t *testing.T, path string, at time.Time) *Cache {
	t.Helper()
	cache := NewCache(path, time.Hour)
	good := testDeployment(t, cedareval.RolloutModeEnforce)
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &good}, at); err != nil {
		t.Fatal(err)
	}
	return cache
}

func TestHeldUnauthorizedReportsAFailedRefreshAndTheDropIsNamed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	fetchedAt := time.Date(2026, 11, 8, 8, 0, 0, 0, time.UTC)
	attemptAt := fetchedAt.Add(time.Minute)
	cache := enforcingCache(t, path, fetchedAt)
	var log bytes.Buffer
	refresher := unauthorizedRefresher(t, cache, nil)
	refresher.Now = func() time.Time { return attemptAt }
	refresher.Diagnostic = diagnostic.New(&log, true)

	if err := refresher.Refresh(context.Background()); !errors.Is(err, errUnauthorizedHeld) {
		t.Fatalf("Refresh() error = %v, want a held 401", err)
	}
	snapshot := cache.Current()
	if snapshot.Deployment == nil || snapshot.State != StateSuccess || !snapshot.Status.Stale ||
		!strings.Contains(snapshot.Status.LastError, "1 of 3") ||
		!snapshot.Status.FetchedAt.Equal(fetchedAt) || !snapshot.Status.LastAttemptAt.Equal(attemptAt) {
		t.Fatalf("held snapshot = %#v, want the policy kept and a failed refresh recorded", snapshot)
	}

	if err := refresher.Refresh(context.Background()); !errors.Is(err, errUnauthorizedHeld) {
		t.Fatalf("Refresh() error = %v, want a held 401", err)
	}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v, want the drop applied", err)
	}
	snapshot = cache.Current()
	if snapshot.Deployment != nil || snapshot.LastKnownGood == nil || snapshot.State != StateUnauthorized ||
		snapshot.Status.Stale || snapshot.Status.LastError != "" {
		t.Fatalf("dropped snapshot = %#v", snapshot)
	}
	if text := log.String(); !strings.Contains(text, "dropped the cached policy") || strings.Contains(text, "recovered") {
		t.Fatalf("log = %q, want the drop named and no recovery claimed", text)
	}
	if _, err := os.Stat(path + ".unauthorized"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("count file after the drop: err = %v, want it removed", err)
	}
}

func TestUnauthorizedWithNoActivePolicyAppliesAtOnce(t *testing.T) {
	now := time.Now().UTC()
	t.Run("empty cache", func(t *testing.T) {
		cache := NewCache(filepath.Join(t.TempDir(), "cache.json"), time.Hour)
		if err := unauthorizedRefresher(t, cache, nil).Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		if state := cache.Current().State; state != StateUnauthorized {
			t.Fatalf("state = %q", state)
		}
	})
	t.Run("last good retained but not active", func(t *testing.T) {
		cache := enforcingCache(t, filepath.Join(t.TempDir(), "cache.json"), now)
		response := StateResponse{ResponseVersion: ResponseVersion, RequestContractVersion: RequestContractVersion, State: StateNoActivePolicy}
		if err := cache.Apply(FetchResult{State: StateNoActivePolicy, Response: &response}, now); err != nil {
			t.Fatal(err)
		}
		if err := unauthorizedRefresher(t, cache, nil).Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		if state := cache.Current().State; state != StateUnauthorized {
			t.Fatalf("state = %q", state)
		}
	})
}

func TestHeldUnauthorizedProtectsALegacyPolicyAndItsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	legacy := testLegacyDeployment(t, cedareval.RolloutModeEnforce)
	data, err := json.Marshal(legacyCacheFile{Version: 1, State: StateSuccess, FetchedAt: time.Now().UTC().Format(time.RFC3339Nano), Deployment: &legacy})
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
	var status atomic.Int64
	status.Store(http.StatusUnauthorized)
	refresher := refresherReplying(t, cache, nil, func() int { return int(status.Load()) })
	for range 2 {
		if err := refresher.Refresh(context.Background()); !errors.Is(err, errUnauthorizedHeld) {
			t.Fatalf("Refresh() error = %v, want a held 401", err)
		}
	}
	if cache.Current().LegacyDeployment == nil {
		t.Fatal("held 401 dropped the legacy policy")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, after) {
		t.Fatal("held 401 rewrote the legacy cache file")
	}

	// Apply can't install a 304 for a legacy policy, but the read was still valid.
	status.Store(http.StatusNotModified)
	_ = refresher.Refresh(context.Background())
	status.Store(http.StatusUnauthorized)
	err = refresher.Refresh(context.Background())
	if !errors.Is(err, errUnauthorizedHeld) || !strings.Contains(err.Error(), "1 of 3") {
		t.Fatalf("Refresh() error = %v, want a new streak at 1 of 3", err)
	}
}

// A drop that can't be written keeps the policy, and the next 401 must try again.
func TestUnauthorizedDropIsRetriedAfterAFailedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	cache := enforcingCache(t, path, time.Now().UTC())
	refresher := unauthorizedRefresher(t, cache, nil)
	for range 2 {
		if err := refresher.Refresh(context.Background()); !errors.Is(err, errUnauthorizedHeld) {
			t.Fatalf("Refresh() error = %v, want a held 401", err)
		}
	}
	// Renaming over a non-empty directory fails, so Apply can't persist.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "occupied"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := refresher.Refresh(context.Background())
	if !errors.Is(err, errUnauthorizedHeld) || !strings.Contains(err.Error(), "replace") {
		t.Fatalf("Refresh() error = %v, want a hold that names the write failure", err)
	}
	if cache.Current().Deployment == nil {
		t.Fatal("a failed write dropped the policy")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v, want the drop applied", err)
	}
	if cache.Current().Deployment != nil {
		t.Fatal("the policy survived past the threshold")
	}
}

// With a one-hour interval, a streak only finishes if held 401s use the short
// retry. Doubling the delay as a failure would leave the second read two hours out.
func TestRunPacesAStreakWithTheShortRetry(t *testing.T) {
	cache := enforcingCache(t, filepath.Join(t.TempDir(), "cache.json"), time.Now().UTC())
	var fetches atomic.Int64
	refresher := unauthorizedRefresher(t, cache, &fetches)
	refresher.Interval = time.Hour
	refresher.unauthorizedRetry = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		refresher.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(5 * time.Second)
	for cache.Current().Deployment != nil {
		if time.Now().After(deadline) {
			t.Fatalf("policy still active after %d reads", fetches.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The streak is over, so the loop is back on the hourly interval.
	time.Sleep(100 * time.Millisecond)
	if got := fetches.Load(); got != unauthorizedThreshold {
		t.Fatalf("reads = %d, want exactly %d", got, unauthorizedThreshold)
	}
}

// An older binary or a crash can leave a count behind after a successful read.
// That count must not bring the next transient 401 closer to the drop.
func TestUnauthorizedCountFromBeforeASuccessfulReadIsIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	now := time.Now().UTC()
	cache := enforcingCache(t, path, now)
	refresher := unauthorizedRefresher(t, cache, nil)
	for range 2 {
		if err := refresher.Refresh(context.Background()); !errors.Is(err, errUnauthorizedHeld) {
			t.Fatalf("Refresh() error = %v, want a held 401", err)
		}
	}
	// Never loaded, so like an older binary it writes the cache and leaves the count file.
	enforcingCache(t, path, now.Add(time.Minute))

	restarted := NewCache(path, time.Hour)
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	err := unauthorizedRefresher(t, restarted, nil).Refresh(context.Background())
	if !errors.Is(err, errUnauthorizedHeld) || !strings.Contains(err.Error(), "1 of 3") {
		t.Fatalf("Refresh() error = %v, want a new streak at 1 of 3", err)
	}
}

func TestValidReadResetsTheStreakEvenWhenItsWriteFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	cache := enforcingCache(t, path, time.Now().UTC())
	var status atomic.Int64
	status.Store(http.StatusUnauthorized)
	refresher := refresherReplying(t, cache, nil, func() int { return int(status.Load()) })
	for range 2 {
		if err := refresher.Refresh(context.Background()); !errors.Is(err, errUnauthorizedHeld) {
			t.Fatalf("Refresh() error = %v, want a held 401", err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "occupied"), 0o700); err != nil {
		t.Fatal(err)
	}
	status.Store(http.StatusNotModified)
	if err := refresher.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil, want the write failure")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	status.Store(http.StatusUnauthorized)
	err := refresher.Refresh(context.Background())
	if !errors.Is(err, errUnauthorizedHeld) || !strings.Contains(err.Error(), "1 of 3") {
		t.Fatalf("Refresh() error = %v, want a new streak at 1 of 3", err)
	}
}

// The first read succeeds and parks the timer an hour out, so the streak below
// only finishes if a hold started by RefreshNow brings the next read forward.
func TestRefreshNowHoldUsesTheShortRetry(t *testing.T) {
	cache := enforcingCache(t, filepath.Join(t.TempDir(), "cache.json"), time.Now().UTC())
	var fetches atomic.Int64
	refresher := refresherReplying(t, cache, &fetches, func() int {
		if fetches.Load() == 1 {
			return http.StatusNotModified
		}
		return http.StatusUnauthorized
	})
	refresher.Interval = time.Hour
	refresher.unauthorizedRetry = 10 * time.Millisecond
	early := make(chan struct{}, 1)
	refresher.RefreshNow = early
	ready := make(chan struct{})
	refresher.InitialRefreshDone = ready

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		refresher.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	<-ready
	early <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for cache.Current().Deployment != nil {
		if time.Now().After(deadline) {
			t.Fatalf("policy still active after %d reads", fetches.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The third 401 can't save its drop, so the policy is still active. The next
// try must come after the short retry, not the failure backoff.
func TestRunRetriesAFailedDropWithTheShortRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	cache := enforcingCache(t, path, time.Now().UTC())
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "occupied"), 0o700); err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int64
	refresher := unauthorizedRefresher(t, cache, &fetches)
	refresher.Interval = time.Hour
	refresher.unauthorizedRetry = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		refresher.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(5 * time.Second)
	for fetches.Load() <= unauthorizedThreshold {
		if time.Now().After(deadline) {
			t.Fatalf("reads = %d, want a retry after the failed drop", fetches.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	for cache.Current().Deployment != nil {
		if time.Now().After(deadline) {
			t.Fatal("the drop never landed after writes recovered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
