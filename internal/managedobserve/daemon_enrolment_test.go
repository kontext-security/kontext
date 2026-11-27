package managedobserve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

const testPolicyState = `{"responseVersion":2,"requestContractVersion":2,"state":"%STATE%"}`

// enrolmentCloud answers the policy route as the hosted API does: an
// installation stays principal_unavailable until its first post is accepted.
type enrolmentCloud struct {
	alwaysEnrolled bool
	posts          atomic.Int64
	fetches        atomic.Int64
}

func (c *enrolmentCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/policy"):
		c.fetches.Add(1)
		state := "principal_unavailable"
		if c.alwaysEnrolled || c.posts.Load() > 0 {
			state = "no_active_policy"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.ReplaceAll(testPolicyState, "%STATE%", state)))
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "authorization-ledger"):
		c.posts.Add(1)
		w.WriteHeader(http.StatusAccepted)
	default:
		w.WriteHeader(http.StatusAccepted)
	}
}

// startEnrolmentDaemon runs a daemon whose policy timer never fires in a test,
// so any second fetch comes from the accepted post.
func startEnrolmentDaemon(t *testing.T, cloud *enrolmentCloud) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dir := daemonDir(t)
	server := httptest.NewTLSServer(cloud)
	t.Cleanup(server.Close)
	writeTestManagedConfigWithCloudURL(t, filepath.Join(dir, "managed.json"), server.URL)
	writeTestInstallation(t, filepath.Join(dir, "installation.json"))
	socketPath := filepath.Join(hermetic.SocketDir(t), "kontext.sock")

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(ctx, DaemonOptions{
			SocketPath:                    socketPath,
			DBPath:                        filepath.Join(dir, "guard.db"),
			IdleTimeout:                   time.Hour,
			StreamInterval:                20 * time.Millisecond,
			StreamHTTPClient:              server.Client(),
			PolicyRefreshInterval:         time.Hour,
			PolicyHTTPClient:              server.Client(),
			EndpointConfigRefreshInterval: time.Hour,
			EndpointConfigHTTPClient:      server.Client(),
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("RunDaemon() error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("RunDaemon did not stop")
		}
	})
}

func waitForPosts(t *testing.T, cloud *enrolmentCloud) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for cloud.posts.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no post reached the cloud")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAcceptedPostRefreshesPolicyWhilePrincipalUnavailable(t *testing.T) {
	cloud := &enrolmentCloud{}
	startEnrolmentDaemon(t, cloud)
	waitForPosts(t, cloud)

	deadline := time.Now().Add(5 * time.Second)
	for cloud.fetches.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("policy fetches = %d after an accepted post, want a refresh without waiting for the timer", cloud.fetches.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAcceptedPostLeavesAResolvedPolicyAlone(t *testing.T) {
	cloud := &enrolmentCloud{alwaysEnrolled: true}
	startEnrolmentDaemon(t, cloud)
	waitForPosts(t, cloud)

	time.Sleep(300 * time.Millisecond)
	if got := cloud.fetches.Load(); got != 1 {
		t.Fatalf("policy fetches = %d, want 1: an enrolled endpoint keeps the timer's cadence", got)
	}
}

func TestEnrolmentRefreshesAreBounded(t *testing.T) {
	cache := cedarpolicy.NewCache("", time.Hour)
	if err := cache.Apply(cedarpolicy.FetchResult{
		State: cedarpolicy.StatePrincipalUnavailable,
		Response: &cedarpolicy.StateResponse{
			ResponseVersion:        cedarpolicy.ResponseVersion,
			RequestContractVersion: cedarpolicy.RequestContractVersion,
			State:                  cedarpolicy.StatePrincipalUnavailable,
		},
	}, time.Now()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	now := make(chan struct{}, 1)
	enrolment := &enrolmentRefresh{cache: cache, now: now, left: maxEnrolmentRefreshes}

	// A refresh still pending isn't a second one, so it doesn't use up the bound.
	enrolment.afterAcceptedPost()
	enrolment.afterAcceptedPost()
	if enrolment.left != maxEnrolmentRefreshes-1 {
		t.Fatalf("left = %d after a pending refresh, want %d", enrolment.left, maxEnrolmentRefreshes-1)
	}

	refreshes := 0
	for range 3 * maxEnrolmentRefreshes {
		select {
		case <-now:
			refreshes++
		default:
		}
		enrolment.afterAcceptedPost()
	}
	select {
	case <-now:
		refreshes++
	default:
	}
	if refreshes != maxEnrolmentRefreshes {
		t.Fatalf("refreshes = %d, want the bound of %d for an installation that never enrols", refreshes, maxEnrolmentRefreshes)
	}
}

func TestAcceptedPostRefreshesWhenNoFetchHasWorkedYet(t *testing.T) {
	now := make(chan struct{}, 1)
	enrolment := &enrolmentRefresh{cache: cedarpolicy.NewCache("", time.Hour), now: now, left: maxEnrolmentRefreshes}

	enrolment.afterAcceptedPost()
	select {
	case <-now:
	default:
		t.Fatal("no refresh after an accepted post with no policy fetched yet")
	}
}

// A new endpoint's first settings read is refused, so until a read confirms
// them the daemon captures on the default and records calls without their
// input. An accepted post shows the cloud now knows the installation.
func TestAcceptedPostRefreshesUnconfirmedSettings(t *testing.T) {
	settingsNow := make(chan struct{}, 1)
	enrolment := &enrolmentRefresh{
		cache:    cedarpolicy.NewCache("", time.Hour),
		settings: endpointconfig.NewCache(filepath.Join(t.TempDir(), "endpoint-config.json")), settingsNow: settingsNow, settingsLeft: maxEnrolmentRefreshes,
	}

	// A refresh still pending isn't a second one, so it doesn't use up the bound.
	enrolment.afterAcceptedPost()
	enrolment.afterAcceptedPost()
	select {
	case <-settingsNow:
	default:
		t.Fatal("no settings refresh after an accepted post with no settings confirmed yet")
	}
	if enrolment.settingsLeft != maxEnrolmentRefreshes-1 {
		t.Fatalf("settingsLeft = %d after a pending refresh, want %d", enrolment.settingsLeft, maxEnrolmentRefreshes-1)
	}
}

func TestAcceptedPostLeavesConfirmedSettingsToTheTimer(t *testing.T) {
	settings := endpointconfig.NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	on, off := true, false
	config := endpointconfig.Config{PayloadCaptureMode: payloadcapture.ModeFull, WorkTypeClassification: &on, ToolOutputCompaction: &off, CodexProxy: &on, HookInventory: &off, HookState: &endpointconfig.UnmanagedHookState}
	identity, err := endpointconfig.ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	response := endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity}
	if err := settings.Apply(endpointconfig.FetchResult{Response: &response, ETag: identity}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	settingsNow := make(chan struct{}, 1)
	enrolment := &enrolmentRefresh{
		cache:    cedarpolicy.NewCache("", time.Hour),
		settings: settings, settingsNow: settingsNow, settingsLeft: maxEnrolmentRefreshes,
	}

	enrolment.afterAcceptedPost()
	select {
	case <-settingsNow:
		t.Fatal("settings refresh after an accepted post although a read had confirmed them")
	default:
	}
	if enrolment.settingsLeft != maxEnrolmentRefreshes {
		t.Fatalf("settingsLeft = %d, want %d untouched", enrolment.settingsLeft, maxEnrolmentRefreshes)
	}
}

func TestSettingsRefreshesAreBounded(t *testing.T) {
	settingsNow := make(chan struct{}, 1)
	enrolment := &enrolmentRefresh{
		cache:    cedarpolicy.NewCache("", time.Hour),
		settings: endpointconfig.NewCache(filepath.Join(t.TempDir(), "endpoint-config.json")), settingsNow: settingsNow, settingsLeft: maxEnrolmentRefreshes,
	}

	refreshes := 0
	for range 3 * maxEnrolmentRefreshes {
		enrolment.afterAcceptedPost()
		select {
		case <-settingsNow:
			refreshes++
		default:
		}
	}
	if refreshes != maxEnrolmentRefreshes {
		t.Fatalf("refreshes = %d, want the bound of %d for settings that never confirm", refreshes, maxEnrolmentRefreshes)
	}
}
