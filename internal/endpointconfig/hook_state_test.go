package endpointconfig

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// A confirmed v7 hook state survives a restart, and nothing less than a
// confirmed config moves a Mac off unmanaged.
func TestHookStateIsTheConfirmedConfigs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	cache := NewCache(path)
	if got := cache.Current().HookState(); got != UnmanagedHookState {
		t.Fatalf("no config: %+v", got)
	}
	response := testResponse(t, payloadcapture.ModeSummary)
	nonce := "Zm9vYmFyYmF6cXV4cXV1eDEy"
	state := HookState{Desired: HookStateInstalled, Generation: 7, RepairNonce: &nonce}
	response.Config.HookState = &state
	identity, err := ComputeIdentity(response.Config)
	if err != nil {
		t.Fatal(err)
	}
	response.ConfigIdentity = identity
	if err := cache.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got := cache.Current().HookState()
	if got.Desired != HookStateInstalled || got.Generation != 7 || got.Nonce() != nonce {
		t.Fatalf("confirmed: %+v", got)
	}
	restarted := NewCache(path)
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if got := restarted.Current().HookState(); got.Desired != HookStateInstalled || got.Generation != 7 || got.Nonce() != nonce {
		t.Fatalf("after restart: %+v", got)
	}
	// Every field is in the identity: a changed one is a new config.
	for name, change := range map[string]func(*HookState){
		"desired":    func(h *HookState) { h.Desired = HookStateUnmanaged },
		"generation": func(h *HookState) { h.Generation++ },
		"nonce":      func(h *HookState) { h.RepairNonce = nil },
	} {
		changed := state
		change(&changed)
		config := response.Config
		config.HookState = &changed
		other, err := ComputeIdentity(config)
		if err != nil {
			t.Fatal(err)
		}
		if other == identity {
			t.Fatalf("%s is not part of the identity", name)
		}
	}
}

// installedResponse is a v7 response asking for installed hooks.
func installedResponse(t *testing.T) (Response, HookState) {
	t.Helper()
	response := testResponse(t, payloadcapture.ModeSummary)
	nonce := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	state := HookState{Desired: HookStateInstalled, Generation: 3, RepairNonce: &nonce}
	response.Config.HookState = &state
	identity, err := ComputeIdentity(response.Config)
	if err != nil {
		t.Fatal(err)
	}
	response.ConfigIdentity = identity
	return response, state
}

// A snapshot's hook state is a copy: changing its nonce changes nothing
// the cache later hands out.
func TestHookStateIsACopy(t *testing.T) {
	cache := NewCache("")
	response, state := installedResponse(t)
	if err := cache.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// Neither the caller's response nor a snapshot shares the cache's nonce.
	*response.Config.HookState.RepairNonce = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	got := cache.Current().HookState()
	*got.RepairNonce = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if again := cache.Current().HookState(); again.Nonce() != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" || again.Generation != state.Generation {
		t.Fatalf("a caller's change reached the cache: %+v", again)
	}
}

// A 304 to the fallback request can't confirm the newer version's
// directive, whatever ETag it carries: the hooks read unmanaged.
func TestFallbackNotModifiedNeverConfirmsTheNewerDirective(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	response, _ := installedResponse(t)
	if err := cache.Apply(FetchResult{Response: &response, Version: ResponseVersion}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("response_version") == strconv.Itoa(ResponseVersion) {
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"code":"unsupported_version","supportedResponseVersions":[1,2,3,4,5,6]}`))
			return
		}
		w.Header().Set("ETag", `"`+response.ConfigIdentity+`"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	refresher := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
	if err := refresher.Refresh(context.Background()); !errors.Is(err, ErrNewestUnsupported) {
		t.Fatalf("Refresh() = %v", err)
	}
	if got := cache.Current().HookState(); !got.Equal(UnmanagedHookState) {
		t.Fatalf("hook state after a fallback 304: %+v", got)
	}
}

// Once the fallback version confirmed a config, a failure to refresh it is
// only a failure: its hook inventory switch stays on.
func TestAFailedFallbackRefreshKeepsTheFallbacksSwitches(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	fallback := fallbackResponse(t, payloadcapture.ModeSummary, false)
	var down atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("response_version") == strconv.Itoa(ResponseVersion) {
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"code":"unsupported_version","supportedResponseVersions":[1,2,3,4,5,6]}`))
			return
		}
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("ETag", `"`+fallback.ConfigIdentity+`"`)
		_ = json.NewEncoder(w).Encode(fallback)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	refresher := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !cache.Current().HookInventoryEnabled() {
		t.Fatal("the fallback's switch reads off")
	}
	down.Store(true)
	if err := refresher.Refresh(context.Background()); err == nil {
		t.Fatal("refresh against a failing server succeeded")
	}
	if !cache.Current().HookInventoryEnabled() {
		t.Fatal("a transient failure turned the fallback's confirmed switch off")
	}
}

// A 304 that answers the newer version's identity on the fallback request
// confirms nothing; the refresher asks again without it and takes the
// fallback's config, rather than sending the same identity every time.
func TestACrossVersionNotModifiedFetchesTheFallbackAgain(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	response := inventoryOnResponse(t)
	if err := cache.Apply(FetchResult{Response: &response, Version: ResponseVersion}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	fallback := fallbackResponse(t, payloadcapture.ModeSummary, false)
	var suppressed, undecided atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("response_version") == strconv.Itoa(ResponseVersion) {
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"code":"unsupported_version","supportedResponseVersions":[1,2,3,4,5,6]}`))
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			w.Header().Set("ETag", `"`+response.ConfigIdentity+`"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		// While the retry runs, the refused version's hook state is off.
		suppressed.Store(cache.Current().HookState().Equal(UnmanagedHookState))
		// ...and its inventory switch reads undecided, not a confirmed
		// opt-out that would purge the queued hook results.
		undecided.Store(!cache.Current().HookInventoryDecided())
		w.Header().Set("ETag", `"`+fallback.ConfigIdentity+`"`)
		_ = json.NewEncoder(w).Encode(fallback)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	refresher := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() = %v", err)
	}
	if !suppressed.Load() {
		t.Fatal("the refused version's hook state stayed on during the retry")
	}
	if !undecided.Load() {
		t.Fatal("the retry read as a decided hook inventory switch")
	}
	if !cache.Current().HookInventoryDecided() {
		t.Fatal("the fallback's own config didn't decide the switch")
	}
	if got := cache.Current(); got.ConfigIdentity != fallback.ConfigIdentity || got.Status.NewestUnsupported {
		t.Fatalf("after the retry: identity %s, status %+v", got.ConfigIdentity, got.Status)
	}
}

// installedResponse with the hook inventory switch on.
func inventoryOnResponse(t *testing.T) Response {
	t.Helper()
	response, _ := installedResponse(t)
	yes := true
	response.Config.HookInventory = &yes
	identity, err := ComputeIdentity(response.Config)
	if err != nil {
		t.Fatal(err)
	}
	response.ConfigIdentity = identity
	return response
}

// A confirmed opt-out stays decided while a refused version is negotiated,
// so a purge that failed can run again; a confirmed opt-in reads off but
// undecided, so nothing queued is purged.
func TestAConfirmedOptOutStaysDecidedDuringAFallback(t *testing.T) {
	for _, test := range []struct {
		name        string
		inventoryOn bool
		decided     bool
	}{
		{"opt-out", false, true},
		{"opt-in", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
			response, _ := installedResponse(t)
			if test.inventoryOn {
				response = inventoryOnResponse(t)
			}
			if err := cache.Apply(FetchResult{Response: &response, Version: ResponseVersion}, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			cache.markNewestUnsupported()
			got := cache.Current()
			if !got.Status.NewestUnsupported {
				t.Fatal("the refusal wasn't marked")
			}
			if got.HookInventoryEnabled() {
				t.Fatal("the switch read on during the fallback")
			}
			if got.HookInventoryDecided() != test.decided {
				t.Fatalf("HookInventoryDecided() = %v, want %v", got.HookInventoryDecided(), test.decided)
			}
		})
	}
}

// Storage refused the fallback's write, so the file still holds the newer
// version's config: a later refusal marks that file, and a restart doesn't
// bring its hook state back.
func TestARefusalMarksANewerFileTheFallbackCouldNotReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	cache := NewCache(path)
	response, _ := installedResponse(t)
	if err := cache.Apply(FetchResult{Response: &response, Version: ResponseVersion}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// What a fallback apply leaves when its write fails.
	fallback := fallbackResponse(t, payloadcapture.ModeSummary, false)
	cache.mu.Lock()
	cache.lastGood, cache.active = cloneResponse(&fallback), cloneResponse(&fallback)
	cache.mu.Unlock()
	cache.markNewestUnsupported()
	if cache.Current().Status.NewestUnsupported {
		t.Fatal("the fallback's confirmed config reads refused")
	}
	restarted := NewCache(path)
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if got := restarted.Current().HookState(); !got.Equal(UnmanagedHookState) {
		t.Fatalf("after restart: %+v", got)
	}
}
