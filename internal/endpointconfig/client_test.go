package endpointconfig

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

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

const testInstallationID = "ins_0123456789abcdefghijklmnopqrstuv"

func TestClientFetchAndConditionalRefresh(t *testing.T) {
	configuration := testResponse(t, payloadcapture.ModeFull)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/api/v1/installations/"+testInstallationID+"/configuration" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		query := request.URL.Query()
		if len(query) != 1 || query.Get("response_version") != "6" {
			t.Fatalf("query = %v", query)
		}
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("Authorization = %q", request.Header.Get("Authorization"))
		}
		w.Header().Set("ETag", `"`+configuration.ConfigIdentity+`"`)
		if got := request.Header.Get("If-None-Match"); got != "" {
			if got != `"`+configuration.ConfigIdentity+`"` {
				t.Fatalf("If-None-Match = %q", got)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(configuration)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Fetch(context.Background(), "token", testInstallationID, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Response == nil || result.Response.Config.PayloadCaptureMode != payloadcapture.ModeFull {
		t.Fatalf("Fetch() = %#v", result)
	}
	result, err = client.Fetch(context.Background(), "token", testInstallationID, configuration.ConfigIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if !result.NotModified || result.ETag != configuration.ConfigIdentity || requests != 2 {
		t.Fatalf("conditional Fetch() = %#v, requests = %d", result, requests)
	}
}

func TestClientRejectsUntrustedResponses(t *testing.T) {
	tests := []struct {
		name string
		body func(Response) string
		etag string
	}{
		{name: "unknown field", body: func(response Response) string {
			data, _ := json.Marshal(response)
			return strings.TrimSuffix(string(data), "}") + `,"policyText":"permit();"}`
		}, etag: "valid"},
		{name: "wrong identity", body: func(response Response) string {
			response.ConfigIdentity = strings.Repeat("f", 64)
			data, _ := json.Marshal(response)
			return string(data)
		}, etag: strings.Repeat("f", 64)},
		{name: "missing etag", body: marshalResponse},
		{name: "wrong etag", body: marshalResponse, etag: strings.Repeat("f", 64)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := testResponse(t, payloadcapture.ModeFull)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.etag == "valid" {
					w.Header().Set("ETag", `"`+configuration.ConfigIdentity+`"`)
				} else if test.etag != "" {
					w.Header().Set("ETag", `"`+test.etag+`"`)
				}
				_, _ = w.Write([]byte(test.body(configuration)))
			}))
			defer server.Close()
			client, err := NewClient(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Fetch(context.Background(), "token", testInstallationID, ""); err == nil {
				t.Fatal("Fetch() error = nil")
			}
		})
	}
}

func marshalResponse(response Response) string {
	data, _ := json.Marshal(response)
	return string(data)
}

// TestClientAcceptsWeakETags covers the transformed-response path: an
// intermediary that compresses the body (Cloudflare, corporate proxies)
// legally weakens the validator to W/"<identity>". The identity inside is
// still the origin's, so both the fresh and the not-modified paths must
// accept it. Regression test for the silent refresh outage that pinned
// payload capture to summary.
func TestClientAcceptsWeakETags(t *testing.T) {
	configuration := testResponse(t, payloadcapture.ModeFull)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("ETag", `W/"`+configuration.ConfigIdentity+`"`)
		if request.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(configuration)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.Fetch(context.Background(), "token", testInstallationID, "")
	if err != nil {
		t.Fatalf("Fetch with weak ETag: %v", err)
	}
	if result.Response == nil || result.ETag != configuration.ConfigIdentity {
		t.Fatalf("Fetch() = %#v", result)
	}

	result, err = client.Fetch(context.Background(), "token", testInstallationID, configuration.ConfigIdentity)
	if err != nil {
		t.Fatalf("conditional Fetch with weak ETag: %v", err)
	}
	if !result.NotModified || result.ETag != configuration.ConfigIdentity {
		t.Fatalf("conditional Fetch() = %#v", result)
	}
}

func TestParseETagAcceptsStrongAndWeakForms(t *testing.T) {
	identity := strings.Repeat("a", 64)
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "strong", value: `"` + identity + `"`, want: identity},
		{name: "weak", value: `W/"` + identity + `"`, want: identity},
		{name: "weak with surrounding space", value: ` W/"` + identity + `" `, want: identity},
		{name: "lowercase weak prefix is not a valid validator", value: `w/"` + identity + `"`, want: ""},
		{name: "unquoted", value: identity, want: ""},
		{name: "not hex", value: `"` + strings.Repeat("z", 64) + `"`, want: ""},
		{name: "empty", value: "", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := parseETag(test.value); got != test.want {
				t.Fatalf("parseETag(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

// TestRefresherLogsFailureTransitions covers the observability contract: a
// refresh loop that fails must say so in the daemon log exactly once per
// distinct error, and must log recovery. The outage this guards against
// failed every minute for a day without a single log line.
func TestRefresherLogsFailureTransitions(t *testing.T) {
	configuration := testResponse(t, payloadcapture.ModeFull)
	healthy := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", `"`+configuration.ConfigIdentity+`"`)
		_ = json.NewEncoder(w).Encode(configuration)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	var log strings.Builder
	refresher := Refresher{
		Client:         client,
		Cache:          NewCache(""),
		TokenSource:    func(context.Context) (string, error) { return "token", nil },
		InstallationID: testInstallationID,
		Diagnostic:     diagnostic.New(&log, true),
	}

	// Two failing attempts with the same error: one log line.
	if err := refresher.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded against a failing server")
	}
	if err := refresher.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded against a failing server")
	}
	failures := strings.Count(log.String(), "endpoint config refresh failed")
	if failures != 1 {
		t.Fatalf("failure lines = %d, want 1 (log: %q)", failures, log.String())
	}

	// Recovery: exactly one recovery line, and a later steady-state success
	// stays quiet.
	healthy = true
	for range 2 {
		if err := refresher.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh after recovery: %v", err)
		}
	}
	if recoveries := strings.Count(log.String(), "endpoint config refresh recovered"); recoveries != 1 {
		t.Fatalf("recovery lines = %d, want 1 (log: %q)", recoveries, log.String())
	}

	// A new, different failure logs again.
	server.Close()
	if err := refresher.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded against a closed server")
	}
	if failures := strings.Count(log.String(), "endpoint config refresh failed"); failures != 2 {
		t.Fatalf("failure lines after new error = %d, want 2 (log: %q)", failures, log.String())
	}
}

// A server that predates v6 refuses it with 406 unsupported_version: the
// client asks it for v5 instead, whose configuration has no hook inventory
// switch, which reads as off, and goes on asking for v5 alone for an hour.
// Conditional refreshes work as before.
func TestClientFallsBackForAServerThatPredatesV6(t *testing.T) {
	configuration := fallbackResponse(t, payloadcapture.ModeFull, true)
	var asked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		version := request.URL.Query().Get("response_version")
		asked = append(asked, version)
		if version != "5" {
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"code":"unsupported_version","supportedResponseVersions":[1,2,3,4,5]}`))
			return
		}
		w.Header().Set("ETag", `"`+configuration.ConfigIdentity+`"`)
		if request.Header.Get("If-None-Match") == `"`+configuration.ConfigIdentity+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(configuration)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	client.now = func() time.Time { return clock }
	result, err := client.Fetch(context.Background(), "token", testInstallationID, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Response == nil || result.Response.ResponseVersion != FallbackResponseVersion || result.Response.Config.HookInventory != nil ||
		result.Response.Config.HookInventoryEnabled() || !result.Response.Config.CodexProxyEnabled() || !result.Response.Config.ToolOutputCompactionEnabled() {
		t.Fatalf("Fetch() = %#v", result.Response)
	}
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	if err := cache.Apply(result, time.Now()); err != nil {
		t.Fatal(err)
	}
	result, err = client.Fetch(context.Background(), "token", testInstallationID, cache.ConditionalIdentity())
	if err != nil || !result.NotModified {
		t.Fatalf("conditional Fetch() = %#v, %v", result, err)
	}
	if err := cache.Apply(result, time.Now()); err != nil {
		t.Fatal(err)
	}
	if snapshot := cache.Current(); !snapshot.Confirmed || !snapshot.Config.CodexProxyEnabled() {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	clock = clock.Add(fallbackFor)
	if _, err := client.Fetch(context.Background(), "token", testInstallationID, cache.ConditionalIdentity()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(asked, " "); got != "6 5 5 6 5" {
		t.Fatalf("versions asked = %s", got)
	}
}

// Only unsupported_version says the server predates v6. Any other 406, and
// one for the fallback itself, fails the fetch.
func TestClientFailsOnOtherRefusals(t *testing.T) {
	for name, refusal := range map[string]struct {
		body    string
		refuses string
		asked   string
	}{
		"another code":          {body: `{"code":"unauthorized"}`, refuses: "6", asked: "6"},
		"no body":               {refuses: "6", asked: "6"},
		"the fallback too":      {body: `{"code":"unsupported_version","supportedResponseVersions":[1,2,3,4]}`, refuses: "6 5", asked: "6 5"},
		"a response of another": {body: `{"code":"unsupported_version"}`, refuses: "6", asked: "6 5"},
	} {
		t.Run(name, func(t *testing.T) {
			var asked []string
			v6 := testResponse(t, payloadcapture.ModeFull)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				version := request.URL.Query().Get("response_version")
				asked = append(asked, version)
				if strings.Contains(refusal.refuses, version) {
					w.WriteHeader(http.StatusNotAcceptable)
					_, _ = w.Write([]byte(refusal.body))
					return
				}
				// Asked for v5, a server must not answer v6.
				w.Header().Set("ETag", `"`+v6.ConfigIdentity+`"`)
				_ = json.NewEncoder(w).Encode(v6)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if result, err := client.Fetch(context.Background(), "token", testInstallationID, ""); err == nil {
				t.Fatalf("Fetch() = %#v", result)
			}
			if got := strings.Join(asked, " "); got != refusal.asked {
				t.Fatalf("versions asked = %s, want %s", got, refusal.asked)
			}
		})
	}
}

// A server rolled back past both versions answers each with 406
// unsupported_version. Nothing it last sent can be confirmed, so the refresh
// fails closed to the defaults instead of keeping full capture in force.
func TestRefresherFailsClosedWhenNoVersionIsServed(t *testing.T) {
	cache := NewCache("")
	full := testResponse(t, payloadcapture.ModeFull)
	if err := cache.Apply(FetchResult{Response: &full}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotAcceptable)
		_, _ = w.Write([]byte(`{"code":"unsupported_version","supportedResponseVersions":[1,2,3,4]}`))
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
		TokenSource:    func(context.Context) (string, error) { return "token", nil },
	}
	if err := refresher.Refresh(context.Background()); !errors.Is(err, ErrNoCommonVersion) {
		t.Fatalf("Refresh() error = %v, want ErrNoCommonVersion", err)
	}
	snapshot := cache.Current()
	if snapshot.Confirmed || snapshot.Config.PayloadCaptureMode != payloadcapture.ModeSummary || !snapshot.Status.NoCommonVersion {
		t.Fatalf("snapshot after no common version = %#v", snapshot)
	}
}

func TestHookInventoryEnabledReadsTheSwitch(t *testing.T) {
	on, off := true, false
	for name, test := range map[string]struct {
		value *bool
		want  bool
	}{"absent": {nil, false}, "off": {&off, false}, "on": {&on, true}} {
		t.Run(name, func(t *testing.T) {
			if got := (Config{HookInventory: test.value}).HookInventoryEnabled(); got != test.want {
				t.Fatalf("HookInventoryEnabled() = %v, want %v", got, test.want)
			}
		})
	}
}

// A snapshot names the enrolment whose refresh confirmed it, and forgets it
// when that authority is rejected or the config comes from disk.
func TestSnapshotNamesTheConfirmingEnrolment(t *testing.T) {
	full := testResponse(t, payloadcapture.ModeFull)
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("ETag", `"`+full.ConfigIdentity+`"`)
		_ = json.NewEncoder(w).Encode(full)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	cache := NewCache(path)
	refresher := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token-a", nil }}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cache.Current().Owner; got == "" || got != Owner("token-a") || got == Owner("token-b") {
		t.Fatalf("owner %q", got)
	}
	reloaded := NewCache(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if snapshot := reloaded.Current(); !snapshot.Confirmed || snapshot.Owner != "" {
		t.Fatalf("reloaded snapshot %+v", snapshot)
	}
	status = http.StatusUnauthorized
	_ = refresher.Refresh(context.Background())
	if got := cache.Current().Owner; got != "" {
		t.Fatalf("owner after rejection %q", got)
	}
}

// A rollback past both versions drops the directive but keeps a prompt
// opt-out as a veto, through a restart, and never an opt-in.
func TestNoCommonVersionKeepsThePromptOptOut(t *testing.T) {
	rollback := func(t *testing.T, cache *Cache) {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"code":"unsupported_version","supportedResponseVersions":[1,2,3,4]}`))
		}))
		defer server.Close()
		client, err := NewClient(server.URL, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		refresher := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
		if err := refresher.Refresh(context.Background()); !errors.Is(err, ErrNoCommonVersion) {
			t.Fatalf("Refresh() = %v", err)
		}
	}
	for _, test := range []struct {
		name string
		mode payloadcapture.Mode
		veto bool
	}{{"omitted", payloadcapture.ModeOmitted, true}, {"summary", payloadcapture.ModeSummary, true}, {"full", payloadcapture.ModeFull, false}} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			cache := NewCache(filepath.Join(dir, "endpoint-config.json"))
			response := testResponse(t, test.mode)
			if err := cache.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			rollback(t, cache)
			if got := cache.Current().Status.PromptVeto; got != test.veto {
				t.Fatalf("veto = %v, want %v", got, test.veto)
			}
			// An offline restart still knows why the cache was dropped.
			restarted := NewCache(filepath.Join(dir, "endpoint-config.json"))
			if err := restarted.Load(); !errors.Is(err, ErrCacheInvalidated) {
				t.Fatalf("Load() = %v", err)
			}
			status := restarted.Current().Status
			if status.PromptVeto != test.veto || !status.NoCommonVersion {
				t.Fatalf("restarted status %+v", status)
			}
			// A second rollback keeps the veto though nothing is confirmed.
			rollback(t, restarted)
			if restarted.Current().Status.PromptVeto != test.veto {
				t.Fatal("veto lost on a second rollback")
			}
			// A confirmed config lifts it.
			if err := restarted.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			if restarted.Current().Status.PromptVeto {
				t.Fatal("veto kept after a confirmed config")
			}
		})
	}
}

// An expired or revoked token drops the directive like a rollback, and
// keeps a prompt opt-out the same way: it never clears a veto already held.
func TestAuthorityRejectionKeepsThePromptOptOut(t *testing.T) {
	reject := func(t *testing.T, cache *Cache, status int) {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		defer server.Close()
		client, err := NewClient(server.URL, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		refresher := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
		if err := refresher.Refresh(context.Background()); !errors.Is(err, ErrAuthorityRejected) {
			t.Fatalf("Refresh() = %v", err)
		}
	}
	for _, test := range []struct {
		name string
		mode payloadcapture.Mode
		veto bool
	}{{"omitted", payloadcapture.ModeOmitted, true}, {"full", payloadcapture.ModeFull, false}} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			cache := NewCache(filepath.Join(dir, "endpoint-config.json"))
			response := testResponse(t, test.mode)
			if err := cache.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			reject(t, cache, http.StatusUnauthorized)
			if got := cache.Current().Status.PromptVeto; got != test.veto {
				t.Fatalf("veto after 401 = %v, want %v", got, test.veto)
			}
			restarted := NewCache(filepath.Join(dir, "endpoint-config.json"))
			if err := restarted.Load(); !errors.Is(err, ErrCacheInvalidated) {
				t.Fatalf("Load() = %v", err)
			}
			// A later 403, with nothing confirmed, keeps what the 401 kept.
			reject(t, restarted, http.StatusForbidden)
			if got := restarted.Current().Status.PromptVeto; got != test.veto {
				t.Fatalf("veto after restart and 403 = %v, want %v", got, test.veto)
			}
		})
	}
}

// The cloud's installation_not_found drops the directive like a 401; a bare
// 404 from a proxy doesn't.
func TestInstallationNotFoundRejectsTheDirective(t *testing.T) {
	for _, test := range []struct {
		body     string
		rejected bool
	}{{`{"code":"installation_not_found"}`, true}, {`not found`, false}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(test.body))
		}))
		client, err := NewClient(server.URL, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
		response := testResponse(t, payloadcapture.ModeFull)
		if err := cache.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		refresher := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
		err = refresher.Refresh(context.Background())
		server.Close()
		if errors.Is(err, ErrAuthorityRejected) != test.rejected || cache.Current().Confirmed == test.rejected {
			t.Fatalf("%s: err %v, confirmed %v", test.body, err, cache.Current().Confirmed)
		}
	}
}

// A server that refuses v6 and then fails the v5 retry leaves no v6-only
// switch on.
func TestV6RefusalTurnsHookInventoryOff(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	on := testResponse(t, payloadcapture.ModeSummary)
	yes := true
	on.Config.HookInventory = &yes
	identity, err := ComputeIdentity(on.Config)
	if err != nil {
		t.Fatal(err)
	}
	on.ConfigIdentity = identity
	if err := cache.Apply(FetchResult{Response: &on}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if !cache.Current().HookInventoryEnabled() {
		t.Fatal("confirmed switch reads off")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("response_version") == "6" {
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"code":"unsupported_version","supportedResponseVersions":[1,2,3,4,5]}`))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	refresher := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
	if err := refresher.Refresh(context.Background()); !errors.Is(err, ErrV6Unsupported) {
		t.Fatalf("Refresh() = %v", err)
	}
	snapshot := cache.Current()
	if snapshot.HookInventoryEnabled() || !snapshot.Confirmed {
		t.Fatalf("after v6 refusal: enabled=%v confirmed=%v", snapshot.HookInventoryEnabled(), snapshot.Confirmed)
	}
	// A restart while configuration is still unavailable keeps it off.
	restarted := NewCache(cache.path)
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if restarted.Current().HookInventoryEnabled() {
		t.Fatal("restart turned the refused switch back on")
	}
}

// A directive belongs to the cloud that confirmed it: after re-enrolment at
// another cloud it isn't restored, and the opt-out holds until that cloud
// confirms its own. An older-version cache and a legacy rejection marker
// hold the opt-out too.
func TestCachedDirectiveBelongsToItsCloud(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoint-config.json")
	first := NewCache(path)
	first.Bind("https://a.example/", "token-a")
	response := testResponse(t, payloadcapture.ModeFull)
	if err := first.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	same := NewCache(path)
	same.Bind("https://a.example", "token-a")
	if err := same.Load(); err != nil || !same.Current().Confirmed {
		t.Fatalf("same cloud: %v %+v", err, same.Current().Status)
	}
	// Restored, the directive still names the enrolment that confirmed it.
	if owner := same.Current().Owner; owner != Owner("token-a") {
		t.Fatalf("restored owner %q", owner)
	}
	other := NewCache(path)
	other.Bind("https://b.example", "token-a")
	if err := other.Load(); err != nil || other.Current().Confirmed || !other.Current().Status.PromptVeto {
		t.Fatalf("other cloud: %v confirmed=%v %+v", err, other.Current().Confirmed, other.Current().Status)
	}

	legacy := filepath.Join(t.TempDir(), "endpoint-config.json")
	marked := NewCache(legacy)
	if err := os.WriteFile(marked.rejectedPath, []byte("refresh required\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := marked.Load(); !errors.Is(err, ErrCacheInvalidated) || !marked.Current().Status.PromptVeto {
		t.Fatalf("legacy marker: %v %+v", err, marked.Current().Status)
	}

	older := filepath.Join(t.TempDir(), "endpoint-config.json")
	if err := os.WriteFile(older, []byte(`{"version":1,"fetchedAt":"2026-01-01T00:00:00Z","response":{"responseVersion":4}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	upgraded := NewCache(older)
	if err := upgraded.Load(); err != nil || !upgraded.Current().Status.PromptVeto {
		t.Fatalf("older version: %v %+v", err, upgraded.Current().Status)
	}
}

// Re-enrolling into another workspace on the same cloud doesn't restore the
// previous enrolment's directive, and a file that names no enrolment, from
// an older build, isn't restored by a bound cache either.
func TestCachedDirectiveBelongsToItsEnrolment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	first := NewCache(path)
	first.Bind("https://a.example", "token-a")
	response := testResponse(t, payloadcapture.ModeFull)
	if err := first.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	other := NewCache(path)
	other.Bind("https://a.example", "token-b")
	if err := other.Load(); err != nil || other.Current().Confirmed || !other.Current().Status.PromptVeto {
		t.Fatalf("other enrolment: %v %+v", err, other.Current().Status)
	}
	legacyPath := filepath.Join(t.TempDir(), "endpoint-config.json")
	unbound := NewCache(legacyPath)
	if err := unbound.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	legacy := NewCache(legacyPath)
	legacy.Bind("https://a.example", "token-a")
	if err := legacy.Load(); err != nil || legacy.Current().Confirmed || !legacy.Current().Status.PromptVeto {
		t.Fatalf("legacy file: %v %+v", err, legacy.Current().Status)
	}
}

// A confirmed opt-out whose cache file can't be replaced is journaled with
// the veto, and a journal that can't be written takes the cache's place, so
// an offline restart keeps both the veto and an owed route removal.
func TestTheVetoSurvivesAFailedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoint-config.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := NewCache(path)
	optOut := testResponse(t, payloadcapture.ModeOmitted)
	if err := cache.Apply(FetchResult{Response: &optOut}, time.Now().UTC()); err == nil {
		t.Fatal("replacing a directory succeeded")
	}
	restarted := NewCache(path)
	if err := restarted.Load(); !errors.Is(err, ErrCacheInvalidated) || !restarted.Current().Status.PromptVeto {
		t.Fatalf("failed replace: %v %+v", err, restarted.Current().Status)
	}

	path = filepath.Join(t.TempDir(), "endpoint-config.json")
	cache = NewCache(path)
	if err := cache.Apply(FetchResult{Response: &optOut}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cache.rejectedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cache.rejectAuthority(ErrNoCommonVersion, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cache.rejectedPath); err != nil {
		t.Fatal(err)
	}
	restarted = NewCache(path)
	err := restarted.Load()
	status := restarted.Current().Status
	if !errors.Is(err, ErrCacheInvalidated) || !status.PromptVeto || !status.NoCommonVersion {
		t.Fatalf("unwritable journal: %v %+v", err, status)
	}

	// An unreadable journal holds the veto as well.
	blocked := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	if err := os.Mkdir(blocked.rejectedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := blocked.Load(); err == nil || !blocked.Current().Status.PromptVeto {
		t.Fatalf("unreadable journal: %v %+v", err, blocked.Current().Status)
	}
}

// A 401 after a rollback doesn't cancel the Codex route removal still owed.
func TestARejectionKeepsAnOwedRouteRemoval(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	if err := cache.rejectAuthority(ErrNoCommonVersion, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := cache.rejectAuthority(ErrAuthorityRejected, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if !cache.Current().Status.NoCommonVersion {
		t.Fatalf("%+v", cache.Current().Status)
	}
	restarted := NewCache(cache.path)
	if err := restarted.Load(); !errors.Is(err, ErrCacheInvalidated) || !restarted.Current().Status.NoCommonVersion {
		t.Fatalf("%v %+v", err, restarted.Current().Status)
	}
}

// v5 never carries hookInventory, null included; v4 never carries codexProxy.
func TestNullSwitchesAreRefused(t *testing.T) {
	for _, body := range []string{
		`{"payloadCaptureMode":"summary","workTypeClassification":false,"toolOutputCompaction":false,"codexProxy":true,"hookInventory":null}`,
		`{"payloadCaptureMode":"summary","workTypeClassification":false,"toolOutputCompaction":false,"codexProxy":null}`,
	} {
		var config Config
		if err := json.Unmarshal([]byte(body), &config); err != nil {
			t.Fatal(err)
		}
		if err := config.validate(5); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	var config Config
	if err := json.Unmarshal([]byte(`{"payloadCaptureMode":"summary","workTypeClassification":false,"toolOutputCompaction":false,"codexProxy":true,"extra":1}`), &config); err == nil {
		t.Fatal("unknown field accepted")
	}
	// Keys are matched exactly, as the cloud's schema matches them.
	for _, body := range []string{
		`{"payloadCaptureMode":"summary","workTypeClassification":false,"toolOutputCompaction":false,"codexProxy":true,"HookInventory":true}`,
		`{"payloadCaptureMode":"summary","workTypeClassification":false,"toolOutputCompaction":false,"codexProxy":true,"HookInventory":null}`,
	} {
		var config Config
		if err := json.Unmarshal([]byte(body), &config); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

// A journal left by an earlier rejection takes a newer opt-out before the
// cache is replaced: if its removal fails, a restart still holds the veto.
func TestAStaleJournalCantOverrideANewerOptOut(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	full := testResponse(t, payloadcapture.ModeFull)
	if err := cache.Apply(FetchResult{Response: &full}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := cache.rejectAuthority(ErrAuthorityRejected, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if markerHas(mustRead(t, cache.rejectedPath), markerPromptVeto) {
		t.Fatal("full capture journaled a veto")
	}
	// A crash between the cache replace and the journal's removal leaves
	// the journal as it was just before the replace.
	var left []byte
	beforeReplace = func() { left = mustRead(t, cache.rejectedPath) }
	defer func() { beforeReplace = func() {} }()
	optOut := testResponse(t, payloadcapture.ModeOmitted)
	if err := cache.Apply(FetchResult{Response: &optOut}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.rejectedPath, left, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := NewCache(cache.path)
	_ = restarted.Load()
	if !restarted.Current().Status.PromptVeto {
		t.Fatalf("stale journal restored prompts: %+v", restarted.Current().Status)
	}
}

// With the journal unreadable, the marker that took the cache's place still
// keeps a route removal owed.
func TestAnUnreadableJournalKeepsTheMarkersRouteRemoval(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	if err := os.WriteFile(cache.path, []byte(markerHeader+"\n"+markerVersioned+"\n"+markerNoCommonVersion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cache.rejectedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cache.Load(); err == nil {
		t.Fatal("unreadable journal loaded")
	}
	if status := cache.Current().Status; !status.PromptVeto || !status.NoCommonVersion {
		t.Fatalf("%+v", status)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A v6 refusal that can't be saved with the cache keeps the confirmed
// opt-out in the marker that replaces it.
func TestAnUnsavedV6RefusalKeepsTheOptOut(t *testing.T) {
	cache := NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	optOut := testResponse(t, payloadcapture.ModeOmitted)
	if err := cache.Apply(FetchResult{Response: &optOut}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	replaceFile = func(string, string) error { return errors.New("disk full") }
	defer func() { replaceFile = os.Rename }()
	cache.markV6Unsupported()
	replaceFile = os.Rename
	restarted := NewCache(cache.path)
	if err := restarted.Load(); !errors.Is(err, ErrCacheInvalidated) || !restarted.Current().Status.PromptVeto {
		t.Fatalf("%v %+v", err, restarted.Current().Status)
	}
}
