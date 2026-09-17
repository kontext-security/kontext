package cedarpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/diagnostic"
)

func TestAuthoritySettingOptInAndConditionalRefresh(t *testing.T) {
	deployment := testDeployment(t, cedareval.RolloutModeObserve)
	enabled := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("include_authority_scan") != "true" {
			t.Error("missing opt-in")
		}
		w.Header().Set("ETag", `"`+deployment.DeploymentIdentity+`"`)
		if r.Header.Get("If-None-Match") != "" {
			w.Header().Set("X-Kontext-Authority-Scan", "false")
			if enabled {
				w.Header().Set("X-Kontext-Authority-Scan", "true")
			}
			w.WriteHeader(304)
			return
		}
		data, _ := json.Marshal(deployment)
		var body map[string]any
		_ = json.Unmarshal(data, &body)
		body["authority_scan"] = enabled
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, server.Client())
	cache := NewCache("", 0)
	if cache.Current().AuthorityScan {
		t.Fatal("scan enabled before API confirmation")
	}
	refresh := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
	for _, want := range []bool{true, false, true} {
		enabled = want
		if err := refresh.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		if cache.Current().AuthorityScan != want {
			t.Fatalf("scan enabled=%t, want %t", cache.Current().AuthorityScan, want)
		}
	}
	// A legacy API does not opt this CLI into sending a strict device extension.
	if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &deployment}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if cache.Current().AuthorityScan {
		t.Fatal("legacy API retained scan opt-in")
	}
}

func TestAuthorityStateResponseAndInvalidSetting(t *testing.T) {
	for _, setting := range []string{"true", "false", "null", `"true"`} {
		t.Run(setting, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"responseVersion":2,"requestContractVersion":2,"state":"no_active_policy","authority_scan":` + setting + `}`))
			}))
			defer server.Close()
			client, _ := NewClient(server.URL, server.Client())
			var log bytes.Buffer
			client.Diagnostic = diagnostic.New(&log, true)
			result, err := client.Fetch(context.Background(), "token", testInstallationID, "")
			valid := setting == "true" || setting == "false"
			if err != nil {
				t.Fatalf("error=%v", err)
			}
			if !valid && (result.AuthorityScan != nil || log.Len() == 0) {
				t.Fatal("invalid setting must be absent and diagnosed")
			}
			if valid && (result.AuthorityScan == nil || *result.AuthorityScan != (setting == "true")) {
				t.Fatal("setting lost")
			}
		})
	}
}

func TestAuthorityBodyWinsHeaderDisagreement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Kontext-Authority-Scan", "false")
		_, _ = w.Write([]byte(`{"responseVersion":2,"requestContractVersion":2,"state":"no_active_policy","authority_scan":true}`))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, server.Client())
	var log bytes.Buffer
	client.Diagnostic = diagnostic.New(&log, true)
	result, err := client.Fetch(context.Background(), "token", testInstallationID, "")
	if err != nil || result.AuthorityScan == nil || !*result.AuthorityScan || !strings.Contains(log.String(), "using body") {
		t.Fatalf("result=%+v error=%v log=%s", result, err, log.String())
	}
}

func TestAuthority304WithoutHeaderKeepsSwitch(t *testing.T) {
	deployment := testDeployment(t, cedareval.RolloutModeObserve)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+deployment.DeploymentIdentity+`"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	for _, enabled := range []bool{true, false} {
		cache := NewCache("", 0)
		if err := cache.Apply(FetchResult{State: StateSuccess, Deployment: &deployment, AuthorityScan: &enabled}, time.Now()); err != nil {
			t.Fatal(err)
		}
		client, _ := NewClient(server.URL, server.Client())
		refresh := Refresher{Client: client, Cache: cache, InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }}
		if err := refresh.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		if cache.Current().AuthorityScan != enabled || !cache.Current().AuthorityScanKnown {
			t.Fatal("304 erased the confirmed switch")
		}
	}
}

func TestHungTokenSourceReleasesInitialPolicyWait(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	ready := make(chan struct{})
	client, _ := NewClient("https://example.test", nil)
	refresh := Refresher{Client: client, Cache: NewCache("", 0), InitialRefreshDone: ready, TokenSource: func(context.Context) (string, error) { <-blocked; return "token", nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { refresh.Run(ctx); close(done) }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("initial wait blocked on TokenSource")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked on TokenSource")
	}
	pending := refresh.tokenPending
	if err := refresh.Refresh(ctx); err == nil || refresh.tokenPending != pending {
		t.Fatal("hung token lookup spawned another worker")
	}
}

func TestAuthorityPolicyRecoveryNotifiesImmediately(t *testing.T) {
	fail := true
	enabled := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(500)
			return
		}
		_, _ = fmt.Fprintf(w, `{"responseVersion":2,"requestContractVersion":2,"state":"no_active_policy","authority_scan":%t}`, enabled)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, server.Client())
	called := 0
	refresh := Refresher{Client: client, Cache: NewCache("", 0), InstallationID: testInstallationID, TokenSource: func(context.Context) (string, error) { return "token", nil }, OnAuthorityScanAvailable: func() { called++ }}
	if err := refresh.Refresh(context.Background()); err == nil {
		t.Fatal("expected offline startup")
	}
	fail = false
	for i := 0; i < 2; i++ {
		if err := refresh.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if called != 1 {
		t.Fatalf("recovery notifications=%d", called)
	}
	for _, value := range []bool{false, false, true, true} {
		enabled = value
		if err := refresh.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if called != 2 {
		t.Fatalf("off/on did not notify exactly once: %d", called)
	}
}
