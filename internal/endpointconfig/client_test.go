package endpointconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		if len(query) != 1 || query.Get("response_version") != "3" {
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
