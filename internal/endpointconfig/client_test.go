package endpointconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
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
		if len(query) != 1 || query.Get("response_version") != "2" {
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
