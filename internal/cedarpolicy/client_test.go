package cedarpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
)

const testInstallationID = "ins_0123456789abcdefghijklmnopqrstuv"

func TestClientFetchDeploymentAndConditionalRefresh(t *testing.T) {
	deployment := testDeployment(t, cedareval.RolloutModeObserve)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v1/installations/"+testInstallationID+"/policy" {
			t.Fatalf("request path = %q", r.URL.Path)
		}
		query := r.URL.Query()
		if len(query) != 2 || query.Get("response_version") != "1" || query.Get("request_contract_version") != "1" {
			t.Fatalf("request query = %v", query)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("ETag", `"`+deployment.DeploymentIdentity+`"`)
		if got := r.Header.Get("If-None-Match"); got != "" {
			if got != `"`+deployment.DeploymentIdentity+`"` {
				t.Fatalf("If-None-Match = %q", got)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(deployment)
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
	if result.State != StateSuccess || result.Deployment == nil {
		t.Fatalf("Fetch() = %#v", result)
	}
	result, err = client.Fetch(context.Background(), "token", testInstallationID, deployment.DeploymentIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateNotModified || result.ETag != deployment.DeploymentIdentity || requests != 2 {
		t.Fatalf("conditional Fetch() = %#v, requests = %d", result, requests)
	}
}

func TestClientFetchStateResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   StateResponse
	}{
		{name: "disabled", status: http.StatusOK, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateDisabled, RolloutMode: "disabled"}},
		{name: "no active policy", status: http.StatusOK, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateNoActivePolicy}},
		{name: "principal unavailable", status: http.StatusOK, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StatePrincipalUnavailable}},
		{name: "unauthorized", status: http.StatusUnauthorized, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateUnauthorized}},
		{name: "unsupported", status: http.StatusNotAcceptable, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateUnsupportedVersion, SupportedResponseVersions: []int{1}, SupportedRequestContractVersions: []int{1}}},
		{name: "unavailable", status: http.StatusServiceUnavailable, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateUnavailable, Retryable: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_ = json.NewEncoder(w).Encode(test.body)
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
			if result.State != test.body.State {
				t.Fatalf("Fetch().State = %q, want %q", result.State, test.body.State)
			}
		})
	}
}

func TestClientRejectsStateThatDoesNotMatchHTTPStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   StateResponse
	}{
		{name: "success with unavailable", status: http.StatusOK, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateUnavailable, Retryable: true}},
		{name: "unauthorized with disabled", status: http.StatusUnauthorized, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateDisabled, RolloutMode: "disabled"}},
		{name: "not acceptable with unauthorized", status: http.StatusNotAcceptable, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateUnauthorized}},
		{name: "unavailable with disabled", status: http.StatusServiceUnavailable, body: StateResponse{ResponseVersion: 1, RequestContractVersion: 1, State: StateDisabled, RolloutMode: "disabled"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_ = json.NewEncoder(w).Encode(test.body)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Fetch(context.Background(), "token", testInstallationID, ""); err == nil {
				t.Fatal("Fetch() error = nil, want HTTP status/state mismatch")
			}
		})
	}
}

func TestClientRejectsUntrustedResponses(t *testing.T) {
	tests := []struct {
		name string
		body func(*Deployment) string
		etag string
	}{
		{name: "unknown deployment field", body: func(d *Deployment) string {
			data, _ := json.Marshal(d)
			return strings.TrimSuffix(string(data), "}") + `,"endpointConfig":{}}`
		}, etag: "valid"},
		{name: "known state field on wrong state", body: func(*Deployment) string {
			return `{"responseVersion":1,"requestContractVersion":1,"state":"no_active_policy","retryable":true}`
		}},
		{name: "missing etag", body: marshalDeployment},
		{name: "wrong etag", body: marshalDeployment, etag: strings.Repeat("f", 64)},
		{name: "trailing json", body: func(d *Deployment) string { return marshalDeployment(d) + `{}` }, etag: "valid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deployment := testDeployment(t, cedareval.RolloutModeObserve)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.etag == "valid" {
					w.Header().Set("ETag", `"`+deployment.DeploymentIdentity+`"`)
				} else if test.etag != "" {
					w.Header().Set("ETag", `"`+test.etag+`"`)
				}
				_, _ = w.Write([]byte(test.body(&deployment)))
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

func TestClientAcceptsMaximumDecodedPolicyDespiteJSONEscaping(t *testing.T) {
	deployment := testDeployment(t, cedareval.RolloutModeObserve)
	deployment.PolicyText = strings.Repeat(`"`, cedareval.PolicyMaxBytes)
	deployment.PolicyHash = cedareval.ComputePolicyHash(deployment.PolicyText)
	identity, err := cedareval.ComputeDeploymentIdentity(cedareval.DeploymentIdentityInput{
		ResponseVersion:        deployment.ResponseVersion,
		RequestContractVersion: deployment.RequestContractVersion,
		PolicyHash:             deployment.PolicyHash,
		RolloutMode:            string(deployment.RolloutMode),
		EvaluationPrincipal:    deployment.EvaluationPrincipal,
	})
	if err != nil {
		t.Fatal(err)
	}
	deployment.DeploymentIdentity = identity
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"`+deployment.DeploymentIdentity+`"`)
		_ = json.NewEncoder(w).Encode(deployment)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Fetch(context.Background(), "token", testInstallationID, ""); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientRejectsPlaintextRemoteURL(t *testing.T) {
	if _, err := NewClient("http://example.com", nil); err == nil {
		t.Fatal("NewClient() error = nil")
	}
}

func marshalDeployment(deployment *Deployment) string {
	data, _ := json.Marshal(deployment)
	return string(data)
}
