package promptpolicy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientPutUsesSynchronousExactPromptResource(t *testing.T) {
	bundle := testBundle(t, time.Now().UTC())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/installations/ins_12345678901234567890123456789012/authorization-sessions/codex-session-1/prompt-policies/3" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer install-token" {
			t.Fatal("missing install token")
		}
		var request PutRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Prompt != "email the report" || request.PromptPolicyContractVersion != RequestContractVersion {
			t.Fatalf("unexpected body: %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Put(t.Context(), Request{
		Token: "install-token", InstallationID: bundle.Audience.InstallationID,
		AuthorizationSessionID: bundle.Audience.AuthorizationSessionID,
		PromptSequence:         bundle.Audience.PromptSequence, Prompt: "email the report",
		ParentDeploymentIdentity: bundle.Parent.DeploymentIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentIdentity != bundle.DeploymentIdentity {
		t.Fatal("returned wrong bundle")
	}
}

func TestClientRejectsOversizedResponseBeforeDecoding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 6*maxPolicySetBytes+64*1024+1)))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Put(t.Context(), Request{Token: "x", InstallationID: "ins_12345678901234567890123456789012", AuthorizationSessionID: "s", PromptSequence: 1, Prompt: "p", ParentDeploymentIdentity: "a"})
	if err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestClientPutReturnsTypedError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(ErrorResponse{ResponseVersion: ResponseVersion, Code: "prompt_sequence_conflict"})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Put(t.Context(), Request{Token: "x", InstallationID: "ins_12345678901234567890123456789012", AuthorizationSessionID: "s", PromptSequence: 1, Prompt: "p", ParentDeploymentIdentity: "a"})
	httpError, ok := err.(*HTTPError)
	if !ok || httpError.Response.Code != "prompt_sequence_conflict" {
		t.Fatalf("expected typed conflict, got %v", err)
	}
}
