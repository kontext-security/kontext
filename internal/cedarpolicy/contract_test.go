package cedarpolicy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
)

func TestDeploymentValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Deployment)
		wantErr string
	}{
		{name: "valid response"},
		{
			name: "policy hash mismatch",
			mutate: func(d *Deployment) {
				d.PolicySet.SourceHash = strings.Repeat("a", 64)
			},
			wantErr: "policy hash",
		},
		{
			name: "deployment identity mismatch",
			mutate: func(d *Deployment) {
				d.DeploymentIdentity = strings.Repeat("b", 64)
			},
			wantErr: "deployment identity",
		},
		{
			name: "unsupported mode",
			mutate: func(d *Deployment) {
				d.RolloutMode = "future"
			},
			wantErr: "rollout mode",
		},
		{
			name: "schema hash mismatch",
			mutate: func(d *Deployment) {
				d.Schema.Hash = strings.Repeat("a", 64)
			},
			wantErr: "schema hash",
		},
		{
			// Version skew between CLI and cloud is flagged by the cache,
			// not rejected here: the identity still binds the digest.
			name: "tool catalog digest skew",
			mutate: func(d *Deployment) {
				d.ToolCatalogDigest = strings.Repeat("0", 64)
				d.DeploymentIdentity = testDeploymentIdentity(t, *d)
			},
		},
		{
			name: "malformed tool catalog digest",
			mutate: func(d *Deployment) {
				d.ToolCatalogDigest = "not-a-digest"
			},
			wantErr: "hash encoding",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deployment := testDeployment(t, cedareval.RolloutModeObserve)
			if test.mutate != nil {
				test.mutate(&deployment)
			}
			err := deployment.Validate()
			if test.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantErr == "" && deployment.MatchesToolCatalog() != (deployment.ToolCatalogDigest == testToolCatalogDigest) {
				t.Fatalf("MatchesToolCatalog() = %t for digest %q", deployment.MatchesToolCatalog(), deployment.ToolCatalogDigest)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestStateResponseRejectsWrongShape(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `{"responseVersion":2,"requestContractVersion":2,"state":"no_active_policy","extra":true}`,
		},
		{
			name: "known field on wrong state",
			body: `{"responseVersion":2,"requestContractVersion":2,"state":"no_active_policy","retryable":true}`,
		},
		{
			name: "missing disabled mode",
			body: `{"responseVersion":2,"requestContractVersion":2,"state":"disabled"}`,
		},
		{
			name: "unsupported versions not exact",
			body: `{"responseVersion":2,"requestContractVersion":2,"state":"unsupported_version","supportedResponseVersions":[1,2],"supportedRequestContractVersions":[2]}`,
		},
		{
			name: "retired principal detail state",
			body: `{"responseVersion":2,"requestContractVersion":2,"state":"principal_unmatched"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var response StateResponse
			if err := json.Unmarshal([]byte(test.body), &response); err == nil {
				t.Fatal("Unmarshal() error = nil")
			}
		})
	}
}

func TestDecodeStrictRejectsTrailingData(t *testing.T) {
	body := `{"responseVersion":2,"requestContractVersion":2,"state":"no_active_policy"}{}`
	var response StateResponse
	if err := decodeStrict(strings.NewReader(body), &response); err == nil {
		t.Fatal("decodeStrict() error = nil")
	}
}
