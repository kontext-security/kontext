package cedarpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf16"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/toolcatalog"
)

const (
	ResponseVersion        = 2
	RequestContractVersion = 2
	// A valid 1 MiB UTF-8 policy can expand to six bytes per input byte when
	// represented with JSON Unicode escapes. Bound the wire independently from
	// the decoded policy contract so valid responses are never truncated.
	MaxResponseBytes = 12*cedareval.PolicyMaxBytes + 64*1024
)

var sha256HexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Deployment struct {
	ResponseVersion        int                           `json:"responseVersion"`
	RequestContractVersion int                           `json:"requestContractVersion"`
	PolicySet              PolicySet                     `json:"policySet"`
	Schema                 Schema                        `json:"schema"`
	ToolCatalogDigest      string                        `json:"toolCatalogDigest"`
	RolloutMode            cedareval.RolloutMode         `json:"rolloutMode"`
	EvaluationPrincipal    cedareval.EvaluationPrincipal `json:"evaluationPrincipal"`
	DeploymentIdentity     string                        `json:"deploymentIdentity"`
}

// LegacyDeployment is the version-1 shape kept only so an endpoint can finish
// enforcing its last valid policy while it upgrades offline.
type LegacyDeployment struct {
	ResponseVersion        int                           `json:"responseVersion"`
	RequestContractVersion int                           `json:"requestContractVersion"`
	PolicyHash             string                        `json:"policyHash"`
	RolloutMode            cedareval.RolloutMode         `json:"rolloutMode"`
	EvaluationPrincipal    cedareval.EvaluationPrincipal `json:"evaluationPrincipal"`
	PolicyText             string                        `json:"policyText"`
	Signature              string                        `json:"signature,omitempty"`
	DeploymentIdentity     string                        `json:"deploymentIdentity"`
}

func (d LegacyDeployment) Validate() error {
	if d.ResponseVersion != 1 || d.RequestContractVersion != 1 {
		return errors.New("cedar policy: legacy deployment uses unsupported contract versions")
	}
	if len([]byte(d.PolicyText)) > cedareval.PolicyMaxBytes {
		return fmt.Errorf("cedar policy: policy text exceeds %d bytes", cedareval.PolicyMaxBytes)
	}
	if d.RolloutMode != cedareval.RolloutModeObserve && d.RolloutMode != cedareval.RolloutModeEnforce {
		return fmt.Errorf("cedar policy: unsupported rollout mode %q", d.RolloutMode)
	}
	principalLength := utf16Length(d.EvaluationPrincipal.EntityID)
	if d.EvaluationPrincipal.EntityType != cedareval.PrincipalEntityType || principalLength == 0 || principalLength > 1024 {
		return errors.New("cedar policy: invalid legacy evaluation principal")
	}
	if d.Signature != "" {
		signatureLength := utf16Length(d.Signature)
		if signatureLength == 0 || signatureLength > 8192 {
			return errors.New("cedar policy: invalid signature")
		}
	}
	if !sha256HexPattern.MatchString(d.PolicyHash) || !sha256HexPattern.MatchString(d.DeploymentIdentity) {
		return errors.New("cedar policy: invalid hash encoding")
	}
	if d.PolicyHash != cedareval.ComputePolicyHash(d.PolicyText) {
		return errors.New("cedar policy: policy hash does not match policy text")
	}
	expected, err := cedareval.ComputeDeploymentIdentity(cedareval.DeploymentIdentityInput{
		ResponseVersion:        d.ResponseVersion,
		RequestContractVersion: d.RequestContractVersion,
		PolicyHash:             d.PolicyHash,
		RolloutMode:            string(d.RolloutMode),
		EvaluationPrincipal:    d.EvaluationPrincipal,
	})
	if err != nil {
		return err
	}
	if d.DeploymentIdentity != expected {
		return errors.New("cedar policy: deployment identity does not match response metadata")
	}
	return nil
}

type PolicySet struct {
	Source     string `json:"source"`
	SourceHash string `json:"sourceHash"`
}

type Schema struct {
	Source string `json:"source"`
	Hash   string `json:"hash"`
}

func (d Deployment) Validate() error {
	if d.ResponseVersion != ResponseVersion {
		return fmt.Errorf("cedar policy: unsupported response version %d", d.ResponseVersion)
	}
	if d.RequestContractVersion != RequestContractVersion {
		return fmt.Errorf("cedar policy: unsupported request contract version %d", d.RequestContractVersion)
	}
	if len([]byte(d.PolicySet.Source)) > cedareval.PolicyMaxBytes {
		return fmt.Errorf("cedar policy: policy text exceeds %d bytes", cedareval.PolicyMaxBytes)
	}
	if len([]byte(d.Schema.Source)) == 0 || len([]byte(d.Schema.Source)) > cedareval.PolicyMaxBytes {
		return fmt.Errorf("cedar policy: schema source must contain 1 to %d bytes", cedareval.PolicyMaxBytes)
	}
	if d.RolloutMode != cedareval.RolloutModeObserve && d.RolloutMode != cedareval.RolloutModeEnforce {
		return fmt.Errorf("cedar policy: unsupported rollout mode %q", d.RolloutMode)
	}
	principalLength := utf16Length(d.EvaluationPrincipal.EntityID)
	if d.EvaluationPrincipal.EntityType != cedareval.EndpointEntityTypeV2 || principalLength == 0 || principalLength > 1024 {
		return errors.New("cedar policy: invalid evaluation principal")
	}
	if !sha256HexPattern.MatchString(d.PolicySet.SourceHash) ||
		!sha256HexPattern.MatchString(d.Schema.Hash) ||
		!sha256HexPattern.MatchString(d.ToolCatalogDigest) ||
		!sha256HexPattern.MatchString(d.DeploymentIdentity) {
		return errors.New("cedar policy: invalid hash encoding")
	}
	expectedPolicyHash := cedareval.ComputePolicyHash(d.PolicySet.Source)
	if d.PolicySet.SourceHash != expectedPolicyHash {
		return errors.New("cedar policy: policy hash does not match policy text")
	}
	if d.Schema.Hash != cedareval.ComputeSchemaHash(d.Schema.Source) {
		return errors.New("cedar policy: schema hash does not match schema source")
	}
	expectedDeploymentIdentity, err := cedareval.ComputeDeploymentIdentityV2(cedareval.DeploymentIdentityV2Input{
		ResponseVersion:        d.ResponseVersion,
		RequestContractVersion: d.RequestContractVersion,
		PolicySetSourceHash:    d.PolicySet.SourceHash,
		SchemaHash:             d.Schema.Hash,
		ToolCatalogDigest:      d.ToolCatalogDigest,
		RolloutMode:            string(d.RolloutMode),
		EvaluationPrincipal:    d.EvaluationPrincipal,
	})
	if err != nil {
		return err
	}
	if d.DeploymentIdentity != expectedDeploymentIdentity {
		return errors.New("cedar policy: deployment identity does not match response metadata")
	}
	return nil
}

// MatchesToolCatalog reports whether the deployment was compiled against
// the tool catalog this binary carries. A mismatch is version skew between
// the CLI and the cloud, not corruption: the policy still evaluates against
// the ids this endpoint knows, so it is flagged rather than rejected.
func (d Deployment) MatchesToolCatalog() bool {
	return d.ToolCatalogDigest == toolcatalog.Digest()
}

type State string

const (
	StateSuccess              State = "success"
	StateNotModified          State = "not_modified"
	StateDisabled             State = "disabled"
	StateNoActivePolicy       State = "no_active_policy"
	StatePrincipalUnavailable State = "principal_unavailable"
	StateUnsupportedVersion   State = "unsupported_version"
	StateUnauthorized         State = "unauthorized"
	StateUnavailable          State = "unavailable"
)

type StateResponse struct {
	ResponseVersion                  int    `json:"responseVersion"`
	RequestContractVersion           int    `json:"requestContractVersion"`
	State                            State  `json:"state"`
	DeploymentIdentity               string `json:"deploymentIdentity,omitempty"`
	RolloutMode                      string `json:"rolloutMode,omitempty"`
	SupportedResponseVersions        []int  `json:"supportedResponseVersions,omitempty"`
	SupportedRequestContractVersions []int  `json:"supportedRequestContractVersions,omitempty"`
	Retryable                        bool   `json:"retryable,omitempty"`
}

func (s *StateResponse) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var probe struct {
		State State `json:"state"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	allowed := []string{"responseVersion", "requestContractVersion", "state"}
	switch probe.State {
	case StateNotModified:
		allowed = append(allowed, "deploymentIdentity")
	case StateDisabled:
		allowed = append(allowed, "rolloutMode")
	case StateNoActivePolicy, StatePrincipalUnavailable, StateUnauthorized:
	case StateUnsupportedVersion:
		allowed = append(allowed, "supportedResponseVersions", "supportedRequestContractVersions")
	case StateUnavailable:
		allowed = append(allowed, "retryable")
	default:
		return fmt.Errorf("cedar policy: unknown response state %q", probe.State)
	}
	if err := requireExactFields(fields, allowed); err != nil {
		return err
	}
	type wireState StateResponse
	var decoded wireState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*s = StateResponse(decoded)
	return s.Validate()
}

func (s StateResponse) Validate() error {
	switch s.State {
	case StateUnsupportedVersion:
		if s.ResponseVersion != 1 || s.RequestContractVersion != 1 ||
			!supportedVersionsValid(s.SupportedResponseVersions) ||
			!supportedVersionsValid(s.SupportedRequestContractVersions) {
			return errors.New("cedar policy: unsupported-version response has invalid supported versions")
		}
		return nil
	}
	if s.ResponseVersion != ResponseVersion || s.RequestContractVersion != RequestContractVersion {
		return errors.New("cedar policy: state response uses unsupported contract versions")
	}
	switch s.State {
	case StateNotModified:
		if !sha256HexPattern.MatchString(s.DeploymentIdentity) {
			return errors.New("cedar policy: not-modified response has invalid deployment identity")
		}
	case StateDisabled:
		if s.RolloutMode != string(cedareval.RolloutModeDisabled) {
			return errors.New("cedar policy: disabled response must declare disabled rollout mode")
		}
	case StateNoActivePolicy, StatePrincipalUnavailable, StateUnauthorized:
	case StateUnavailable:
		if !s.Retryable {
			return errors.New("cedar policy: unavailable response must be retryable")
		}
	default:
		return fmt.Errorf("cedar policy: unknown response state %q", s.State)
	}
	return nil
}

func supportedVersionsValid(versions []int) bool {
	return len(versions) == 1 && versions[0] == 1 ||
		len(versions) == 2 && versions[0] == 1 && versions[1] == 2
}

func requireExactFields(fields map[string]json.RawMessage, allowed []string) error {
	if len(fields) != len(allowed) {
		return errors.New("cedar policy: state response has missing or unexpected fields")
	}
	for _, field := range allowed {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("cedar policy: state response is missing field %q", field)
		}
	}
	return nil
}

func decodeStrict[T any](reader io.Reader, target *T) error {
	limited := io.LimitReader(reader, MaxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > MaxResponseBytes {
		return fmt.Errorf("cedar policy: response exceeds %d bytes", MaxResponseBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("cedar policy: unexpected trailing json value")
	}
	return nil
}

func utf16Length(value string) int {
	return len(utf16.Encode([]rune(value)))
}
