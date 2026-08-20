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
)

const (
	ResponseVersion        = 1
	RequestContractVersion = 1
	// A valid 1 MiB UTF-8 policy can expand to six bytes per input byte when
	// represented with JSON Unicode escapes. Bound the wire independently from
	// the decoded policy contract so valid responses are never truncated.
	MaxResponseBytes = 6*cedareval.PolicyMaxBytes + 64*1024
)

var sha256HexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Deployment struct {
	ResponseVersion        int                           `json:"responseVersion"`
	RequestContractVersion int                           `json:"requestContractVersion"`
	PolicyHash             string                        `json:"policyHash"`
	RolloutMode            cedareval.RolloutMode         `json:"rolloutMode"`
	EvaluationPrincipal    cedareval.EvaluationPrincipal `json:"evaluationPrincipal"`
	PolicyText             string                        `json:"policyText"`
	Signature              string                        `json:"signature,omitempty"`
	DeploymentIdentity     string                        `json:"deploymentIdentity"`
}

func (d Deployment) Validate() error {
	if d.ResponseVersion != ResponseVersion {
		return fmt.Errorf("cedar policy: unsupported response version %d", d.ResponseVersion)
	}
	if d.RequestContractVersion != RequestContractVersion {
		return fmt.Errorf("cedar policy: unsupported request contract version %d", d.RequestContractVersion)
	}
	if len([]byte(d.PolicyText)) > cedareval.PolicyMaxBytes {
		return fmt.Errorf("cedar policy: policy text exceeds %d bytes", cedareval.PolicyMaxBytes)
	}
	if d.RolloutMode != cedareval.RolloutModeObserve && d.RolloutMode != cedareval.RolloutModeEnforce {
		return fmt.Errorf("cedar policy: unsupported rollout mode %q", d.RolloutMode)
	}
	principalLength := utf16Length(d.EvaluationPrincipal.EntityID)
	if d.EvaluationPrincipal.EntityType != cedareval.PrincipalEntityType || principalLength == 0 || principalLength > 1024 {
		return errors.New("cedar policy: invalid evaluation principal")
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
	expectedPolicyHash := cedareval.ComputePolicyHash(d.PolicyText)
	if d.PolicyHash != expectedPolicyHash {
		return errors.New("cedar policy: policy hash does not match policy text")
	}
	expectedDeploymentIdentity, err := cedareval.ComputeDeploymentIdentity(cedareval.DeploymentIdentityInput{
		ResponseVersion:        d.ResponseVersion,
		RequestContractVersion: d.RequestContractVersion,
		PolicyHash:             d.PolicyHash,
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
	case StateUnsupportedVersion:
		if len(s.SupportedResponseVersions) != 1 || s.SupportedResponseVersions[0] != ResponseVersion ||
			len(s.SupportedRequestContractVersions) != 1 || s.SupportedRequestContractVersions[0] != RequestContractVersion {
			return errors.New("cedar policy: unsupported-version response has invalid supported versions")
		}
	case StateUnavailable:
		if !s.Retryable {
			return errors.New("cedar policy: unavailable response must be retryable")
		}
	default:
		return fmt.Errorf("cedar policy: unknown response state %q", s.State)
	}
	return nil
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
