package promptpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

const (
	RequestContractVersion = 2
	ResponseVersion        = 2
	CedarRequestVersion    = 1
	MaxPromptBytes         = 65_536
	maxPolicySetBytes      = 1_048_576
	policySetHashDomain    = "kontext:cedar-policy:v1\x00"
	bundleIdentityDomain   = "kontext:effective-authorization-bundle:v2"
)

var (
	sha256HexPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	installationIDPattern = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{32}$`)
)

type PutRequest struct {
	RequestContractVersion           int    `json:"requestContractVersion"`
	Prompt                           string `json:"prompt"`
	ExpectedParentDeploymentIdentity string `json:"expectedParentDeploymentIdentity"`
}

type Bundle struct {
	ResponseVersion        int                 `json:"responseVersion"`
	RequestContractVersion int                 `json:"requestContractVersion"`
	DeploymentIdentity     string              `json:"deploymentIdentity"`
	RolloutMode            string              `json:"rolloutMode"`
	Audience               Audience            `json:"audience"`
	Parent                 ParentPolicySet     `json:"parent"`
	PolicySet              EffectivePolicySet  `json:"policySet"`
	EvaluationPrincipal    EvaluationPrincipal `json:"evaluationPrincipal"`
	ValidFrom              string              `json:"validFrom"`
	ExpiresAt              string              `json:"expiresAt"`
}

type Audience struct {
	OrganizationID         string `json:"organizationId"`
	InstallationID         string `json:"installationId"`
	AuthorizationSessionID string `json:"authorizationSessionId"`
	PromptSequence         uint64 `json:"promptSequence"`
}

type ParentPolicySet struct {
	PolicySetVersionID  string `json:"policySetVersionId"`
	PolicySetSourceHash string `json:"policySetSourceHash"`
	DeploymentIdentity  string `json:"deploymentIdentity"`
}

type EffectivePolicySet struct {
	PolicySetVersionID string `json:"policySetVersionId"`
	Source             string `json:"source"`
	SourceHash         string `json:"sourceHash"`
	StaticPolicyCount  int    `json:"staticPolicyCount"`
}

type EvaluationPrincipal struct {
	EntityType string `json:"entityType"`
	EntityID   string `json:"entityId"`
}

type ErrorResponse struct {
	ResponseVersion int    `json:"responseVersion"`
	Code            string `json:"code"`
	Retryable       bool   `json:"retryable"`
}

func DecodeBundle(data []byte) (Bundle, error) {
	var bundle Bundle
	if err := decodeStrict(data, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode prompt-policy bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (b Bundle) Validate() error {
	if b.ResponseVersion != ResponseVersion || b.RequestContractVersion != CedarRequestVersion {
		return errors.New("unsupported prompt-policy bundle version")
	}
	if b.RolloutMode != "observe" && b.RolloutMode != "enforce" {
		return errors.New("invalid prompt-policy rollout mode")
	}
	if b.Audience.OrganizationID == "" || !installationIDPattern.MatchString(b.Audience.InstallationID) || b.Audience.AuthorizationSessionID == "" || b.Audience.PromptSequence == 0 {
		return errors.New("invalid prompt-policy audience")
	}
	if len([]byte(b.PolicySet.Source)) > maxPolicySetBytes || b.PolicySet.StaticPolicyCount < 0 {
		return errors.New("invalid prompt-policy policy set")
	}
	if sourceHash(b.PolicySet.Source) != b.PolicySet.SourceHash {
		return errors.New("prompt-policy source hash mismatch")
	}
	for _, value := range []string{b.DeploymentIdentity, b.Parent.PolicySetSourceHash, b.Parent.DeploymentIdentity, b.PolicySet.SourceHash} {
		if !sha256HexPattern.MatchString(value) {
			return errors.New("invalid prompt-policy hash")
		}
	}
	validFrom, err := time.Parse(time.RFC3339Nano, b.ValidFrom)
	if err != nil {
		return errors.New("invalid prompt-policy validFrom")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	if err != nil || !expiresAt.After(validFrom) {
		return errors.New("invalid prompt-policy expiry")
	}
	identity, err := b.ComputeDeploymentIdentity()
	if err != nil {
		return err
	}
	if identity != b.DeploymentIdentity {
		return errors.New("prompt-policy deployment identity mismatch")
	}
	return nil
}

func (b Bundle) ComputeDeploymentIdentity() (string, error) {
	preimage, err := json.Marshal([]any{
		bundleIdentityDomain,
		b.ResponseVersion,
		b.RequestContractVersion,
		b.RolloutMode,
		b.Audience.OrganizationID,
		b.Audience.InstallationID,
		b.Audience.AuthorizationSessionID,
		b.Audience.PromptSequence,
		b.Parent.PolicySetVersionID,
		b.Parent.PolicySetSourceHash,
		b.Parent.DeploymentIdentity,
		b.PolicySet.PolicySetVersionID,
		b.PolicySet.SourceHash,
		b.PolicySet.StaticPolicyCount,
		b.EvaluationPrincipal.EntityType,
		b.EvaluationPrincipal.EntityID,
		b.ValidFrom,
		b.ExpiresAt,
	})
	if err != nil {
		return "", fmt.Errorf("encode deployment identity: %w", err)
	}
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}

func sourceHash(source string) string {
	digest := sha256.Sum256([]byte(policySetHashDomain + source))
	return hex.EncodeToString(digest[:])
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}
