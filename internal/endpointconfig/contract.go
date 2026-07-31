package endpointconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

const (
	ResponseVersion  = 1
	identityDomain   = "kontext:endpoint-config:v1"
	MaxResponseBytes = 64 * 1024
)

var sha256HexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Config struct {
	PayloadCaptureMode payloadcapture.Mode `json:"payloadCaptureMode"`
	// GuardrailLLMEnabled is the org's kill switch for the risk classifier's
	// guardrail LLM. Optional, and absent means enabled — note this is the
	// OPPOSITE default to PayloadCaptureMode, deliberately. Capture falls back
	// to the privacy-safe "record nothing" whenever the configuration is
	// unconfirmed; this flag exists only to turn the LLM off, so treating
	// "unconfirmed" as off would let a transient fetch failure silently disable
	// the classifier's second opinion with nobody noticing. Resolve it through
	// riskclassifier.ResolveLLMEnabled rather than reading it directly.
	//
	// NOT YET EFFECTIVE REMOTELY: ComputeIdentity's preimage covers
	// PayloadCaptureMode alone, and that identity is the shared ETag both sides
	// must agree on, so flipping only this field leaves the identity unchanged
	// and a conditional refresh reuses the cached config. Adding it to the
	// preimage here alone would instead break Validate against every response
	// the current server sends. Both halves have to move together, with
	// ResponseVersion and identityDomain bumped. Inert until then, since the
	// server does not send the field; the local override still works. See the
	// remote kill switch section of docs/guard.md.
	GuardrailLLMEnabled *bool `json:"guardrailLlmEnabled,omitempty"`
}

func (c Config) Validate() error {
	switch c.PayloadCaptureMode {
	case payloadcapture.ModeOmitted, payloadcapture.ModeSummary, payloadcapture.ModeFull:
		return nil
	default:
		return fmt.Errorf("endpoint configuration: unsupported payload capture mode %q", c.PayloadCaptureMode)
	}
}

type Response struct {
	ResponseVersion int    `json:"responseVersion"`
	Config          Config `json:"config"`
	ConfigIdentity  string `json:"configIdentity"`
}

func (r Response) Validate() error {
	if r.ResponseVersion != ResponseVersion {
		return fmt.Errorf("endpoint configuration: unsupported response version %d", r.ResponseVersion)
	}
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if !sha256HexPattern.MatchString(r.ConfigIdentity) {
		return errors.New("endpoint configuration: invalid identity encoding")
	}
	identity, err := ComputeIdentity(r.Config)
	if err != nil {
		return err
	}
	if r.ConfigIdentity != identity {
		return errors.New("endpoint configuration: identity does not match config")
	}
	return nil
}

func ComputeIdentity(config Config) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	preimage, err := json.Marshal([]any{identityDomain, ResponseVersion, string(config.PayloadCaptureMode)})
	if err != nil {
		return "", fmt.Errorf("endpoint configuration: encode identity preimage: %w", err)
	}
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}

func decodeStrict[T any](reader io.Reader, target *T) error {
	limited := io.LimitReader(reader, MaxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > MaxResponseBytes {
		return fmt.Errorf("endpoint configuration: response exceeds %d bytes", MaxResponseBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("endpoint configuration: unexpected trailing json value")
	}
	return nil
}
