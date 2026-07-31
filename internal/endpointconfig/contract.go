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
	// ResponseVersion is the contract this build negotiates. The server serves v1
	// and v2 side by side and keys the response off the requested version, so
	// moving here changes only what this build asks for; released binaries keep
	// getting the v1 shape and the v1 identity hashes.
	ResponseVersion  = 2
	identityDomain   = "kontext:endpoint-config:v2"
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
	// Required under v2 and part of the identity preimage, so a change to it alone
	// produces a different ETag and is actually observed by a conditional refresh.
	// It stays a pointer to keep "the server omitted this" distinguishable from
	// "the server said false": the former is a contract violation Validate
	// rejects, the latter is a directive to honour.
	GuardrailLLMEnabled *bool `json:"guardrailLlmEnabled"`
}

func (c Config) Validate() error {
	switch c.PayloadCaptureMode {
	case payloadcapture.ModeOmitted, payloadcapture.ModeSummary, payloadcapture.ModeFull:
	default:
		return fmt.Errorf("endpoint configuration: unsupported payload capture mode %q", c.PayloadCaptureMode)
	}
	// v2 always emits the flag. Guessing a value for a missing one would put this
	// side's identity out of step with the server's and fail every response, so
	// reject it as the contract violation it is.
	if c.GuardrailLLMEnabled == nil {
		return errors.New("endpoint configuration: guardrailLlmEnabled is required")
	}
	return nil
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
	// The preimage is a shared contract: the server hashes the same array in the
	// same order and sends the result as the ETag, and Validate rejects any
	// response whose identity does not match what this computes. Field order and
	// encoding are therefore load-bearing, not stylistic.
	preimage, err := json.Marshal([]any{
		identityDomain,
		ResponseVersion,
		string(config.PayloadCaptureMode),
		*config.GuardrailLLMEnabled,
	})
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
