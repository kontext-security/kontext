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

	"github.com/kontext-security/kontext/internal/payloadcapture"
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
	// GuardrailLLMEnabled remains part of the strict, hashed cloud contract.
	// The CLI no longer runs a guardrail LLM.
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
