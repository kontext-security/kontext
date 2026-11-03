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
	"strconv"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

const (
	// ResponseVersion is the contract this build negotiates. The server serves
	// every version side by side and keys the response off the requested one,
	// so moving here changes only what this build asks for; released binaries
	// keep getting their shape and identity hashes. v3 dropped the retired
	// guardrail LLM flag and added the workspace's work-type switch; v4 adds
	// the endpoint's tool output compaction switch; v5 adds its Codex proxy
	// switch.
	ResponseVersion = 5
	// FallbackResponseVersion is what this build asks a server for that
	// answers ResponseVersion with 406 unsupported_version: one that predates
	// the Codex proxy switch, which then reads as on.
	FallbackResponseVersion = 4
	MaxResponseBytes        = 64 * 1024
)

// identityDomain is the identity domain of a response version this build
// reads.
func identityDomain(version int) string {
	return "kontext:endpoint-config:v" + strconv.Itoa(version)
}

var sha256HexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Config struct {
	PayloadCaptureMode payloadcapture.Mode `json:"payloadCaptureMode"`
	// WorkTypeClassification is the workspace switch for type-of-work
	// classification: when set and capture is not omitted, each turn record
	// carries a redacted, bounded prompt excerpt. Part of the hashed contract.
	WorkTypeClassification *bool `json:"workTypeClassification"`
	// ToolOutputCompaction is the endpoint's switch for tool output
	// compaction. Part of the hashed contract.
	ToolOutputCompaction *bool `json:"toolOutputCompaction"`
	// CodexProxy is the endpoint's switch for routing Codex through the Codex
	// proxy, which also needs tool output compaction on. Part of the hashed
	// contract from v5, which always emits it; v4 never does.
	CodexProxy *bool `json:"codexProxy,omitempty"`
}

// WorkTypeClassificationEnabled reports the switch; absent reads as off.
func (c Config) WorkTypeClassificationEnabled() bool {
	return c.WorkTypeClassification != nil && *c.WorkTypeClassification
}

// ToolOutputCompactionEnabled reports the switch; absent reads as off.
func (c Config) ToolOutputCompactionEnabled() bool {
	return c.ToolOutputCompaction != nil && *c.ToolOutputCompaction
}

// CodexProxyEnabled reports the switch; absent, as from a server that
// predates v5, reads as on, leaving the Codex route to tool output compaction
// alone.
func (c Config) CodexProxyEnabled() bool {
	return c.CodexProxy == nil || *c.CodexProxy
}

// Validate checks the config as ResponseVersion has it.
func (c Config) Validate() error {
	return c.validate(ResponseVersion)
}

func (c Config) validate(version int) error {
	switch c.PayloadCaptureMode {
	case payloadcapture.ModeOmitted, payloadcapture.ModeSummary, payloadcapture.ModeFull:
	default:
		return fmt.Errorf("endpoint configuration: unsupported payload capture mode %q", c.PayloadCaptureMode)
	}
	// Each version always emits all of its switches. Guessing a value for a
	// missing one would put this side's identity out of step with the
	// server's and fail every response, so reject it as the contract
	// violation it is; likewise a switch the version has no place for, which
	// its identity would not cover.
	if c.WorkTypeClassification == nil {
		return errors.New("endpoint configuration: workTypeClassification is required")
	}
	if c.ToolOutputCompaction == nil {
		return errors.New("endpoint configuration: toolOutputCompaction is required")
	}
	if version >= 5 && c.CodexProxy == nil {
		return errors.New("endpoint configuration: codexProxy is required")
	}
	if version < 5 && c.CodexProxy != nil {
		return fmt.Errorf("endpoint configuration: codexProxy is not part of version %d", version)
	}
	return nil
}

type Response struct {
	ResponseVersion int    `json:"responseVersion"`
	Config          Config `json:"config"`
	ConfigIdentity  string `json:"configIdentity"`
}

func (r Response) Validate() error {
	if !readsVersion(r.ResponseVersion) {
		return fmt.Errorf("endpoint configuration: unsupported response version %d", r.ResponseVersion)
	}
	if err := r.Config.validate(r.ResponseVersion); err != nil {
		return err
	}
	if !sha256HexPattern.MatchString(r.ConfigIdentity) {
		return errors.New("endpoint configuration: invalid identity encoding")
	}
	identity, err := computeIdentity(r.ResponseVersion, r.Config)
	if err != nil {
		return err
	}
	if r.ConfigIdentity != identity {
		return errors.New("endpoint configuration: identity does not match config")
	}
	return nil
}

// readsVersion reports whether this build reads responses of version: the
// one it asks for, and the one it falls back to.
func readsVersion(version int) bool {
	return version == ResponseVersion || version == FallbackResponseVersion
}

// ComputeIdentity is config's identity under ResponseVersion.
func ComputeIdentity(config Config) (string, error) {
	return computeIdentity(ResponseVersion, config)
}

func computeIdentity(version int, config Config) (string, error) {
	if err := config.validate(version); err != nil {
		return "", err
	}
	// The preimage is a shared contract: the server hashes the same array in the
	// same order and sends the result as the ETag, and Validate rejects any
	// response whose identity does not match what this computes. Field order and
	// encoding are therefore load-bearing, not stylistic.
	fields := []any{
		identityDomain(version),
		version,
		string(config.PayloadCaptureMode),
		*config.WorkTypeClassification,
		*config.ToolOutputCompaction,
	}
	if version >= 5 {
		fields = append(fields, *config.CodexProxy)
	}
	preimage, err := json.Marshal(fields)
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
