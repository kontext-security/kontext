package endpointconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

const (
	// ResponseVersion is the contract this build negotiates. The server serves
	// every version side by side and keys the response off the requested one,
	// so moving here changes only what this build asks for; released binaries
	// keep getting their shape and identity hashes. v3 dropped the retired
	// guardrail LLM flag and added the workspace's work-type switch; v4 adds
	// the endpoint's tool output compaction switch; v5 adds its Codex proxy
	// switch; v6 adds the hook inventory switch (ADR-0011); v7 adds the
	// desired state of Kontext's hooks (ADR-0012).
	ResponseVersion = 7
	// FallbackResponseVersion is what this build asks a server for that
	// answers ResponseVersion with 406 unsupported_version: one that predates
	// the desired hook state, which then reads as unmanaged.
	FallbackResponseVersion = 6
	MaxResponseBytes        = 64 * 1024
)

// identityDomain is the identity domain of a response version this build
// reads.
func identityDomain(version int) string {
	return "kontext:endpoint-config:v" + strconv.Itoa(version)
}

var sha256HexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// The desired states of Kontext's hooks (ADR-0012). There is no removed: the
// dashboard installs and repairs, and removing Kontext stays local or MDM.
const (
	HookStateUnmanaged = "unmanaged"
	HookStateInstalled = "installed"
)

// maxHookGeneration is the largest generation both sides read exactly: the
// cloud's numbers are IEEE doubles.
const maxHookGeneration = 1<<53 - 1

var repairNoncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

// HookState is what an admin asked for Kontext's hooks on this device.
type HookState struct {
	// Desired is HookStateUnmanaged (the daemon's own self-heal, as before
	// v7) or HookStateInstalled.
	Desired string `json:"desired"`
	// Generation goes up with every admin change to this device; the
	// endpoint acts on a generation newer than the last it reported.
	Generation int64 `json:"generation"`
	// RepairNonce, when new, asks for one re-check and repair now. Always
	// present on the wire, null when no repair was asked for.
	RepairNonce *string `json:"repairNonce"`
}

// UnmanagedHookState is the state of a device no admin has acted on.
var UnmanagedHookState = HookState{Desired: HookStateUnmanaged}

// UnmarshalJSON decodes strictly and requires every key: the identity covers
// all three, so a missing one can't be guessed.
func (h *HookState) UnmarshalJSON(data []byte) error {
	type plain HookState
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	for _, key := range []string{"desired", "generation", "repairNonce"} {
		raw, ok := keys[key]
		if !ok {
			return fmt.Errorf("json: hookState.%s is required", key)
		}
		// Only the nonce may be null: a null generation would decode as 0.
		if key != "repairNonce" && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("json: hookState.%s must not be null", key)
		}
	}
	if len(keys) != 3 {
		return errors.New("json: hookState has unknown fields")
	}
	*h = HookState(decoded)
	return nil
}

func (h HookState) validate() error {
	switch h.Desired {
	case HookStateUnmanaged, HookStateInstalled:
	default:
		return fmt.Errorf("endpoint configuration: unsupported desired hook state %q", h.Desired)
	}
	if h.Generation < 0 || h.Generation > maxHookGeneration {
		return fmt.Errorf("endpoint configuration: hook state generation %d out of range", h.Generation)
	}
	if h.RepairNonce != nil && !repairNoncePattern.MatchString(*h.RepairNonce) {
		return errors.New("endpoint configuration: invalid repair nonce")
	}
	return nil
}

// Nonce is the repair nonce, empty when none was asked for.
func (h HookState) Nonce() string {
	if h.RepairNonce == nil {
		return ""
	}
	return *h.RepairNonce
}

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
	// HookInventory is the deployment's switch for reporting hook inventory
	// (ADR-0011). Part of the hashed contract from v6, which always emits it;
	// v5 never does.
	HookInventory *bool `json:"hookInventory,omitempty"`
	// HookState is the desired state of Kontext's hooks on this device
	// (ADR-0012). Part of the hashed contract from v7, which always emits
	// it; v6 never does.
	HookState *HookState `json:"hookState,omitempty"`
	// nulls names the optional switches the response sent as JSON null,
	// which a pointer can't tell from absent: a version without the switch
	// must not carry its key at all.
	nulls []string
}

// UnmarshalJSON keeps the strict decoder's unknown-field check and records
// an optional switch sent as null.
func (c *Config) UnmarshalJSON(data []byte) error {
	type plain Config
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	// Go matches field names without case; the contract doesn't, and the
	// cloud's schema refuses `HookInventory` for `hookInventory`.
	for key := range keys {
		if !slices.Contains(configKeys(), key) {
			return fmt.Errorf("json: unknown field %q", key)
		}
	}
	*c = Config(decoded)
	for _, key := range []string{"codexProxy", "hookInventory", "hookState"} {
		if raw, ok := keys[key]; ok && string(bytes.TrimSpace(raw)) == "null" {
			c.nulls = append(c.nulls, key)
		}
	}
	return nil
}

// configKeys are Config's wire keys, spelled exactly.
func configKeys() []string {
	t := reflect.TypeOf(Config{})
	keys := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys = append(keys, name)
		}
	}
	return keys
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

// HookInventoryEnabled reports the switch; absent, as from a server that
// predates v6, reads as off, so nothing new is sent until the server asks.
func (c Config) HookInventoryEnabled() bool {
	return c.HookInventory != nil && *c.HookInventory
}

// DesiredHookState reports the desired hook state; absent, as from a server
// that predates v7, reads as unmanaged, so nothing changes until an admin
// acts.
func (c Config) DesiredHookState() HookState {
	if c.HookState == nil {
		return UnmanagedHookState
	}
	return *c.HookState
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
	if len(c.nulls) > 0 {
		return fmt.Errorf("endpoint configuration: %s must not be null", c.nulls[0])
	}
	if version >= 6 && c.HookInventory == nil {
		return errors.New("endpoint configuration: hookInventory is required")
	}
	if version < 6 && c.HookInventory != nil {
		return fmt.Errorf("endpoint configuration: hookInventory is not part of version %d", version)
	}
	if version >= 7 && c.HookState == nil {
		return errors.New("endpoint configuration: hookState is required")
	}
	if version < 7 && c.HookState != nil {
		return fmt.Errorf("endpoint configuration: hookState is not part of version %d", version)
	}
	if c.HookState != nil {
		if err := c.HookState.validate(); err != nil {
			return err
		}
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
	if version >= 6 {
		fields = append(fields, *config.HookInventory)
	}
	if version >= 7 {
		fields = append(fields, config.HookState.Desired, config.HookState.Generation, config.HookState.RepairNonce)
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
