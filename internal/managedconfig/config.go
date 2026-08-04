package managedconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

const (
	Version = "managed-install-v1"
	// Mode is the default posture; ModeEnforce turns daemon decisions into
	// real denies at every hook edge (Claude Code and Cowork alike).
	// ModeRemote delegates the posture to the fetched policy deployment's
	// rollout mode: the endpoint observes until the deployment says enforce,
	// with no local reinstall needed to flip. Observe and enforce remain
	// static pins for deployments that must not change posture remotely.
	Mode        = "observe"
	ModeEnforce = "enforce"
	ModeRemote  = "remote"
	Agent       = "claude"

	DefaultPath  = "/Library/Application Support/Kontext/managed.json"
	EnvPath      = "KONTEXT_MANAGED_CONFIG"
	EnvAllowHTTP = "KONTEXT_MANAGED_ALLOW_HTTP_LOCALHOST"

	DeploymentVersionPath    = "/Library/Application Support/Kontext/deployment-version"
	EnvDeploymentVersionPath = "KONTEXT_DEPLOYMENT_VERSION_PATH"
)

var ErrNotManaged = errors.New("managed config not found")

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Scope identifies which managed config a process resolved: an explicit env
// override, the system-wide MDM install under /Library, or a per-user
// self-serve install written by `kontext setup`.
type Scope string

const (
	ScopeEnv    Scope = "env"
	ScopeSystem Scope = "system"
	ScopeUser   Scope = "user"
)

// Test seam: ResolvePath stats this instead of the /Library literal so tests
// can simulate the presence/absence of an MDM install.
var systemPath = DefaultPath

// UserPath is the self-serve managed config location, or "" when the home
// directory cannot be resolved.
//
// With a profile active this is that profile's config; without one it is the
// legacy unprofiled path, so an install that predates profiles resolves exactly
// what it always did. Any profile-resolution failure — including a corrupt
// active pointer — also falls back to the legacy path. That is safe rather than
// merely lenient: migration MOVES the legacy config into the profile
// directory, so post-migration the fallback names a file that does not exist,
// Load returns ErrNotManaged, and the daemon parks instead of streaming with
// the wrong workspace's credentials. `kontext doctor` validates the pointer
// separately so the failure reads as "broken pointer" and not "not configured".
func UserPath() string {
	if path, err := profile.ActiveManagedConfigPath(); err == nil {
		return path
	}
	return LegacyUserPath()
}

// LegacyUserPath is the pre-profile self-serve config location.
func LegacyUserPath() string {
	return profile.LegacyPath(profile.ManagedConfigFile)
}

// ResolvePath picks the managed config path for this process. Precedence is
// security-relevant: an existing SYSTEM (MDM) config always wins over the
// user-level one, so an org-managed Mac cannot be re-pointed by a self-serve
// setup. The system path is selected whenever it exists OR whenever its
// existence cannot be determined (any stat error other than not-exist), so a
// broken/unreadable MDM config surfaces as an error instead of silently
// falling through to user config.
func ResolvePath() (string, Scope) {
	if path := strings.TrimSpace(os.Getenv(EnvPath)); path != "" {
		return path, ScopeEnv
	}
	if _, err := os.Lstat(systemPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return systemPath, ScopeSystem
	}
	if user := UserPath(); user != "" {
		return user, ScopeUser
	}
	return systemPath, ScopeSystem
}

type Config struct {
	Version  string `json:"version"`
	CloudURL string `json:"cloud_url"`
	Mode     string `json:"mode"`
	Agent    string `json:"agent"`
	// AllowHTTPLoopback permits a plaintext http cloud_url when — and only
	// when — the host is loopback. It exists so a local-development endpoint is
	// declared on disk rather than through an environment variable the daemon
	// never sees. Omitted from the JSON when false so production configs are
	// byte-identical to what they were before this field existed.
	AllowHTTPLoopback bool        `json:"allow_http_loopback,omitempty"`
	Credentials       Credentials `json:"credentials"`
	Device            Device      `json:"device,omitempty"`
	// UnsupportedMode carries the raw mode this build did not recognize, after
	// Mode has already been rewritten to the observe fallback. Empty on every
	// config whose mode this build understands, so callers can treat a
	// non-empty value as "the endpoint is running degraded" and say so.
	UnsupportedMode     string `json:"-"`
	LegacyCoworkEnabled bool   `json:"-"`
}

type configFile struct {
	Version              string          `json:"version"`
	LegacyOrganizationID json.RawMessage `json:"organization_id,omitempty"`
	// LegacyCoworkEnabled is accepted for backward-compatible migration checks.
	// Cowork is now observed through the managed-settings hook path (the hook
	// wrapper labels Cowork from session context), not a separate observer.
	// When old configs still set this flag, daemon startup verifies that the
	// managed hooks are present and enabled so missing coverage fails loudly.
	LegacyCoworkEnabled json.RawMessage `json:"cowork_enabled,omitempty"`
	CloudURL            string          `json:"cloud_url"`
	Mode                string          `json:"mode"`
	Agent               string          `json:"agent"`
	AllowHTTPLoopback   bool            `json:"allow_http_loopback,omitempty"`
	Credentials         Credentials     `json:"credentials"`
	Device              Device          `json:"device,omitempty"`
}

type Credentials struct {
	InstallTokenRef TokenRef `json:"install_token_ref"`
}

type TokenRef struct {
	Source string
	Name   string
}

type Device struct {
	Label string `json:"label,omitempty"`
	// UserEmail is the device user's email as known by the MDM (e.g. an
	// Addigy fact written by the pkg postinstall). The hosted API matches it
	// against the SCIM-provisioned directory to resolve group policies.
	UserEmail string `json:"user_email,omitempty"`
}

type LoadedConfig struct {
	Config   Config
	Path     string
	Checksum string
	// Scope reflects how the path was resolved (env/system/user). LoadFile
	// callers that bypass ResolvePath get an empty Scope.
	Scope Scope
}

// DeploymentVersion returns the installed package version recorded in the
// deployment marker, or "" if the marker is missing or unreadable.
func DeploymentVersion() string {
	path := DeploymentVersionPath
	if override := strings.TrimSpace(os.Getenv(EnvDeploymentVersionPath)); override != "" {
		path = override
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func Load() (LoadedConfig, error) {
	path, scope := ResolvePath()
	loaded, err := LoadFile(path)
	if err != nil {
		return LoadedConfig{}, err
	}
	loaded.Scope = scope
	// The loopback-http opt-in is a developer convenience and has no business on
	// an organization-managed Mac: an MDM deployment streaming governance records
	// in plaintext to something listening on localhost is never intended, and
	// refusing loudly beats serving it. Scope is only known here, which is why
	// this is not in Parse — LoadFile stays the scope-agnostic primitive.
	if scope == ScopeSystem && loaded.Config.AllowHTTPLoopback {
		return LoadedConfig{}, fmt.Errorf(
			"allow_http_loopback is not permitted in an organization-managed config (%s)", path)
	}
	return loaded, nil
}

func LoadFile(path string) (LoadedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LoadedConfig{}, ErrNotManaged
		}
		return LoadedConfig{}, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return LoadedConfig{}, err
	}
	digest := sha256.Sum256(data)
	return LoadedConfig{
		Config:   cfg,
		Path:     path,
		Checksum: hex.EncodeToString(digest[:]),
	}, nil
}

func Parse(data []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var file configFile
	if err := decoder.Decode(&file); err != nil {
		return Config{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("unexpected trailing JSON value")
	}
	return normalizeAndValidate(Config{
		Version:             file.Version,
		CloudURL:            file.CloudURL,
		Mode:                file.Mode,
		Agent:               file.Agent,
		AllowHTTPLoopback:   file.AllowHTTPLoopback,
		Credentials:         file.Credentials,
		Device:              file.Device,
		LegacyCoworkEnabled: legacyCoworkEnabled(file.LegacyCoworkEnabled),
	})
}

func legacyCoworkEnabled(raw json.RawMessage) bool {
	var enabled bool
	return json.Unmarshal(raw, &enabled) == nil && enabled
}

func ParseTokenRef(value string) (TokenRef, error) {
	value = strings.TrimSpace(value)
	source, name, ok := strings.Cut(value, ":")
	if !ok {
		return TokenRef{}, errors.New("install token ref must use source:name")
	}
	ref := TokenRef{
		Source: strings.TrimSpace(source),
		Name:   strings.TrimSpace(name),
	}
	if err := validateTokenRef(ref); err != nil {
		return TokenRef{}, err
	}
	return ref, nil
}

func (r TokenRef) String() string {
	if r.Source == "" && r.Name == "" {
		return ""
	}
	return r.Source + ":" + r.Name
}

func (r *TokenRef) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	ref, err := ParseTokenRef(value)
	if err != nil {
		return err
	}
	*r = ref
	return nil
}

func (r TokenRef) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func ResolveInstallToken(ctx context.Context, ref TokenRef) (string, error) {
	if err := validateTokenRef(ref); err != nil {
		return "", err
	}
	switch ref.Source {
	case "env":
		token := strings.TrimSpace(os.Getenv(ref.Name))
		if token == "" {
			return "", fmt.Errorf("install token env %s is empty", ref.Name)
		}
		return token, nil
	case "keychain":
		return resolveKeychainInstallToken(ctx, ref.Name)
	default:
		return "", errors.New("install token ref source must be keychain or env")
	}
}

func normalizeAndValidate(cfg Config) (Config, error) {
	cfg.Version = strings.TrimSpace(cfg.Version)
	cfg.CloudURL = strings.TrimSpace(cfg.CloudURL)
	cfg.Mode = strings.TrimSpace(cfg.Mode)
	cfg.Agent = strings.TrimSpace(cfg.Agent)
	cfg.Credentials.InstallTokenRef.Source = strings.TrimSpace(cfg.Credentials.InstallTokenRef.Source)
	cfg.Credentials.InstallTokenRef.Name = strings.TrimSpace(cfg.Credentials.InstallTokenRef.Name)
	cfg.Device.Label = strings.TrimSpace(cfg.Device.Label)
	cfg.Device.UserEmail = strings.TrimSpace(cfg.Device.UserEmail)

	if cfg.Version != Version {
		return Config{}, fmt.Errorf("version must be %q", Version)
	}
	if err := validateCloudURL(cfg.CloudURL, cfg.AllowHTTPLoopback); err != nil {
		return Config{}, err
	}
	// An unrecognized mode is the signature of a DOWNGRADE: a newer build wrote
	// a posture this one has no name for (as happened when `remote` was added
	// and older binaries met it). Refusing to load is the worst available
	// response — launchd then crash-loops the daemon, so the endpoint reports
	// nothing at all and still enforces nothing, and no self-updater can
	// recover a binary that will not boot. Falling back to observe is strictly
	// better on both axes: it cannot enforce less than a process that never
	// starts, and it keeps the telemetry that makes the skew diagnosable.
	// Recorded rather than swallowed so startup and `kontext doctor` can say it
	// out loud; the write path stays strict via ValidateMode.
	// A MISSING mode is not a downgrade, it is a malformed config, and stays a
	// hard error exactly as before.
	if err := ValidateMode(cfg.Mode); err != nil {
		if cfg.Mode == "" {
			return Config{}, err
		}
		cfg.UnsupportedMode = cfg.Mode
		cfg.Mode = Mode
	}
	if cfg.Agent != Agent {
		return Config{}, fmt.Errorf("agent must be %q", Agent)
	}
	if err := validateTokenRef(cfg.Credentials.InstallTokenRef); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ValidateMode reports whether value is a posture this build implements. The
// READ path (Parse) deliberately does not fail on a bad mode — see
// normalizeAndValidate — so this is the gate for every WRITE path instead:
// nothing should ever persist a mode that the writer itself cannot evaluate.
func ValidateMode(value string) error {
	switch strings.TrimSpace(value) {
	case Mode, ModeEnforce, ModeRemote:
		return nil
	default:
		return fmt.Errorf("mode must be %q, %q, or %q", Mode, ModeEnforce, ModeRemote)
	}
}

// ValidateCloudURL enforces the managed.json cloud_url shape: https with host
// only, or loopback http when the config opts in (allowLoopback) or the
// EnvAllowHTTP escape hatch is set. Exported so `kontext setup` can fail a bad
// --cloud-url before any state is written, with exactly the rules the daemon's
// parser will apply later.
func ValidateCloudURL(value string, allowLoopback bool) error {
	return validateCloudURL(value, allowLoopback)
}

func validateCloudURL(value string, allowLoopback bool) error {
	if value == "" {
		return errors.New("cloud_url is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("cloud_url is invalid: %w", err)
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !loopbackHTTPPermitted(parsed.Hostname(), allowLoopback) {
			return errors.New("cloud_url must use https, or point at a loopback host with allow_http_loopback set (`--allow-http-loopback`)")
		}
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return errors.New("cloud_url must include host")
	}
	if parsed.Port() == "" && strings.Contains(parsed.Host, ":") {
		return errors.New("cloud_url must include a valid port")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return errors.New("cloud_url must include a valid port")
		}
	}
	if parsed.User != nil {
		return errors.New("cloud_url must not include userinfo")
	}
	if parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		return errors.New("cloud_url must not include path")
	}
	if parsed.RawQuery != "" {
		return errors.New("cloud_url must not include query")
	}
	if parsed.Fragment != "" {
		return errors.New("cloud_url must not include fragment")
	}
	return nil
}

// loopbackHTTPPermitted reports whether plaintext http is acceptable for host.
//
// Two things must both hold: the host is genuinely loopback, and the operator
// has opted in. The opt-in comes either from the config itself (allowLoopback,
// the durable form) or from EnvAllowHTTP (the original ambient form, kept
// working so existing local-dev setups are not broken).
//
// The config form exists because the env form cannot be seen by the processes
// that matter. A LaunchAgent does not inherit a shell's environment, so a
// config the terminal accepts would be rejected by the daemon that has to serve
// it — visibly fine, silently dead. State on disk is read identically by the
// CLI, the daemon, and anything else.
func loopbackHTTPPermitted(host string, allowLoopback bool) bool {
	if !allowLoopback && !envAllowsHTTPLoopback() {
		return false
	}
	return isLoopbackHost(host)
}

func envAllowsHTTPLoopback() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvAllowHTTP))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// isLoopbackHost is the hard boundary on this relaxation: the opt-in widens the
// SCHEME only, and only for a host that cannot leave the machine. It never makes
// plaintext acceptable to a remote endpoint.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateTokenRef(ref TokenRef) error {
	switch ref.Source {
	case "keychain", "env":
	default:
		return errors.New("install token ref source must be keychain or env")
	}
	if ref.Name == "" {
		return errors.New("install token ref name is required")
	}
	if strings.ContainsAny(ref.Name, " \t\r\n:") {
		return errors.New("install token ref name must not contain whitespace or colon")
	}
	if ref.Source == "env" && !envNamePattern.MatchString(ref.Name) {
		return errors.New("env install token ref name must be a valid environment variable name")
	}
	return nil
}

func resolveKeychainInstallToken(ctx context.Context, name string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("keychain install token refs are only supported on macOS")
	}
	out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", name, "-w").Output()
	if err != nil {
		return "", fmt.Errorf("read install token from keychain: %w", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("install token keychain item %s is empty", name)
	}
	return token, nil
}

// RewriteMode atomically rewrites the managed config file behind loaded with
// the given mode. Every other field's value is preserved verbatim, including
// legacy fields the parser only tolerates — but the document is re-serialized,
// so key order and whitespace are normalized. The write is refused when the
// file changed since it was loaded, and the result is round-tripped through
// Parse so a config the daemon would refuse to load is never written. The
// whole read-verify-replace sequence runs under the config write lock, so a
// cooperating writer (`kontext setup`) cannot slip a rewrite in between the
// checksum verification and the final rename.
func RewriteMode(loaded LoadedConfig, mode string) error {
	if loaded.Path == "" {
		return errors.New("managed config path is required")
	}
	return WithWriteLock(loaded.Path, func() error {
		return rewriteModeLocked(loaded, mode)
	})
}

func rewriteModeLocked(loaded LoadedConfig, mode string) error {
	// Explicit, because the Parse() round-trip below no longer rejects an
	// unknown mode — it would quietly normalize one to observe and write that
	// through as if the caller had asked for it.
	if err := ValidateMode(mode); err != nil {
		return err
	}
	data, err := os.ReadFile(loaded.Path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != loaded.Checksum {
		return errors.New("managed config changed since it was loaded")
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	encodedMode, err := json.Marshal(mode)
	if err != nil {
		return err
	}
	raw["mode"] = encodedMode
	rewritten, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	rewritten = append(rewritten, '\n')
	if _, err := Parse(rewritten); err != nil {
		return fmt.Errorf("rewritten managed config is invalid: %w", err)
	}

	dir := filepath.Dir(loaded.Path)
	temp, err := os.CreateTemp(dir, ".managed-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(rewritten); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, loaded.Path)
}
