package endpointconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/fsperm"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

const (
	DefaultRefreshInterval = time.Minute
	DefaultMaxBackoff      = 10 * time.Minute
)

var defaultConfig = Config{PayloadCaptureMode: payloadcapture.ModeSummary}

var ErrCacheInvalidated = errors.New("endpoint configuration cache invalidated; refresh required")

type Status struct {
	FetchedAt     time.Time
	LastAttemptAt time.Time
	Stale         bool
	LastError     string
	Invalid       bool
	// NoCommonVersion: the server serves no response version this build
	// implements, so the defaults are in force, not a confirmed config
	// that may come back.
	NoCommonVersion bool
	// PromptVeto: the last confirmed config before a rejection let no prompt
	// leave the endpoint. Until a config is confirmed again, prompts are
	// recorded as omitted, so a later opt-in can't recover them.
	PromptVeto bool
	// NewestUnsupported: the server refused this build's response version and
	// the older one could not be confirmed, so the hook switches (v6 and v7)
	// read as off and unmanaged.
	NewestUnsupported bool
}

// HookInventoryEnabled is the hook inventory switch as far as this snapshot
// can confirm it: a confirmed v6 or v7 config that says on, from a server
// that hasn't since refused this build's version without confirming another.
func (s Snapshot) HookInventoryEnabled() bool {
	return s.Confirmed && !s.Status.NewestUnsupported && s.Config.HookInventoryEnabled()
}

// HookState is the desired state of Kontext's hooks as far as this snapshot
// can confirm it (ADR-0012): a confirmed v7 config's, and unmanaged for
// anything less, so nothing changes on a Mac the cloud hasn't asked about.
func (s Snapshot) HookState() HookState {
	if !s.Confirmed || s.Status.NewestUnsupported {
		return UnmanagedHookState
	}
	return s.Config.DesiredHookState()
}

type Snapshot struct {
	Config         Config
	Configured     Config
	ConfigIdentity string
	Confirmed      bool
	// Owner names the install token whose refresh confirmed Config (see
	// Owner()), empty until a refresh in this process confirms it. A caller
	// that must act only on its own enrolment's settings compares it, in the
	// same snapshot as Config.
	Owner          string
	FallbackReason string
	LastKnownGood  *Response
	Status         Status
}

// cacheFileVersion is written by this build. Version 1 files load fine and
// are still accepted; a version this build does not know is
// rejected rather than guessed at.
const cacheFileVersion = 2

type cacheFile struct {
	Version   int       `json:"version"`
	FetchedAt string    `json:"fetchedAt"`
	Response  *Response `json:"response"`
	// CloudURL is the cloud that confirmed Response. A directive belongs to
	// it: another cloud's workspace never runs under it.
	CloudURL string `json:"cloudUrl,omitempty"`
	// Owner names the enrolment (see Owner) whose token confirmed Response:
	// re-enrolling into another workspace on the same cloud doesn't inherit
	// it.
	Owner string `json:"owner,omitempty"`
	// NewestRefused: after Response was confirmed, the server refused this
	// build's version and the older one could not be confirmed. It keeps the
	// hook switches off across a restart until a config is confirmed again.
	// The key dates from when v6 was the newest version.
	NewestRefused bool `json:"v6Refused,omitempty"`
	// Retained only to decode existing cache files with the strict decoder.
	GuardrailLLMDirective *bool `json:"guardrailLlmDirective,omitempty"`
}

type Cache struct {
	cloudURL     string
	path         string
	rejectedPath string
	now          func() time.Time

	mu       sync.RWMutex
	fetched  time.Time
	active   *Response
	lastGood *Response
	status   Status
	owner    string
	// cloudURL and boundOwner are what Bind named.
	boundOwner string
}

func NewCache(path string) *Cache {
	return &Cache{path: path, rejectedPath: path + ".rejected", now: time.Now}
}

// Bind names the cloud and the enrolment this process runs under. Load then
// restores only a directive that this enrolment confirmed on that cloud, and
// Apply records both. Unbound, a cache takes any directive.
func (c *Cache) Bind(cloudURL, installToken string) {
	c.mu.Lock()
	c.cloudURL = normalCloudURL(cloudURL)
	c.boundOwner = Owner(installToken)
	c.mu.Unlock()
}

// Owner names an install token without holding it: two enrolments never
// share one.
func Owner(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("kontext/endpoint-config/owner/v1|" + token))
	return hex.EncodeToString(sum[:])
}

func normalCloudURL(cloudURL string) string {
	return strings.TrimRight(strings.TrimSpace(cloudURL), "/")
}

// Keep revocation in the installation's writable state directory, independently
// of a custom cache location whose directory may prevent deletion or replacement.
func NewCacheForDB(path, dbPath string) *Cache {
	c := NewCache(path)
	c.rejectedPath = dbPath + ".endpoint-config-rejected"
	return c
}

func DefaultCachePathForDB(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "endpoint-config.json")
}

// Load restores validated settings. Freshness is tracked separately so an
// offline restart does not change the last successfully applied directive.
func (c *Cache) Load() error {
	if c.path == "" {
		return nil
	}
	if marker, err := os.ReadFile(c.rejectedPath); err == nil {
		// The marker keeps why the cache was dropped, so an offline restart
		// finishes what the rejection started.
		c.mu.Lock()
		// A marker from a build before the veto never says whether the
		// dropped directive let prompts leave, so it holds the opt-out.
		veto := markerHas(marker, markerPromptVeto) || !markerHas(marker, markerVersioned)
		c.status = Status{Stale: true, Invalid: true, LastError: ErrCacheInvalidated.Error(), NoCommonVersion: markerHas(marker, markerNoCommonVersion), PromptVeto: veto}
		c.mu.Unlock()
		return ErrCacheInvalidated
	} else if !errors.Is(err, os.ErrNotExist) {
		c.holdVeto()
		// The marker may have taken the cache's place when the journal
		// couldn't be written: a route removal it owes still holds.
		if data, readErr := os.ReadFile(c.path); readErr == nil && bytes.HasPrefix(data, []byte(markerHeader)) && markerHas(data, markerNoCommonVersion) {
			c.mu.Lock()
			c.status.NoCommonVersion = true
			c.mu.Unlock()
		}
		return fmt.Errorf("endpoint configuration cache: revocation journal: %w", err)
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		c.holdVeto()
		return fmt.Errorf("endpoint configuration cache: read: %w", err)
	}
	if bytes.HasPrefix(data, []byte(markerHeader)) {
		// The journal couldn't be written, so the marker took the cache's
		// place.
		c.mu.Lock()
		c.status = Status{Stale: true, Invalid: true, LastError: ErrCacheInvalidated.Error(), NoCommonVersion: markerHas(data, markerNoCommonVersion), PromptVeto: markerHas(data, markerPromptVeto) || !markerHas(data, markerVersioned)}
		c.mu.Unlock()
		return ErrCacheInvalidated
	}
	// A response persisted by a build that negotiated another version has a
	// different config shape, which the strict decoder below rejects. Read
	// its version alone first so an upgrade discards it instead.
	var peek struct {
		Response *struct {
			ResponseVersion int `json:"responseVersion"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &peek); err == nil && peek.Response != nil && !readsVersion(peek.Response.ResponseVersion) {
		c.discardOlderVersion()
		return nil
	}
	var file cacheFile
	if err := decodeStrict(strings.NewReader(string(data)), &file); err != nil {
		// An unreadable cache, a truncated one included, may have held an
		// opt-out: it holds until a config is confirmed.
		c.holdVeto()
		return fmt.Errorf("endpoint configuration cache: %w", err)
	}
	if file.Version < 1 || file.Version > cacheFileVersion || file.Response == nil {
		c.holdVeto()
		return errors.New("endpoint configuration cache: invalid cache shape")
	}
	if err := file.Response.Validate(); err != nil {
		// A cache written by a build that negotiated an older response version
		// cannot be revalidated under this contract: its identity was computed
		// over a different preimage. Discard it and start unconfirmed rather than
		// failing startup. The next refresh repopulates it.
		if !readsVersion(file.Response.ResponseVersion) {
			c.discardOlderVersion()
			return nil
		}
		c.holdVeto()
		return fmt.Errorf("endpoint configuration cache: %w", err)
	}
	fetchedAt, err := time.Parse(time.RFC3339Nano, file.FetchedAt)
	if err != nil {
		c.holdVeto()
		return fmt.Errorf("endpoint configuration cache: invalid fetchedAt: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// A bound cache restores only what this enrolment confirmed on this
	// cloud. A file that doesn't name them, from an older build, can't show
	// it: the next refresh replaces it.
	if c.cloudURL != "" && normalCloudURL(file.CloudURL) != c.cloudURL || c.boundOwner != "" && file.Owner != c.boundOwner {
		// Whether it let prompts leave isn't this enrolment's answer, so the
		// opt-out holds.
		c.status = Status{Stale: true, LastError: "persisted configuration was confirmed by another enrolment or cloud", PromptVeto: true}
		return nil
	}
	c.fetched = fetchedAt
	c.active = cloneResponse(file.Response)
	c.lastGood = cloneResponse(file.Response)
	// Bound, the file names this enrolment, which confirmed it.
	c.owner = c.boundOwner
	c.status = Status{FetchedAt: fetchedAt, Stale: true, NewestUnsupported: file.NewestRefused}
	return nil
}

// replaceFile is os.Rename; a test makes the replace fail with it.
var replaceFile = os.Rename

// beforeReplace lets a test stop between the journal update and the cache
// replace, where a crash would leave both.
var beforeReplace = func() {}

func (c *Cache) discardOlderVersion() {
	c.mu.Lock()
	// Its opt-out, if it held one, can't be read under this contract, and
	// unconfirmed prompts would be recoverable after a later opt-in: the
	// opt-out holds until a config is confirmed.
	c.status = Status{Stale: true, LastError: "persisted configuration predates the current response version", PromptVeto: true}
	c.mu.Unlock()
}

func (c *Cache) Apply(result FetchResult, fetchedAt time.Time) error {
	return c.apply(result, fetchedAt, c.boundOwnerName())
}

// apply takes a result the owner's install token fetched, and records the
// owner with it.
func (c *Cache) apply(result FetchResult, fetchedAt time.Time, owner string) error {
	if fetchedAt.IsZero() {
		fetchedAt = c.now().UTC()
	}
	c.mu.RLock()
	lastGood := cloneResponse(c.lastGood)
	c.mu.RUnlock()
	var confirmed *Response
	switch {
	case result.NotModified:
		if lastGood == nil || result.ETag == "" || result.ETag != lastGood.ConfigIdentity {
			return errors.New("endpoint configuration cache: not-modified result does not match last-known-good config")
		}
		// A 304 to the fallback request can't confirm a newer version's
		// directive, whatever ETag it carries.
		if result.Version != 0 && result.Version < lastGood.ResponseVersion {
			return fmt.Errorf("%w: a not-modified answer for response version %d", ErrNewestUnsupported, result.Version)
		}
		if result.Version != 0 && result.Version != lastGood.ResponseVersion {
			return errors.New("endpoint configuration cache: not-modified result is for another response version")
		}
		confirmed = lastGood
	case result.Response != nil:
		if err := result.Response.Validate(); err != nil {
			return err
		}
		confirmed = cloneResponse(result.Response)
	default:
		return errors.New("endpoint configuration cache: result has no configuration")
	}
	file := cacheFile{
		Version:   cacheFileVersion,
		FetchedAt: fetchedAt.UTC().Format(time.RFC3339Nano),
		Response:  cloneResponse(confirmed),
		CloudURL:  c.boundCloudURL(),
		Owner:     owner,
	}
	// A verified directive is authoritative even if the local disk fails.
	// In particular, retaining an older Full directive after a valid opt-out
	// would contradict the workspace's known settings.
	c.mu.Lock()
	c.fetched = fetchedAt
	c.active = cloneResponse(confirmed)
	c.lastGood = cloneResponse(confirmed)
	c.owner = owner
	c.status = Status{FetchedAt: fetchedAt, LastAttemptAt: fetchedAt, Stale: true}
	c.mu.Unlock()
	// A journal left from an earlier rejection is read before the cache on
	// restart, so it first takes this config's opt-out: a crash or a failed
	// unlink below then can't restore an older answer over it.
	if c.path != "" {
		if _, err := os.Stat(c.rejectedPath); err == nil {
			marker := markerHeader + "\n" + markerVersioned + "\n"
			if !promptsAllowed(confirmed.Config) {
				marker += markerPromptVeto + "\n"
			}
			if err := os.WriteFile(c.rejectedPath, []byte(marker), 0600); err != nil {
				c.MarkFailed(err, fetchedAt)
				return fmt.Errorf("endpoint configuration cache: update revocation: %w", err)
			}
		}
	}
	beforeReplace()
	if err := c.persist(file); err != nil {
		// The journal that replaces the file must keep a confirmed opt-out.
		c.mu.Lock()
		c.status.PromptVeto = !promptsAllowed(confirmed.Config)
		c.mu.Unlock()
		err = errors.Join(err, c.invalidatePersisted())
		c.MarkFailed(err, fetchedAt)
		return err
	}
	if c.path != "" {
		if err := os.Remove(c.rejectedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.MarkFailed(err, fetchedAt)
			return fmt.Errorf("endpoint configuration cache: clear revocation: %w", err)
		}
	}
	c.mu.Lock()
	c.fetched = fetchedAt
	c.active = cloneResponse(confirmed)
	c.lastGood = cloneResponse(confirmed)
	c.owner = owner
	c.status = Status{FetchedAt: fetchedAt, LastAttemptAt: fetchedAt}
	c.mu.Unlock()
	return nil
}

// MarkFailed retains the last validated directive while recording its staleness.
func (c *Cache) MarkFailed(err error, attemptedAt time.Time) {
	if attemptedAt.IsZero() {
		attemptedAt = c.now().UTC()
	}
	c.mu.Lock()
	c.markFailedLocked(err, attemptedAt)
	c.mu.Unlock()
}

func (c *Cache) markFailedLocked(err error, attemptedAt time.Time) {
	c.status.FetchedAt = c.fetched
	c.status.LastAttemptAt = attemptedAt
	c.status.Stale = true
	if err != nil {
		c.status.LastError = err.Error()
	}
}

// markNewestUnsupported turns the hook switches off until a config is
// confirmed again.
func (c *Cache) markNewestUnsupported() {
	c.mu.Lock()
	// A config the fallback version confirmed is the server's word: a
	// later failure to refresh it is only a failure. The file may still
	// hold the newer version's config, if storage refused the fallback's
	// write; that file is marked below, so a restart can't restore it.
	fallbackConfirmed := c.lastGood != nil && c.lastGood.ResponseVersion < ResponseVersion
	if !fallbackConfirmed {
		c.status.NewestUnsupported = true
	}
	c.mu.Unlock()
	// The refusal is kept with the file, so a restart while configuration
	// is unavailable doesn't turn v6-only switches back on.
	if c.path == "" {
		return
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var file cacheFile
	if decodeStrict(strings.NewReader(string(data)), &file) != nil || file.Response == nil || file.NewestRefused {
		return
	}
	if fallbackConfirmed && file.Response.ResponseVersion < ResponseVersion {
		return
	}
	file.NewestRefused = true
	if c.persist(file) != nil {
		// Without the flag on disk, the file must not restore the switch.
		// The marker that replaces it keeps the confirmed opt-out.
		c.mu.Lock()
		c.status.PromptVeto = !promptsAllowed(file.Response.Config)
		c.mu.Unlock()
		_ = c.invalidatePersisted()
	}
}

func (c *Cache) MarkInvalid(err error) {
	attemptedAt := c.now().UTC()
	c.mu.Lock()
	c.active = nil
	c.owner = ""
	c.markFailedLocked(err, attemptedAt)
	c.status.Invalid = true
	c.mu.Unlock()
}

func (c *Cache) Current() Snapshot {
	c.mu.RLock()
	active := cloneResponse(c.active)
	lastGood := cloneResponse(c.lastGood)
	status := c.status
	owner := c.owner
	c.mu.RUnlock()
	if active == nil {
		configured := defaultConfig
		identity := ""
		fallbackReason := "no_confirmed_config"
		if lastGood != nil {
			configured = lastGood.Config
			identity = lastGood.ConfigIdentity
			fallbackReason = "awaiting_confirmation"
		}
		if !status.LastAttemptAt.IsZero() && status.Stale {
			fallbackReason = "refresh_failed"
		}
		if status.Invalid {
			fallbackReason = "invalid_cache"
		}
		return Snapshot{
			Config:         defaultConfig,
			Configured:     configured,
			ConfigIdentity: identity,
			FallbackReason: fallbackReason,
			LastKnownGood:  lastGood,
			Status:         status,
		}
	}
	return Snapshot{
		Config:         active.Config,
		Configured:     active.Config,
		ConfigIdentity: active.ConfigIdentity,
		Confirmed:      true,
		Owner:          owner,
		LastKnownGood:  lastGood,
		Status:         status,
	}
}

func (c *Cache) ConditionalIdentity() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.lastGood == nil {
		return ""
	}
	return c.lastGood.ConfigIdentity
}

func (c *Cache) persist(file cacheFile) error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("endpoint configuration cache: create directory: %w", err)
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("endpoint configuration cache: encode: %w", err)
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(c.path), ".endpoint-config-*.tmp")
	if err != nil {
		return fmt.Errorf("endpoint configuration cache: create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := fsperm.RestrictFile(temporary); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("endpoint configuration cache: set permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("endpoint configuration cache: write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("endpoint configuration cache: sync: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("endpoint configuration cache: close: %w", err)
	}
	if err := replaceFile(temporaryPath, c.path); err != nil {
		return fmt.Errorf("endpoint configuration cache: replace: %w", err)
	}
	cleanup = false
	// A successful rename makes the new file visible, but the replacement is
	// not crash-durable until the containing directory is synced. If that sync
	// fails, Apply deliberately leaves the in-memory value unconfirmed and the
	// next refresh heals the cache (possibly after one extra 200 response).
	if err := fsperm.SyncDir(filepath.Dir(c.path)); err != nil {
		return fmt.Errorf("endpoint configuration cache: sync directory: %w", err)
	}
	return nil
}

func cloneResponse(input *Response) *Response {
	if input == nil {
		return nil
	}
	clone := *input
	// The hook state carries a pointer of its own: a caller changing the
	// nonce of one snapshot must not change the cache's.
	if input.Config.HookState != nil {
		state := input.Config.HookState.clone()
		clone.Config.HookState = &state
	}
	return &clone
}

type TokenSource func(context.Context) (string, error)

type Refresher struct {
	Client         *Client
	Cache          *Cache
	TokenSource    TokenSource
	InstallationID string
	Interval       time.Duration
	MaxBackoff     time.Duration
	Now            func() time.Time
	Jitter         func(time.Duration) time.Duration
	OnChanged      func(Snapshot)
	// OnApplied receives the install token of each refresh the cache took,
	// a 304 included, so a caller can tell which enrolment the current
	// settings belong to.
	OnApplied func(token string)
	// Diagnostic surfaces refresh state transitions in the daemon log. A
	// refresh loop that fails silently leaves payload capture degraded with
	// no operator-visible signal, so failures must not be log-invisible.
	Diagnostic diagnostic.Logger

	lastFailure string
}

func (r *Refresher) Refresh(ctx context.Context) error {
	if r.Client == nil || r.Cache == nil || r.TokenSource == nil {
		return r.fail(errors.New("endpoint configuration refresher is not configured"))
	}
	token, err := r.TokenSource(ctx)
	if err != nil {
		return r.fail(err)
	}
	result, err := r.Client.Fetch(ctx, token, r.InstallationID, r.Cache.ConditionalIdentity())
	if err != nil {
		return r.fail(err)
	}
	err = r.Cache.apply(result, r.now(), Owner(token))
	if err != nil && result.NotModified && errors.Is(err, ErrNewestUnsupported) {
		// The 304 answered the newer version's identity on the fallback
		// request, and confirms nothing; asked again without it, the server
		// sends the fallback's config.
		result, err = r.Client.Fetch(ctx, token, r.InstallationID, "")
		if err == nil {
			err = r.Cache.apply(result, r.now(), Owner(token))
		}
	}
	if err != nil {
		return r.fail(err)
	}
	if r.OnApplied != nil {
		r.OnApplied(token)
	}
	r.recovered()
	r.notify()
	return nil
}

func (r *Refresher) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	maxBackoff := r.MaxBackoff
	if maxBackoff < interval {
		maxBackoff = DefaultMaxBackoff
		if maxBackoff < interval {
			maxBackoff = 10 * interval
		}
	}
	delay := interval
	for {
		if ctx.Err() != nil {
			return
		}
		if err := r.Refresh(ctx); err == nil {
			delay = interval
		} else if delay < maxBackoff {
			delay *= 2
			if delay > maxBackoff {
				delay = maxBackoff
			}
		}
		timer := time.NewTimer(r.jitter(delay))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (r *Refresher) fail(err error) error {
	if r.Cache != nil {
		if errors.Is(err, ErrAuthorityRejected) || errors.Is(err, ErrNoCommonVersion) {
			err = errors.Join(err, r.Cache.rejectAuthority(err, r.now()))
		} else {
			r.Cache.MarkFailed(err, r.now())
			if errors.Is(err, ErrNewestUnsupported) {
				r.Cache.markNewestUnsupported()
			}
		}
		r.notify()
	}
	// Log once per distinct error, not once per attempt: the loop retries
	// every minute and a repeated line per retry would drown the daemon log.
	if message := err.Error(); message != r.lastFailure {
		r.lastFailure = message
		diagnostic.LogAlways(r.Diagnostic, "endpoint config refresh failed (retaining last validated settings when available): %v\n", err)
	}
	return err
}

const (
	markerHeader          = "refresh required"
	markerNoCommonVersion = "no-common-version"
	markerPromptVeto      = "prompt-veto"
	// markerVersioned: the marker says whether a veto holds.
	markerVersioned = "v2"
)

func (c *Cache) boundOwnerName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.boundOwner
}

// holdVeto keeps the prompt opt-out after a cache that couldn't be read.
func (c *Cache) holdVeto() {
	c.mu.Lock()
	c.status.PromptVeto = true
	c.mu.Unlock()
}

func (c *Cache) boundCloudURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cloudURL
}

func markerHas(marker []byte, flag string) bool {
	return slices.Contains(strings.Fields(string(marker)), flag)
}

func (c *Cache) rejectAuthority(err error, at time.Time) error {
	c.mu.Lock()
	// A Codex route removal still owed survives a later rejection, a 401
	// included: no config has re-enabled the route.
	noCommon := errors.Is(err, ErrNoCommonVersion) || c.status.NoCommonVersion
	// A rejection (a rollback, an expired or revoked token) drops the
	// directive but not a prompt opt-out: the last confirmed config let no
	// prompt leave, and an unconfirmed record would be recovered by a later
	// opt-in. The veto lasts until a config is confirmed. Never an opt-in kept.
	veto := c.status.PromptVeto || c.active != nil && !promptsAllowed(c.active.Config) || c.active == nil && c.lastGood != nil && !promptsAllowed(c.lastGood.Config)
	c.active = nil
	c.owner = ""
	c.lastGood = nil
	c.status = Status{FetchedAt: c.fetched, LastAttemptAt: at, Stale: true, Invalid: true, LastError: err.Error(), NoCommonVersion: noCommon, PromptVeto: veto}
	c.mu.Unlock()
	return c.invalidatePersisted()
}

// promptsAllowed is payloadcapture.PromptsAllowed for a confirmed config.
func promptsAllowed(config Config) bool {
	return config.PayloadCaptureMode == payloadcapture.ModeFull && config.WorkTypeClassificationEnabled()
}

func (c *Cache) invalidatePersisted() error {
	if c.path == "" {
		return nil
	}
	c.mu.RLock()
	marker := markerHeader + "\n" + markerVersioned + "\n"
	if c.status.NoCommonVersion {
		marker += markerNoCommonVersion + "\n"
	}
	if c.status.PromptVeto {
		marker += markerPromptVeto + "\n"
	}
	c.mu.RUnlock()
	if err := os.MkdirAll(filepath.Dir(c.rejectedPath), 0700); err == nil {
		if err := os.WriteFile(c.rejectedPath, []byte(marker), 0600); err == nil {
			return nil
		}
	}
	// A directory can deny deletion while its existing file remains writable:
	// the marker then replaces the cache, so the veto and a route removal
	// still owed survive a restart. Truncation is the last resort; Load
	// holds the veto for an empty file too.
	if err := os.WriteFile(c.path, []byte(marker), 0600); err == nil {
		return nil
	}
	writeErr := os.WriteFile(c.path, nil, 0600)
	if writeErr == nil {
		return nil
	}
	removeErr := os.Remove(c.path)
	if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("endpoint configuration cache: cannot durably invalidate: %w", errors.Join(writeErr, removeErr))
}

func (r *Refresher) recovered() {
	if r.lastFailure == "" {
		return
	}
	r.lastFailure = ""
	diagnostic.LogAlways(r.Diagnostic, "endpoint config refresh recovered\n")
}

func (r *Refresher) notify() {
	if r.OnChanged != nil && r.Cache != nil {
		r.OnChanged(r.Cache.Current())
	}
}

func (r *Refresher) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Refresher) jitter(delay time.Duration) time.Duration {
	if r.Jitter != nil {
		return r.Jitter(delay)
	}
	// Spread retry traffic over [75%, 125%] without changing the configured
	// steady-state interval or the bounded exponential backoff.
	return delay*3/4 + time.Duration(rand.Int64N(int64(delay/2)+1))
}
