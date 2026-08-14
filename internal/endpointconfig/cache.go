package endpointconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

const (
	DefaultRefreshInterval = time.Minute
	DefaultMaxBackoff      = 10 * time.Minute
)

var defaultConfig = Config{PayloadCaptureMode: payloadcapture.ModeSummary}

type Status struct {
	FetchedAt     time.Time
	LastAttemptAt time.Time
	Stale         bool
	LastError     string
	Invalid       bool
}

type Snapshot struct {
	Config     Config
	Configured Config
	// GuardrailLLMDirective is the most recent value the org ever set explicitly,
	// which is not the same as what the current response happens to carry. A kill
	// switch must not be undone by a response that merely says nothing about it —
	// a rollback to a server build that omits the field, for instance — so an
	// explicit directive is remembered until an explicit one replaces it. Nil
	// means the org has never set it, which resolves to enabled.
	GuardrailLLMDirective *bool
	// PromptPolicyDirective is remembered across transient refresh failures so
	// an enabled authorization barrier cannot silently fail open.
	PromptPolicyDirective *bool
	ConfigIdentity        string
	Confirmed             bool
	FallbackReason        string
	LastKnownGood         *Response
	Status                Status
}

// cacheFileVersion is written by this build. Version 1 files load fine and
// simply carry no remembered directive; a version this build does not know is
// rejected rather than guessed at.
const cacheFileVersion = 3

type cacheFile struct {
	Version   int       `json:"version"`
	FetchedAt string    `json:"fetchedAt"`
	Response  *Response `json:"response"`
	// GuardrailLLMDirective is stored beside the response rather than inside its
	// config, because the response's identity is verified against its config on
	// load — editing the config to carry a remembered value would invalidate it.
	GuardrailLLMDirective *bool `json:"guardrailLlmDirective,omitempty"`
	PromptPolicyDirective *bool `json:"promptPolicyDirective,omitempty"`
}

type Cache struct {
	path string
	now  func() time.Time

	mu                    sync.RWMutex
	fetched               time.Time
	active                *Response
	lastGood              *Response
	status                Status
	directive             *bool
	promptPolicyDirective *bool
}

func NewCache(path string) *Cache {
	return &Cache{path: path, now: time.Now}
}

func DefaultCachePathForDB(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "endpoint-config.json")
}

// Load restores only the conditional value. The effective configuration stays
// at the privacy-safe default until the server confirms it with 200 or 304.
func (c *Cache) Load() error {
	if c.path == "" {
		return nil
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("endpoint configuration cache: read: %w", err)
	}
	var file cacheFile
	if err := decodeStrict(strings.NewReader(string(data)), &file); err != nil {
		return fmt.Errorf("endpoint configuration cache: %w", err)
	}
	if file.Version < 1 || file.Version > cacheFileVersion || file.Response == nil {
		return errors.New("endpoint configuration cache: invalid cache shape")
	}
	if err := file.Response.Validate(); err != nil {
		// A cache written by a build that negotiated an older response version
		// cannot be revalidated under this contract: its identity was computed
		// over a different preimage. Discard it and start unconfirmed rather than
		// failing startup — the next refresh repopulates it, and the remembered
		// guardrail directive below is what actually needed to survive.
		if file.Response.ResponseVersion != ResponseVersion {
			c.mu.Lock()
			c.directive = cloneBool(file.GuardrailLLMDirective)
			c.promptPolicyDirective = cloneBool(file.PromptPolicyDirective)
			c.status = Status{Stale: true, LastError: "persisted configuration predates the current response version"}
			c.mu.Unlock()
			return nil
		}
		return fmt.Errorf("endpoint configuration cache: %w", err)
	}
	fetchedAt, err := time.Parse(time.RFC3339Nano, file.FetchedAt)
	if err != nil {
		return fmt.Errorf("endpoint configuration cache: invalid fetchedAt: %w", err)
	}
	c.mu.Lock()
	c.fetched = fetchedAt
	c.active = nil
	c.lastGood = cloneResponse(file.Response)
	c.directive = cloneBool(file.GuardrailLLMDirective)
	c.promptPolicyDirective = cloneBool(file.PromptPolicyDirective)
	c.status = Status{FetchedAt: fetchedAt, Stale: true, LastError: "persisted configuration not yet confirmed"}
	c.mu.Unlock()
	return nil
}

func (c *Cache) Apply(result FetchResult, fetchedAt time.Time) error {
	if fetchedAt.IsZero() {
		fetchedAt = c.now().UTC()
	}
	c.mu.RLock()
	lastGood := cloneResponse(c.lastGood)
	directive := cloneBool(c.directive)
	promptPolicyDirective := cloneBool(c.promptPolicyDirective)
	c.mu.RUnlock()
	var confirmed *Response
	switch {
	case result.NotModified:
		if lastGood == nil || result.ETag == "" || result.ETag != lastGood.ConfigIdentity {
			return errors.New("endpoint configuration cache: not-modified result does not match last-known-good config")
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
	// Adopt an explicit directive; keep the remembered one when the response is
	// silent. Silence is not a directive, so it must not clear a deliberate off.
	if confirmed.Config.GuardrailLLMEnabled != nil {
		directive = cloneBool(confirmed.Config.GuardrailLLMEnabled)
	}
	if confirmed.Config.PromptPolicyEnabled != nil {
		promptPolicyDirective = cloneBool(confirmed.Config.PromptPolicyEnabled)
	}
	file := cacheFile{
		Version:               cacheFileVersion,
		FetchedAt:             fetchedAt.UTC().Format(time.RFC3339Nano),
		Response:              cloneResponse(confirmed),
		GuardrailLLMDirective: cloneBool(directive),
		PromptPolicyDirective: cloneBool(promptPolicyDirective),
	}
	if err := c.persist(file); err != nil {
		return err
	}
	c.mu.Lock()
	c.fetched = fetchedAt
	c.active = cloneResponse(confirmed)
	c.lastGood = cloneResponse(confirmed)
	c.directive = cloneBool(directive)
	c.promptPolicyDirective = cloneBool(promptPolicyDirective)
	c.status = Status{FetchedAt: fetchedAt, LastAttemptAt: fetchedAt}
	c.mu.Unlock()
	return nil
}

// MarkFailed immediately returns the effective config to summary while
// retaining the validated value solely for conditional revalidation.
func (c *Cache) MarkFailed(err error, attemptedAt time.Time) {
	if attemptedAt.IsZero() {
		attemptedAt = c.now().UTC()
	}
	c.mu.Lock()
	c.markFailedLocked(err, attemptedAt)
	c.mu.Unlock()
}

func (c *Cache) markFailedLocked(err error, attemptedAt time.Time) {
	c.active = nil
	c.status.FetchedAt = c.fetched
	c.status.LastAttemptAt = attemptedAt
	c.status.Stale = true
	if err != nil {
		c.status.LastError = err.Error()
	}
}

func (c *Cache) MarkInvalid(err error) {
	attemptedAt := c.now().UTC()
	c.mu.Lock()
	c.markFailedLocked(err, attemptedAt)
	c.status.Invalid = true
	c.mu.Unlock()
}

func (c *Cache) Current() Snapshot {
	c.mu.RLock()
	active := cloneResponse(c.active)
	lastGood := cloneResponse(c.lastGood)
	directive := cloneBool(c.directive)
	promptPolicyDirective := cloneBool(c.promptPolicyDirective)
	status := c.status
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
			Config:                defaultConfig,
			Configured:            configured,
			GuardrailLLMDirective: directive,
			PromptPolicyDirective: promptPolicyDirective,
			ConfigIdentity:        identity,
			FallbackReason:        fallbackReason,
			LastKnownGood:         lastGood,
			Status:                status,
		}
	}
	return Snapshot{
		Config:                active.Config,
		Configured:            active.Config,
		GuardrailLLMDirective: directive,
		PromptPolicyDirective: promptPolicyDirective,
		ConfigIdentity:        active.ConfigIdentity,
		Confirmed:             true,
		LastKnownGood:         lastGood,
		Status:                status,
	}
}

// cloneBool copies an optional directive so callers cannot mutate cache state
// through the pointer they were handed.
func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
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
	if err := temporary.Chmod(0o600); err != nil {
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
	if err := os.Rename(temporaryPath, c.path); err != nil {
		return fmt.Errorf("endpoint configuration cache: replace: %w", err)
	}
	cleanup = false
	// A successful rename makes the new file visible, but the replacement is
	// not crash-durable until the containing directory is synced. If that sync
	// fails, Apply deliberately leaves the in-memory value unconfirmed and the
	// next refresh heals the cache (possibly after one extra 200 response).
	directory, err := os.Open(filepath.Dir(c.path))
	if err != nil {
		return fmt.Errorf("endpoint configuration cache: open directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("endpoint configuration cache: sync directory: %w", err)
	}
	return nil
}

func cloneResponse(input *Response) *Response {
	if input == nil {
		return nil
	}
	clone := *input
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
	if err := r.Cache.Apply(result, r.now()); err != nil {
		return r.fail(err)
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
		r.Cache.MarkFailed(err, r.now())
		r.notify()
	}
	// Log once per distinct error, not once per attempt: the loop retries
	// every minute and a repeated line per retry would drown the daemon log.
	if message := err.Error(); message != r.lastFailure {
		r.lastFailure = message
		diagnostic.LogAlways(r.Diagnostic, "endpoint config refresh failed (capture degrades to summary until it recovers): %v\n", err)
	}
	return err
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
