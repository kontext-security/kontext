package cedarpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

const (
	DefaultRefreshInterval = time.Minute
	// DefaultMaxAge remains for source compatibility. Valid v2 bundles do not
	// expire by age; they stay active until a valid replacement is installed.
	DefaultMaxAge    = 15 * time.Minute
	cacheFileVersion = 2
)

type CacheStatus struct {
	State         State
	FetchedAt     time.Time
	LastAttemptAt time.Time
	Stale         bool
	Expired       bool
	LastError     string
	Invalid       bool
}

type Snapshot struct {
	Deployment          *Deployment
	LastKnownGood       *Deployment
	LegacyDeployment    *LegacyDeployment
	LegacyLastKnownGood *LegacyDeployment
	State               State
	Status              CacheStatus
}

// SnapshotProvider exposes validated in-memory policy state to the hook path.
// Current never performs filesystem or network I/O.
type SnapshotProvider interface {
	Current() Snapshot
}

type cacheFile struct {
	Version    int         `json:"version"`
	State      State       `json:"state"`
	FetchedAt  string      `json:"fetchedAt"`
	Deployment *Deployment `json:"deployment,omitempty"`
	LastGood   *Deployment `json:"lastGood,omitempty"`
}

type legacyCacheFile struct {
	Version    int               `json:"version"`
	State      State             `json:"state"`
	FetchedAt  string            `json:"fetchedAt"`
	Deployment *LegacyDeployment `json:"deployment,omitempty"`
	LastGood   *LegacyDeployment `json:"lastGood,omitempty"`
}

type Cache struct {
	path string
	now  func() time.Time

	mu             sync.RWMutex
	state          State
	fetched        time.Time
	active         *Deployment
	lastGood       *Deployment
	legacyActive   *LegacyDeployment
	legacyLastGood *LegacyDeployment
	status         CacheStatus
}

func NewCache(path string, _ time.Duration) *Cache {
	return &Cache{path: path, now: time.Now}
}

func DefaultCachePathForDB(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "cedar-policy.json")
}

func (c *Cache) Load() error {
	if c.path == "" {
		return nil
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cedar policy cache: read: %w", err)
	}
	var version struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &version); err != nil {
		return fmt.Errorf("cedar policy cache: %w", err)
	}
	if version.Version == 1 {
		return c.loadLegacy(data)
	}
	var file cacheFile
	if err := decodeStrict(strings.NewReader(string(data)), &file); err != nil {
		return fmt.Errorf("cedar policy cache: %w", err)
	}
	if file.Version != cacheFileVersion {
		return fmt.Errorf("cedar policy cache: unsupported version %d", file.Version)
	}
	if file.Deployment != nil {
		if err := file.Deployment.Validate(); err != nil {
			return fmt.Errorf("cedar policy cache: invalid deployment: %w", err)
		}
	}
	if file.LastGood != nil {
		if err := file.LastGood.Validate(); err != nil {
			return fmt.Errorf("cedar policy cache: invalid last-known-good deployment: %w", err)
		}
	}
	if file.State == StateSuccess && file.Deployment == nil && file.LastGood == nil {
		return errors.New("cedar policy cache: success state has no deployment")
	}
	fetchedAt, err := time.Parse(time.RFC3339Nano, file.FetchedAt)
	if err != nil {
		return fmt.Errorf("cedar policy cache: invalid fetchedAt: %w", err)
	}

	c.mu.Lock()
	c.state = file.State
	c.fetched = fetchedAt
	c.active = cloneDeployment(file.Deployment)
	c.lastGood = cloneDeployment(file.LastGood)
	c.legacyActive = nil
	c.legacyLastGood = nil
	if c.lastGood == nil && file.Deployment != nil {
		c.lastGood = cloneDeployment(file.Deployment)
	}
	c.status = CacheStatus{
		State:     file.State,
		FetchedAt: fetchedAt,
		Stale:     true,
		LastError: "persisted deployment not yet confirmed",
	}
	c.mu.Unlock()
	return nil
}

func (c *Cache) loadLegacy(data []byte) error {
	var file legacyCacheFile
	if err := decodeStrict(strings.NewReader(string(data)), &file); err != nil {
		return fmt.Errorf("cedar policy cache: %w", err)
	}
	if file.Deployment != nil {
		if err := file.Deployment.Validate(); err != nil {
			return fmt.Errorf("cedar policy cache: invalid legacy deployment: %w", err)
		}
	}
	if file.LastGood != nil {
		if err := file.LastGood.Validate(); err != nil {
			return fmt.Errorf("cedar policy cache: invalid legacy last-known-good deployment: %w", err)
		}
	}
	if file.State == StateSuccess && file.Deployment == nil && file.LastGood == nil {
		return errors.New("cedar policy cache: success state has no deployment")
	}
	fetchedAt, err := time.Parse(time.RFC3339Nano, file.FetchedAt)
	if err != nil {
		return fmt.Errorf("cedar policy cache: invalid fetchedAt: %w", err)
	}

	c.mu.Lock()
	c.state = file.State
	c.fetched = fetchedAt
	c.active = nil
	c.lastGood = nil
	c.legacyActive = cloneLegacyDeployment(file.Deployment)
	c.legacyLastGood = cloneLegacyDeployment(file.LastGood)
	if c.legacyLastGood == nil && file.Deployment != nil {
		c.legacyLastGood = cloneLegacyDeployment(file.Deployment)
	}
	c.status = CacheStatus{State: file.State, FetchedAt: fetchedAt, Stale: true, LastError: "persisted legacy deployment not yet replaced"}
	c.mu.Unlock()
	return nil
}

func (c *Cache) Apply(result FetchResult, fetchedAt time.Time) error {
	if fetchedAt.IsZero() {
		fetchedAt = c.now().UTC()
	}
	c.mu.RLock()
	file := cacheFile{
		Version:    cacheFileVersion,
		State:      c.state,
		FetchedAt:  fetchedAt.UTC().Format(time.RFC3339Nano),
		Deployment: cloneDeployment(c.active),
		LastGood:   cloneDeployment(c.lastGood),
	}
	c.mu.RUnlock()

	switch result.State {
	case StateSuccess:
		if result.Deployment == nil {
			return errors.New("cedar policy cache: success result has no deployment")
		}
		if err := result.Deployment.Validate(); err != nil {
			return err
		}
		file.State = StateSuccess
		file.Deployment = cloneDeployment(result.Deployment)
		file.LastGood = nil
	case StateNotModified:
		if file.LastGood == nil || result.ETag == "" || result.ETag != file.LastGood.DeploymentIdentity {
			return errors.New("cedar policy cache: not-modified result does not match last-known-good deployment")
		}
		file.State = StateSuccess
		file.Deployment = cloneDeployment(file.LastGood)
		file.LastGood = nil
	case StateDisabled, StateNoActivePolicy, StatePrincipalUnavailable, StateUnauthorized,
		StateUnsupportedVersion:
		if result.Response == nil || result.Response.State != result.State {
			return errors.New("cedar policy cache: state result is missing its response")
		}
		if err := result.Response.Validate(); err != nil {
			return err
		}
		file.State = result.State
		file.Deployment = nil
	case StateUnavailable:
		return errors.New("cedar policy cache: unavailable result must be recorded as a failed refresh")
	default:
		return fmt.Errorf("cedar policy cache: unsupported result state %q", result.State)
	}

	if err := c.persist(file); err != nil {
		return err
	}
	c.mu.Lock()
	c.state = file.State
	c.fetched = fetchedAt
	c.active = cloneDeployment(file.Deployment)
	c.lastGood = cloneDeployment(file.LastGood)
	c.legacyActive = nil
	c.legacyLastGood = nil
	if c.lastGood == nil && file.Deployment != nil {
		c.lastGood = cloneDeployment(file.Deployment)
	}
	c.status = CacheStatus{
		State:         file.State,
		FetchedAt:     fetchedAt,
		LastAttemptAt: fetchedAt,
	}
	c.mu.Unlock()
	return nil
}

func (c *Cache) MarkFailed(err error, attemptedAt time.Time) {
	if attemptedAt.IsZero() {
		attemptedAt = c.now().UTC()
	}
	c.mu.Lock()
	c.status.State = c.state
	c.status.FetchedAt = c.fetched
	c.status.LastAttemptAt = attemptedAt
	c.status.Stale = true
	if err != nil {
		c.status.LastError = err.Error()
	}
	c.mu.Unlock()
}

// MarkInvalid records that a cache file existed but could not be validated.
// Enforcement uses this signal to fail closed instead of treating corruption
// like a first installation with no cached policy.
func (c *Cache) MarkInvalid(err error) {
	c.mu.Lock()
	c.status.Invalid = true
	c.status.Stale = true
	c.status.Expired = true
	if err != nil {
		c.status.LastError = err.Error()
	}
	c.mu.Unlock()
}

func (c *Cache) Current() Snapshot {
	c.mu.RLock()
	state := c.state
	active := cloneDeployment(c.active)
	lastGood := cloneDeployment(c.lastGood)
	legacyActive := cloneLegacyDeployment(c.legacyActive)
	legacyLastGood := cloneLegacyDeployment(c.legacyLastGood)
	status := c.status
	c.mu.RUnlock()

	if active == nil && state == StateSuccess {
		active = lastGood
	}
	if legacyActive == nil && state == StateSuccess {
		legacyActive = legacyLastGood
	}
	return Snapshot{
		Deployment:          active,
		LastKnownGood:       lastGood,
		LegacyDeployment:    legacyActive,
		LegacyLastKnownGood: legacyLastGood,
		State:               state,
		Status:              status,
	}
}

func (c *Cache) ConditionalIdentity() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.lastGood == nil {
		if c.legacyLastGood == nil {
			return ""
		}
		return c.legacyLastGood.DeploymentIdentity
	}
	return c.lastGood.DeploymentIdentity
}

func cloneLegacyDeployment(deployment *LegacyDeployment) *LegacyDeployment {
	if deployment == nil {
		return nil
	}
	copy := *deployment
	return &copy
}

func (c *Cache) persist(file cacheFile) error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("cedar policy cache: create directory: %w", err)
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("cedar policy cache: encode: %w", err)
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(c.path), ".cedar-policy-*.tmp")
	if err != nil {
		return fmt.Errorf("cedar policy cache: create temporary file: %w", err)
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("cedar policy cache: set permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("cedar policy cache: write: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("cedar policy cache: sync: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("cedar policy cache: close: %w", err)
	}
	if err := os.Rename(tempPath, c.path); err != nil {
		return fmt.Errorf("cedar policy cache: replace: %w", err)
	}
	cleanup = false
	directory, err := os.Open(filepath.Dir(c.path))
	if err != nil {
		return fmt.Errorf("cedar policy cache: open directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("cedar policy cache: sync directory: %w", err)
	}
	return nil
}

func cloneDeployment(input *Deployment) *Deployment {
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
	// Diagnostic surfaces refresh state transitions in the daemon log. A
	// refresh loop that fails silently leaves enforcement running on a stale
	// policy with no operator-visible signal, so failures must not be
	// log-invisible.
	Diagnostic diagnostic.Logger

	lastFailure string
}

func (r *Refresher) Refresh(ctx context.Context) error {
	if r.Client == nil || r.Cache == nil || r.TokenSource == nil {
		err := errors.New("cedar policy refresher is not configured")
		if r.Cache != nil {
			r.recordFailure(err)
		}
		return err
	}
	token, err := r.TokenSource(ctx)
	if err != nil {
		r.recordFailure(err)
		return err
	}
	result, err := r.Client.Fetch(ctx, token, r.InstallationID, r.Cache.ConditionalIdentity())
	if err != nil {
		r.recordFailure(err)
		return err
	}
	if result.State == StateUnavailable {
		err = errors.New("cedar policy is temporarily unavailable")
		r.recordFailure(err)
		return err
	}
	if err := r.Cache.Apply(result, r.now()); err != nil {
		r.recordFailure(err)
		return err
	}
	r.recovered()
	return nil
}

func (r *Refresher) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	maxBackoff := r.MaxBackoff
	if maxBackoff < interval {
		maxBackoff = 10 * interval
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
		timer := time.NewTimer(delay)
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

func (r *Refresher) recordFailure(err error) {
	r.Cache.MarkFailed(err, r.now())
	// Log once per distinct error, not once per attempt: the loop retries
	// every minute and a repeated line per retry would drown the daemon log.
	if message := err.Error(); message != r.lastFailure {
		r.lastFailure = message
		diagnostic.LogAlways(r.Diagnostic, "cedar policy refresh failed (running on the last cached policy until it recovers): %v\n", err)
	}
}

func (r *Refresher) recovered() {
	if r.lastFailure == "" {
		return
	}
	r.lastFailure = ""
	diagnostic.LogAlways(r.Diagnostic, "cedar policy refresh recovered\n")
}

func (r *Refresher) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}
