package managedstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

const (
	SchemaVersion   = "authorization-ledger-v1"
	DefaultEndpoint = "/api/v1/authorization-ledger/batches"

	DefaultBatchLimit        = 100
	MaxPayloadBytes          = 192 * 1024
	DefaultInterval          = 10 * time.Second
	DefaultTimeout           = 30 * time.Second
	DefaultHeartbeatInterval = 60 * time.Second

	// cursorSafetyLag holds the persisted export cursor this far behind the
	// newest exported row. Rows are stamped with a timestamp captured before
	// their write queues on the store's single serialized connection, so
	// under concurrent hook load a row can COMMIT after a flush has already
	// advanced the cursor past its stamp — a strict cursor would then skip it
	// forever. Re-reading the lag window re-sends recent rows instead; the
	// hosted upsert is idempotent per action id, so duplicates are harmless.
	cursorSafetyLag = 30 * time.Second

	maxPayloadSessions            = 100
	maxPayloadActions             = 1000
	maxPayloadReceipts            = 2000
	maxPayloadRiskTypeAnnotations = 1000

	maxErrorBodyBytes = 4096

	envStatePath = "KONTEXT_MANAGED_STREAM_STATE"
	envInterval  = "KONTEXT_MANAGED_STREAM_INTERVAL"
	envTimeout   = "KONTEXT_MANAGED_STREAM_TIMEOUT"
)

var hostedErrorSecretPattern = regexp.MustCompile(`(?i)("(?:[^"]*(?:api[_-]?key|authorization|client[_-]?secret|credential|install[_-]?token|password|secret|token)[^"]*)"\s*:\s*")([^"]*)(")`)

type Options struct {
	DBPath            string
	StatePath         string
	CloudURL          string
	InstallationID    string
	InstallToken      string
	DeviceLabel       string
	UserEmail         string
	DeploymentVersion func() string
	Interval          time.Duration
	HeartbeatInterval time.Duration
	BatchLimit        int
	HTTPClient        *http.Client
	Diagnostic        diagnostic.Logger
	// OnFlushSuccess fires (nil-safe) after every ACCEPTED hosted post, so
	// callers can clear "token rejected" breadcrumbs. It deliberately does
	// not depend on this process's failure counter (a breadcrumb can outlive
	// a daemon restart) and deliberately does NOT fire on empty flushes that
	// never contacted the server — an idle machine with a revoked token must
	// keep its breadcrumb.
	OnFlushSuccess func()
}

const (
	// authFailureThreshold avoids alerting on a transient 401 during a
	// server-side deploy; three consecutive rejections (~30s at the default
	// interval) means the credential itself is the problem.
	authFailureThreshold = 3
	// authFailureRefire re-surfaces the condition roughly every 8 minutes at
	// the default interval.
	authFailureRefire = 50
)

type Payload struct {
	SchemaVersion       string                            `json:"schema_version"`
	InstallationID      string                            `json:"installation_id"`
	BatchID             string                            `json:"batch_id"`
	SentAt              string                            `json:"sent_at"`
	Device              *Device                           `json:"device,omitempty"`
	Sessions            []sqlite.LedgerRecord             `json:"agent_sessions"`
	Actions             []sqlite.LedgerRecord             `json:"authorization_actions"`
	Receipts            []sqlite.LedgerRecord             `json:"authorization_receipts"`
	RiskTypeAnnotations []sqlite.RiskTypeAnnotationRecord `json:"risk_type_annotations,omitempty"`
	ReceiptChainAnchor  *sqlite.LedgerReceiptChainAnchor  `json:"receipt_chain_anchor,omitempty"`
}

type Device struct {
	Label             string `json:"label,omitempty"`
	DeploymentVersion string `json:"deployment_version,omitempty"`
	UserEmail         string `json:"user_email,omitempty"`
}

type State struct {
	UpdatedAfter           *time.Time
	ActionID               string
	RiskTypeCreatedAfter   *time.Time
	RiskTypeAnnotationID   string
	LastHeartbeatAttemptAt string
	LastHeartbeatAt        string
}

type persistedState struct {
	UpdatedAfter           string `json:"updated_after,omitempty"`
	ActionID               string `json:"action_id,omitempty"`
	RiskTypeCreatedAfter   string `json:"risk_type_created_after,omitempty"`
	RiskTypeAnnotationID   string `json:"risk_type_annotation_id,omitempty"`
	LastHeartbeatAttemptAt string `json:"last_heartbeat_attempt_at,omitempty"`
	LastHeartbeatAt        string `json:"last_heartbeat_at,omitempty"`
}

func isAuthStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func AuthFailureStatus(err error) (int, bool) {
	var hostedErr *hostedIngestError
	if !errors.As(err, &hostedErr) || !isAuthStatus(hostedErr.StatusCode) {
		return 0, false
	}
	return hostedErr.StatusCode, true
}

// ShouldReportFailure reports whether a consecutive-failure counter of any kind
// is worth surfacing: the 3rd in a row (skips transient blips), then every 50th
// (~8 minutes at the default interval).
func ShouldReportFailure(consecutiveFailures int) bool {
	if consecutiveFailures <= 0 {
		return false
	}
	return consecutiveFailures == authFailureThreshold ||
		consecutiveFailures%authFailureRefire == 0
}

// ShouldReportAuthFailure shares the generic failure-reporting cadence.
func ShouldReportAuthFailure(consecutiveFailures int) bool {
	return ShouldReportFailure(consecutiveFailures)
}

func Flush(ctx context.Context, opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	store, err := sqlite.OpenStore(opts.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	statePath := opts.StatePath
	if statePath == "" {
		statePath = DefaultStatePathForDB(opts.DBPath)
	}
	state, err := LoadState(statePath)
	if err != nil {
		return err
	}

	limit := batchLimit(opts.BatchLimit)
	maxLimit := limit
	// Pagination within this call uses the true batch cursor so the drain
	// makes forward progress; only the PERSISTED cursor is held back by
	// cursorSafetyLag (see clampCursor).
	pageUpdatedAfter := state.UpdatedAfter
	pageActionID := state.ActionID
	pageRiskTypeCreatedAfter := state.RiskTypeCreatedAfter
	pageRiskTypeAnnotationID := state.RiskTypeAnnotationID
	for {
		// Stamped per page: a full drain can run for minutes, and sent_at /
		// heartbeat marks should reflect when each batch actually shipped.
		now := time.Now().UTC()
		batch, err := store.LedgerBatch(ctx, sqlite.LedgerExportOptions{
			UpdatedAfter:   pageUpdatedAfter,
			UpdatedAfterID: pageActionID,
			Limit:          limit,
			ReceiptLimit:   maxPayloadReceipts,
		})
		if err != nil {
			if errors.Is(err, sqlite.ErrLedgerReceiptRangeTooLarge) {
				if limit == 1 {
					return advancePastMinimumBatch(statePath, batch, state, "receipt range too large", err)
				}
				nextLimit := reducedBatchLimit(limit)
				opts.Diagnostic.Printf(
					"managed stream receipt range exceeds hosted limit; reducing batch limit from %d to %d\n",
					limit,
					nextLimit,
				)
				limit = nextLimit
				continue
			}
			return err
		}
		riskTypeAnnotations, riskTypeCursor, err := store.RiskTypeAnnotations(ctx, sqlite.RiskTypeAnnotationExportOptions{
			CreatedAfter:   pageRiskTypeCreatedAfter,
			CreatedAfterID: pageRiskTypeAnnotationID,
			Limit:          limit,
		})
		if err != nil {
			return err
		}
		if len(batch.Actions) == 0 && len(riskTypeAnnotations) == 0 {
			return postHeartbeatIfDue(ctx, opts, statePath, state, now)
		}

		payload := newPayload(opts, batch.Sessions, batch.Actions, batch.Receipts, riskTypeAnnotations, batch.ReceiptChainAnchor, now)

		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if reason := payloadLimitViolation(payload, len(body)); reason != "" {
			if limit == 1 {
				return advancePastMinimumBatch(statePath, batch, state, reason, nil)
			}
			nextLimit := reducedBatchLimit(limit)
			opts.Diagnostic.Printf(
				"managed stream payload exceeds hosted limits (%s); reducing batch limit from %d to %d\n",
				reason,
				limit,
				nextLimit,
			)
			limit = nextLimit
			continue
		}

		if err := post(ctx, opts, body); err != nil {
			var hostedErr *hostedIngestError
			if errors.As(err, &hostedErr) && shouldRetryWithSmallerBatch(hostedErr.StatusCode) {
				if limit == 1 {
					return err
				}
				nextLimit := reducedBatchLimit(limit)
				opts.Diagnostic.Printf(
					"managed stream hosted ingest returned status %d; reducing batch limit from %d to %d\n",
					hostedErr.StatusCode,
					limit,
					nextLimit,
				)
				limit = nextLimit
				continue
			}
			return err
		}

		// The hosted ledger accepted a post with this token — proof the
		// credential works, which is what breadcrumb-clearing needs.
		if opts.OnFlushSuccess != nil {
			opts.OnFlushSuccess()
		}

		// Reductions are multiplicative and per-region; recovery is additive
		// (AIMD, like TCP), so a drain neither stays pinned at tiny batches nor
		// oscillates against the same wide receipt range it just backed off from.
		if limit < maxLimit {
			limit++
		}

		state.LastHeartbeatAttemptAt = now.Format(time.RFC3339Nano)
		state.LastHeartbeatAt = now.Format(time.RFC3339Nano)
		if batch.Cursor != nil {
			cursorAt := batch.Cursor.UpdatedAt.UTC()
			safeAt, safeID := clampCursor(cursorAt, batch.Cursor.ActionID, now)
			// Never regress the persisted cursor: advancePastMinimumBatch may have
			// deliberately advanced it past a poison row, and clamping back behind
			// that row would re-fetch it (and re-fail) until it ages out of the
			// lag window.
			if cursorAdvances(state, safeAt, safeID) {
				state.UpdatedAfter = &safeAt
				state.ActionID = safeID
			}
			pageUpdatedAfter = &cursorAt
			pageActionID = batch.Cursor.ActionID
		}
		if riskTypeCursor != nil {
			cursorAt := riskTypeCursor.CreatedAt.UTC()
			safeAt, safeID := clampCursor(cursorAt, riskTypeCursor.AnnotationID, now)
			if riskTypeCursorAdvances(state, safeAt, safeID) {
				state.RiskTypeCreatedAfter = &safeAt
				state.RiskTypeAnnotationID = safeID
			}
			pageRiskTypeCreatedAfter = &cursorAt
			pageRiskTypeAnnotationID = riskTypeCursor.AnnotationID
		}
		if err := SaveState(statePath, state); err != nil {
			return err
		}
		// Keep draining: one call empties the queue instead of shipping a
		// single batch per tick. A 40-subagent burst generates events ~20x
		// faster than one capped batch per 10s interval can ship them, which
		// left the hosted dashboard reading a partial session for ~45 minutes
		// (ENG-474). The cursor is persisted per batch, so an interrupted
		// drain resumes where it stopped.
	}
}

func postHeartbeatIfDue(ctx context.Context, opts Options, statePath string, state State, now time.Time) error {
	if !heartbeatDue(state.LastHeartbeatAttemptAt, heartbeatInterval(opts.HeartbeatInterval), now) {
		return nil
	}

	state.LastHeartbeatAttemptAt = now.Format(time.RFC3339Nano)
	if err := SaveState(statePath, state); err != nil {
		return err
	}

	payload := newPayload(opts, nil, nil, nil, nil, nil, now)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := post(ctx, opts, body); err != nil {
		return err
	}

	if opts.OnFlushSuccess != nil {
		opts.OnFlushSuccess()
	}
	state.LastHeartbeatAt = now.Format(time.RFC3339Nano)
	return SaveState(statePath, state)
}

func newPayload(
	opts Options,
	sessions []sqlite.LedgerRecord,
	actions []sqlite.LedgerRecord,
	receipts []sqlite.LedgerRecord,
	riskTypeAnnotations []sqlite.RiskTypeAnnotationRecord,
	receiptChainAnchor *sqlite.LedgerReceiptChainAnchor,
	now time.Time,
) Payload {
	payload := Payload{
		SchemaVersion:       SchemaVersion,
		InstallationID:      opts.InstallationID,
		BatchID:             "batch_" + uuid.NewString(),
		SentAt:              now.Format(time.RFC3339Nano),
		Sessions:            nonNilRecords(sessions),
		Actions:             nonNilRecords(actions),
		Receipts:            nonNilRecords(receipts),
		RiskTypeAnnotations: riskTypeAnnotations,
		ReceiptChainAnchor:  receiptChainAnchor,
	}
	// Resolve the deployment version per flush so an in-place package upgrade
	// is reflected without restarting the daemon.
	label := strings.TrimSpace(opts.DeviceLabel)
	userEmail := strings.TrimSpace(opts.UserEmail)
	deploymentVersion := ""
	if opts.DeploymentVersion != nil {
		deploymentVersion = strings.TrimSpace(opts.DeploymentVersion())
	}
	if label != "" || deploymentVersion != "" || userEmail != "" {
		payload.Device = &Device{Label: label, DeploymentVersion: deploymentVersion, UserEmail: userEmail}
	}
	return payload
}

func nonNilRecords(records []sqlite.LedgerRecord) []sqlite.LedgerRecord {
	if records != nil {
		return records
	}
	return []sqlite.LedgerRecord{}
}

func post(ctx context.Context, opts Options, body []byte) error {
	endpoint, err := endpointURL(opts.CloudURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(opts.InstallToken))

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeoutFromEnv()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &hostedIngestError{
			StatusCode: resp.StatusCode,
			Body:       responseBodySummary(resp.Body),
		}
	}
	return nil
}

type hostedIngestError struct {
	StatusCode int
	Body       string
}

func (e *hostedIngestError) Error() string {
	body := redactHostedErrorBody(e.Body)
	if body == "" {
		return fmt.Sprintf("hosted ledger ingest failed: status %d", e.StatusCode)
	}
	return fmt.Sprintf("hosted ledger ingest failed: status %d: %s", e.StatusCode, body)
}

func redactHostedErrorBody(body string) string {
	redacted := hostedErrorSecretPattern.ReplaceAllString(strings.TrimSpace(body), `${1}[REDACTED]${3}`)
	return diagnostic.Redact(redacted)
}

func batchLimit(limit int) int {
	if limit <= 0 {
		return DefaultBatchLimit
	}
	if limit > DefaultBatchLimit {
		return DefaultBatchLimit
	}
	return limit
}

func reducedBatchLimit(limit int) int {
	next := limit / 2
	if next < 1 {
		return 1
	}
	return next
}

func shouldRetryWithSmallerBatch(statusCode int) bool {
	return statusCode == http.StatusRequestEntityTooLarge
}

func payloadLimitViolation(payload Payload, bodyBytes int) string {
	switch {
	case len(payload.Sessions) > maxPayloadSessions:
		return fmt.Sprintf("agent_sessions=%d exceeds max %d", len(payload.Sessions), maxPayloadSessions)
	case len(payload.Actions) > maxPayloadActions:
		return fmt.Sprintf("authorization_actions=%d exceeds max %d", len(payload.Actions), maxPayloadActions)
	case len(payload.Receipts) > maxPayloadReceipts:
		return fmt.Sprintf("authorization_receipts=%d exceeds max %d", len(payload.Receipts), maxPayloadReceipts)
	case len(payload.RiskTypeAnnotations) > maxPayloadRiskTypeAnnotations:
		return fmt.Sprintf("risk_type_annotations=%d exceeds max %d", len(payload.RiskTypeAnnotations), maxPayloadRiskTypeAnnotations)
	case bodyBytes > MaxPayloadBytes:
		return fmt.Sprintf("body_bytes=%d exceeds max %d", bodyBytes, MaxPayloadBytes)
	default:
		return ""
	}
}

func advancePastMinimumBatch(statePath string, batch sqlite.LedgerBatch, state State, reason string, cause error) error {
	if batch.Cursor == nil {
		if cause != nil {
			return cause
		}
		return fmt.Errorf("managed stream minimum batch rejected: %s", reason)
	}
	if err := saveCursor(statePath, batch, state); err != nil {
		return err
	}
	if cause != nil {
		return fmt.Errorf("managed stream advanced cursor past rejected minimum batch (%s): %w", reason, cause)
	}
	return fmt.Errorf("managed stream advanced cursor past oversized minimum batch: %s", reason)
}

// saveCursor persists the TRUE cursor, without the safety lag. It is only
// used to advance past a poison minimum batch — clamping there could pin the
// cursor before the rejected row and re-fetch it forever.
func saveCursor(statePath string, batch sqlite.LedgerBatch, state State) error {
	updatedAfter := batch.Cursor.UpdatedAt.UTC()
	state.UpdatedAfter = &updatedAfter
	state.ActionID = batch.Cursor.ActionID
	return SaveState(statePath, state)
}

// clampCursor holds the persisted cursor back to now-cursorSafetyLag so rows
// whose writes commit after the flush read (but with an earlier timestamp
// stamp) are re-scanned on the next flush instead of being skipped forever.
// A clamped cursor does not correspond to a stored row, so the id tiebreak
// is cleared.
func clampCursor(cursorAt time.Time, actionID string, now time.Time) (time.Time, string) {
	maxSafe := now.Add(-cursorSafetyLag)
	if cursorAt.After(maxSafe) {
		return maxSafe, ""
	}
	return cursorAt, actionID
}

// cursorAdvances reports whether (at, id) sorts strictly after the cursor
// already persisted in state, matching the (updated_at_cursor_key, id)
// export ordering.
func cursorAdvances(state State, at time.Time, id string) bool {
	if state.UpdatedAfter == nil {
		return true
	}
	if at.After(*state.UpdatedAfter) {
		return true
	}
	return at.Equal(*state.UpdatedAfter) && id > state.ActionID
}

func riskTypeCursorAdvances(state State, at time.Time, id string) bool {
	if state.RiskTypeCreatedAfter == nil {
		return true
	}
	if at.After(*state.RiskTypeCreatedAfter) {
		return true
	}
	return at.Equal(*state.RiskTypeCreatedAfter) && id > state.RiskTypeAnnotationID
}

func parseStateUpdatedAfter(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", value)
}

func responseBodySummary(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, maxErrorBodyBytes+1))
	if err != nil {
		return ""
	}
	truncated := len(data) > maxErrorBodyBytes
	if truncated {
		data = data[:maxErrorBodyBytes]
	}
	summary := strings.Join(strings.Fields(string(data)), " ")
	if truncated {
		summary += "..."
	}
	return summary
}

func endpointURL(cloudURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cloudURL))
	if err != nil {
		return "", err
	}
	parsed.Path = DefaultEndpoint
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func DefaultStatePath() string {
	if path := strings.TrimSpace(os.Getenv(envStatePath)); path != "" {
		return path
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "Kontext", "managed-observe", "stream-state.json")
	}
	return filepath.Join("managed-observe", "stream-state.json")
}

func DefaultStatePathForDB(dbPath string) string {
	if path := strings.TrimSpace(os.Getenv(envStatePath)); path != "" {
		return path
	}
	if dbPath = strings.TrimSpace(dbPath); dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "stream-state.json")
	}
	return DefaultStatePath()
}

func DefaultIntervalFromEnv() time.Duration {
	if value := strings.TrimSpace(os.Getenv(envInterval)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultInterval
}

func DefaultTimeoutFromEnv() time.Duration {
	if value := strings.TrimSpace(os.Getenv(envTimeout)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultTimeout
}

func heartbeatInterval(value time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return DefaultHeartbeatInterval
}

func heartbeatDue(lastAttemptAt string, interval time.Duration, now time.Time) bool {
	if strings.TrimSpace(lastAttemptAt) == "" {
		return true
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(lastAttemptAt))
	if err != nil {
		return true
	}
	return !parsed.Add(interval).After(now)
}

func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	var state State
	var persisted persistedState
	if err := json.Unmarshal(data, &persisted); err != nil {
		return State{}, err
	}
	if updatedAfter := strings.TrimSpace(persisted.UpdatedAfter); updatedAfter != "" {
		parsed, err := parseStateUpdatedAfter(updatedAfter)
		if err != nil {
			return State{}, fmt.Errorf("parse managed stream state: %w", err)
		}
		state.UpdatedAfter = &parsed
	}
	state.ActionID = strings.TrimSpace(persisted.ActionID)
	if createdAfter := strings.TrimSpace(persisted.RiskTypeCreatedAfter); createdAfter != "" {
		parsed, err := parseStateUpdatedAfter(createdAfter)
		if err != nil {
			return State{}, fmt.Errorf("parse managed stream risk-type state: %w", err)
		}
		state.RiskTypeCreatedAfter = &parsed
	}
	state.RiskTypeAnnotationID = strings.TrimSpace(persisted.RiskTypeAnnotationID)
	state.LastHeartbeatAttemptAt = strings.TrimSpace(persisted.LastHeartbeatAttemptAt)
	state.LastHeartbeatAt = strings.TrimSpace(persisted.LastHeartbeatAt)
	return state, nil
}

func SaveState(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	persisted := persistedState{
		ActionID:               strings.TrimSpace(state.ActionID),
		RiskTypeAnnotationID:   strings.TrimSpace(state.RiskTypeAnnotationID),
		LastHeartbeatAttemptAt: strings.TrimSpace(state.LastHeartbeatAttemptAt),
		LastHeartbeatAt:        strings.TrimSpace(state.LastHeartbeatAt),
	}
	if state.UpdatedAfter != nil {
		persisted.UpdatedAfter = state.UpdatedAfter.UTC().Format(time.RFC3339Nano)
	}
	if state.RiskTypeCreatedAfter != nil {
		persisted.RiskTypeCreatedAfter = state.RiskTypeCreatedAfter.UTC().Format(time.RFC3339Nano)
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(path), ".stream-state-*.tmp")
	if err != nil {
		return err
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
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func validateOptions(opts Options) error {
	if strings.TrimSpace(opts.DBPath) == "" {
		return errors.New("managed stream requires db path")
	}
	if strings.TrimSpace(opts.CloudURL) == "" {
		return errors.New("managed stream requires cloud url")
	}
	if strings.TrimSpace(opts.InstallationID) == "" {
		return errors.New("managed stream requires installation id")
	}
	if strings.TrimSpace(opts.InstallToken) == "" {
		return errors.New("managed stream requires install token")
	}
	return nil
}
