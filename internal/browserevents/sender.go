package browserevents

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IngestPath is the cloud endpoint for browser activity.
const IngestPath = "/api/v1/browser-activity/batches"

// Sender timing. A change is sent after SendDelay, so a burst of messages
// becomes one batch; failures back off up to MaxBackoff, and a cloud that has
// no browser endpoint yet (404) is asked again only after NotFoundBackoff.
const (
	SendDelay       = 30 * time.Second
	MaxBackoff      = 30 * time.Minute
	NotFoundBackoff = 6 * time.Hour
)

// Sender sends the store's pending rows to the cloud.
type Sender struct {
	Store          *Store
	BaseURL        string
	InstallationID string
	Tokens         func(context.Context) (string, error)
	HTTP           *http.Client
	Logf           func(format string, args ...any)
	// Warnf reports failures that stop uploads, in the daemon's normal log:
	// the first of a run of failures, then at most once per WarnEvery. A 404
	// stays quiet.
	Warnf    func(format string, args ...any)
	now      func() time.Time
	lastWarn time.Time
	// limit is the batch size, MaxRecordsPerBatch until the cloud answers
	// 413; then it halves, down to one record.
	limit int
}

// WarnEvery spaces out the warnings of a run of failed sends.
const WarnEvery = time.Hour

// Binding names an enrollment: the cloud, installation and install token. A
// new token, even at the same address, may belong to another workspace.
func Binding(baseURL, installationID, token string) string {
	sum := sha256.Sum256([]byte(strings.TrimRight(strings.TrimSpace(baseURL), "/") + "\n" + installationID + "\n" + strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:16])
}

// Outcome of one send.
type Outcome int

const (
	// Sent: the cloud answered; rejected records are dropped.
	Sent Outcome = iota
	// Nothing: no rows were pending.
	Nothing
	// Retry: a network error, 429 or 5xx; send the same rows later.
	Retry
	// NotFound: the cloud has no browser endpoint, such as one that predates
	// it; ask again much later and say nothing.
	NotFound
	// Refused: the cloud refused the batch as a whole (401, 403, 400). A 413
	// halves the batch instead.
	Refused
)

// SendOnce sends up to one batch of pending rows.
func (s *Sender) SendOnce(ctx context.Context) (Outcome, error) {
	// An unbound store takes no records, so it is bound even with nothing
	// to send.
	if s.Store.Bound() && len(s.Store.Pending(1).Records) == 0 {
		// Days that aged out leave the disk even when nothing is sent.
		if err := s.Store.Flush(); err != nil {
			return Retry, err
		}
		return Nothing, nil
	}
	token, err := s.Tokens(ctx)
	if err != nil || strings.TrimSpace(token) == "" {
		return Retry, fmt.Errorf("browser events: install token: %v", err)
	}
	// Rows recorded under another enrollment never leave with this token.
	dropped, err := s.Store.Bind(Binding(s.BaseURL, s.InstallationID, token))
	if err != nil {
		return Retry, err
	}
	if dropped > 0 {
		s.logf("browser events: the enrollment changed; dropped %d rows recorded under the previous one", dropped)
	}
	if s.limit <= 0 || s.limit > MaxRecordsPerBatch {
		s.limit = MaxRecordsPerBatch
	}
	pending := s.Store.Pending(s.limit)
	if len(pending.Records) == 0 {
		if err := s.Store.Flush(); err != nil {
			return Retry, err
		}
		return Nothing, nil
	}
	now := s.clock()
	batch := CloudBatch{Schema: CloudSchema, InstallationID: s.InstallationID, SentAt: now().UTC().Format(time.RFC3339), Records: pending.Records}
	if err := batch.Validate(); err != nil {
		// A row the store kept that the contract no longer allows: drop the
		// batch's rows rather than retry them forever.
		_ = s.Store.Ack(pending)
		return Refused, err
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return Retry, err
	}
	endpoint, err := url.JoinPath(strings.TrimRight(strings.TrimSpace(s.BaseURL), "/"), IngestPath)
	if err != nil {
		return Refused, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Refused, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	request.Header.Set("Content-Type", "application/json")
	response, err := s.HTTP.Do(request)
	if err != nil {
		return Retry, err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	switch {
	case response.StatusCode == http.StatusOK || response.StatusCode == http.StatusCreated:
		// Rows are marked sent only when the answer accounts for each of
		// them; {} from a proxy would otherwise mark them all.
		answer, err := DecodeCloudResponse(data, len(pending.Records))
		if err != nil {
			return Retry, err
		}
		if err := s.Store.Ack(pending); err != nil {
			return Sent, err
		}
		for _, r := range answer.Rejected {
			s.logf("browser events: the cloud rejected record %d: %s", r.Index, r.Reason)
		}
		return Sent, nil
	case response.StatusCode == http.StatusNotFound:
		return NotFound, nil
	case response.StatusCode == http.StatusRequestEntityTooLarge:
		if len(pending.Records) > 1 {
			// Smaller batches next time; the same oldest rows would
			// otherwise block every later one.
			s.limit = len(pending.Records) / 2
			return Retry, fmt.Errorf("browser events: batch of %d records too large, sending %d next", len(pending.Records), s.limit)
		}
		// One record the cloud will never take: drop it so the rest move.
		if err := s.Store.Ack(pending); err != nil {
			return Retry, err
		}
		return Sent, errors.New("browser events: dropped a record the cloud found too large")
	case response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
		return Retry, fmt.Errorf("browser events: status %d", response.StatusCode)
	default:
		return Refused, fmt.Errorf("browser events: status %d", response.StatusCode)
	}
}

// Run sends whenever changed fires, after SendDelay, and backs off on
// failure, until ctx ends.
func (s *Sender) Run(ctx context.Context, changed <-chan struct{}) {
	now := s.clock()
	plan := sendPlan{due: now().Add(SendDelay)}
	timer := time.NewTimer(SendDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
			if plan.changed(now()) {
				timer.Reset(max(plan.due.Sub(now()), 0))
			}
			continue
		case <-timer.C:
		}
		outcome, err := s.SendOnce(ctx)
		plan.after(outcome, now())
		switch {
		case outcome == Sent && err != nil:
			s.logf("%v", err)
		case outcome == Retry || outcome == Refused:
			s.logf("browser events: send failed (%d in a row): %v", plan.failures, err)
			s.warn(plan.failures, now(), err)
		}
		timer.Reset(max(plan.due.Sub(now()), 0))
	}
}

// sendPlan says when the next send is due. A change brings it forward to
// SendDelay from now at most, and never moves a send that is due sooner, so
// a steady stream of messages cannot postpone it. While the sender backs off
// after a failure or a 404, changes leave it alone.
type sendPlan struct {
	due      time.Time
	holding  bool
	failures int
}

func (p *sendPlan) changed(now time.Time) bool {
	soon := now.Add(SendDelay)
	if p.holding || !p.due.After(soon) {
		return false
	}
	p.due = soon
	return true
}

func (p *sendPlan) after(outcome Outcome, now time.Time) {
	switch outcome {
	case Sent:
		p.failures, p.holding = 0, false
		p.due = now.Add(time.Second)
	case Nothing:
		p.failures, p.holding = 0, false
		p.due = now.Add(time.Hour)
	case NotFound:
		p.failures, p.holding = 0, true
		p.due = now.Add(NotFoundBackoff)
	default:
		p.failures++
		p.holding = true
		p.due = now.Add(backoff(p.failures))
	}
}

func backoff(failures int) time.Duration {
	wait := SendDelay
	for i := 1; i < failures && wait < MaxBackoff; i++ {
		wait *= 2
	}
	return min(wait, MaxBackoff)
}

// warn reports the first failure of a run, then at most once per WarnEvery.
func (s *Sender) warn(failures int, now time.Time, err error) {
	if s.Warnf == nil || (failures > 1 && now.Sub(s.lastWarn) < WarnEvery) {
		return
	}
	s.lastWarn = now
	s.Warnf("browser activity upload failed (%d in a row): %v", failures, err)
}

func (s *Sender) clock() func() time.Time {
	if s.now != nil {
		return s.now
	}
	return time.Now
}

func (s *Sender) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}
