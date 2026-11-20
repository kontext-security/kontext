package browserevents

import (
	"bytes"
	"context"
	"encoding/json"
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
	now            func() time.Time
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
	// Refused: the cloud refused the batch as a whole (401, 403, 400, 413).
	Refused
)

// SendOnce sends up to one batch of pending rows.
func (s *Sender) SendOnce(ctx context.Context) (Outcome, error) {
	pending := s.Store.Pending(MaxRecordsPerBatch)
	if len(pending.Records) == 0 {
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
	token, err := s.Tokens(ctx)
	if err != nil || strings.TrimSpace(token) == "" {
		return Retry, fmt.Errorf("browser events: install token: %v", err)
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
		var answer CloudResponse
		if err := json.Unmarshal(data, &answer); err != nil {
			return Retry, fmt.Errorf("browser events: unreadable answer: %w", err)
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
