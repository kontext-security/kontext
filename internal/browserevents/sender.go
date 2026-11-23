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
	"sync"
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
	// 413; then it halves, down to one record, and doubles back with each
	// accepted batch.
	limit int
	// rebind makes reading the token and binding to it one step, so an
	// older read cannot bind the store back after a newer one. It is a
	// channel so a hello can stop waiting for it at its deadline.
	rebind     chan struct{}
	rebindInit sync.Once
}

// TokenReadTimeout bounds one read of the install token.
const TokenReadTimeout = 10 * time.Second

// MaxResponseBytes bounds the cloud's answer.
const MaxResponseBytes = 4 << 20

// noRedirects is client without following redirects: a 307 or 308 would send
// the batch, with the installation id, to wherever it points. A redirect
// then reads as its status, which SendOnce refuses.
func noRedirects(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	copied := *client
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copied
}

// split separates rows the contract allows from rows it does not.
func (p Pending) split() (valid, invalid Pending) {
	for i, record := range p.Records {
		source := Extension{Version: record.ExtensionVersion, Browser: record.Browser, Profile: record.Profile}
		target := &valid
		if source.validate() != nil || record.Record.Validate() != nil {
			target = &invalid
		}
		target.Records = append(target.Records, record)
		target.keys = append(target.keys, p.keys[i])
		target.versions = append(target.versions, p.versions[i])
	}
	valid.binding, invalid.binding = p.binding, p.binding
	valid.generation, invalid.generation = p.generation, p.generation
	return valid, invalid
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

// Rebind reads the current install token and binds the store to it, so an
// enrollment change is seen before the next record is taken, not only when
// there is something to send. Rows recorded under the previous enrollment are
// dropped and never leave with the new token.
func (s *Sender) Rebind(ctx context.Context) (token string, err error) {
	s.rebindInit.Do(func() { s.rebind = make(chan struct{}, 1) })
	select {
	case s.rebind <- struct{}{}:
	case <-ctx.Done():
		// Another read is under way; it decides the binding.
		return "", fmt.Errorf("browser events: waiting for the install token: %w", ctx.Err())
	}
	release := func() { <-s.rebind }
	// A stuck credential read must not hold up its caller past the
	// deadline. It keeps the slot until it ends, so at most one read is
	// ever outstanding; later callers wait for it up to their own deadline.
	readCtx, cancel := context.WithTimeout(ctx, TokenReadTimeout)
	defer cancel()
	token, err, handedOff := readToken(readCtx, s.Tokens, release)
	if !handedOff {
		defer release()
	}
	if err != nil || strings.TrimSpace(token) == "" {
		// The enrollment cannot be confirmed, such as when the
		// configuration names another cloud: no record is taken until it
		// can, so none is counted for the wrong workspace.
		s.Store.Suspend()
		return "", fmt.Errorf("browser events: install token: %v", err)
	}
	dropped, err := s.Store.Bind(Binding(s.BaseURL, s.InstallationID, token))
	if err != nil {
		return "", err
	}
	if dropped > 0 {
		s.logf("browser events: the enrollment changed; dropped %d rows recorded under the previous one", dropped)
	}
	return token, nil
}

// SendOnce sends up to one batch of pending rows.
func (s *Sender) SendOnce(ctx context.Context) (Outcome, error) {
	// Local retention does not wait for the token or the cloud: expired
	// days leave the disk whatever this send's outcome.
	defer func() { _ = s.Store.Flush() }()
	token, err := s.Rebind(ctx)
	if err != nil {
		return Retry, err
	}
	if s.limit <= 0 || s.limit > MaxRecordsPerBatch {
		s.limit = MaxRecordsPerBatch
	}
	pending := s.Store.Pending(s.limit)
	if pending.binding != Binding(s.BaseURL, s.InstallationID, token) {
		// A hello bound the store to another enrollment after the token was
		// read: these rows are not this token's. The next send reads again.
		return Retry, errors.New("browser events: the enrollment changed during a send")
	}
	if len(pending.Records) == 0 {
		if err := s.Store.Flush(); err != nil {
			return Retry, err
		}
		return Nothing, nil
	}
	now := s.clock()
	// A row the store kept that the contract no longer allows is dropped on
	// its own, rather than retried forever; the valid rows go on.
	pending, invalid := pending.split()
	if len(invalid.Records) > 0 {
		if err := s.Store.Drop(invalid); err != nil {
			return Retry, err
		}
		s.logf("browser events: dropped %d stored records the contract does not allow", len(invalid.Records))
	}
	if len(pending.Records) == 0 {
		return Sent, nil
	}
	batch := CloudBatch{Schema: CloudSchema, InstallationID: s.InstallationID, SentAt: now().UTC().Format(time.RFC3339), Records: pending.Records}
	if err := batch.Validate(); err != nil {
		// The batch itself is wrong, such as its installation id: no row
		// is to blame, so none is marked sent.
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
	response, err := noRedirects(s.HTTP).Do(request)
	if err != nil {
		return Retry, err
	}
	defer response.Body.Close()
	// Large enough for a full batch of rejections with the longest reasons
	// in any script. A cut-off answer would be retried forever.
	switch {
	case response.StatusCode == http.StatusOK || response.StatusCode == http.StatusCreated:
		// Only an acknowledgement needs its whole body; other answers are
		// judged by their status.
		data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
		if err != nil {
			return Retry, fmt.Errorf("browser events: read the answer: %w", err)
		}
		if len(data) > MaxResponseBytes {
			return Retry, errors.New("browser events: the answer is too large")
		}
		// Rows are marked sent only when the answer accounts for each of
		// them; {} from a proxy would otherwise mark them all.
		answer, err := DecodeCloudResponse(data, len(pending.Records))
		if err != nil {
			return Retry, err
		}
		if err := s.Store.Ack(pending); err != nil {
			return Sent, err
		}
		// After a 413 the batch grows back, doubling with each success.
		s.limit = min(s.limit*2, MaxRecordsPerBatch)
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

// readToken returns at ctx's deadline even when read does not honor it, as
// some credential stores do not. A read still running then calls release
// when it ends, and handedOff is true; its answer is dropped.
func readToken(ctx context.Context, read func(context.Context) (string, error), release func()) (token string, err error, handedOff bool) {
	type result struct {
		token string
		err   error
	}
	var mu sync.Mutex
	abandoned := false
	done := make(chan result, 1)
	go func() {
		token, err := read(ctx)
		mu.Lock()
		defer mu.Unlock()
		if abandoned {
			release()
			return
		}
		done <- result{token, err}
	}()
	select {
	case r := <-done:
		return r.token, r.err, false
	case <-ctx.Done():
	}
	mu.Lock()
	defer mu.Unlock()
	select {
	case r := <-done:
		return r.token, r.err, false
	default:
		abandoned = true
		return "", ctx.Err(), true
	}
}
