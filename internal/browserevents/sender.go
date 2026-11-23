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
	// held are the rows the cloud refused as ahead of its clock, by key:
	// each goes again only after its own backoff, and meanwhile the rows
	// behind it are sent. Only SendOnce reads or writes it.
	held map[string]heldRow
}

// heldRow is a row version the cloud refused as in the future.
type heldRow struct {
	version  int
	refusals int
	until    time.Time
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
	return p.partition(func(_ int, record CloudRecord) bool {
		source := Extension{Version: record.ExtensionVersion, Browser: record.Browser, Profile: record.Profile}
		return source.validate() == nil && record.Record.Validate() == nil
	})
}

// partition splits p into the rows keep holds for and the others.
func (p Pending) partition(keep func(int, CloudRecord) bool) (kept, others Pending) {
	for i, record := range p.Records {
		target := &kept
		if !keep(i, record) {
			target = &others
		}
		target.Records = append(target.Records, record)
		target.keys = append(target.keys, p.keys[i])
		target.versions = append(target.versions, p.versions[i])
	}
	kept.binding, others.binding = p.binding, p.binding
	kept.generation, others.generation = p.generation, p.generation
	return kept, others
}

// hold notes rows the cloud refused as ahead of its clock: each waits its
// own backoff, longer with each refusal of the same version.
func (s *Sender) hold(p Pending, now time.Time) {
	if s.held == nil {
		s.held = map[string]heldRow{}
	}
	for i, key := range p.keys {
		h := s.held[key]
		if h.version != p.versions[i] {
			h = heldRow{version: p.versions[i]}
		}
		h.refusals++
		h.until = now.Add(backoff(h.refusals))
		s.held[key] = h
	}
}

// heldDue is when the first row still waiting may go again.
func (s *Sender) heldDue() (time.Time, bool) {
	var first time.Time
	now := s.clock()()
	for _, h := range s.held {
		if h.until.After(now) && (first.IsZero() || h.until.Before(first)) {
			first = h.until
		}
	}
	return first, !first.IsZero()
}

// aheadOfTheCloud reports whether the cloud refused a record for a time
// ahead of its own clock. The endpoint's clock was fast: the same record is
// taken once the cloud's clock has caught up, so it is not acknowledged.
func aheadOfTheCloud(reason string) bool {
	return strings.HasSuffix(reason, " in the future")
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
	// One deadline covers waiting for an earlier read and this one, so a
	// stuck read never holds up the background sender (and its flush).
	readCtx, cancel := context.WithTimeout(ctx, TokenReadTimeout)
	defer cancel()
	waited := s.Store.Epoch()
	select {
	case s.rebind <- struct{}{}:
	case <-readCtx.Done():
		// Another read is under way and has not confirmed the enrollment
		// in time: nothing more is taken until one does, for any profile.
		// A read that confirmed it while this one waited is not undone.
		s.Store.SuspendAt(waited)
		return "", fmt.Errorf("browser events: waiting for the install token: %w", readCtx.Err())
	}
	release := func() { <-s.rebind }
	if deadline, _ := readCtx.Deadline(); readCtx.Err() != nil || !beforeDeadline(deadline) {
		// The slot came free together with the deadline: this caller
		// gave up waiting, so a read confirmed meanwhile is not undone.
		release()
		s.Store.SuspendAt(waited)
		return "", fmt.Errorf("browser events: waiting for the install token: %w", context.DeadlineExceeded)
	}
	// Taken with the slot held: a Bind or Suspend after this, such as a
	// waiter that gave up, is newer than this read, so it is not undone.
	started := s.Store.Epoch()
	// A stuck credential read must not hold up its caller past the
	// deadline. It keeps the slot until it ends, so at most one read is
	// ever outstanding; later callers wait for it up to their own deadline.
	// The store is suspended before an abandoned read can give up the
	// slot, so a later successful bind is never undone by this timeout.
	// Its own suspensions are fenced too: nothing newer than this read is
	// undone by it.
	suspend := func() { s.Store.SuspendAt(started) }
	token, err, handedOff := readToken(readCtx, s.Tokens, release, suspend)
	if handedOff {
		return "", fmt.Errorf("browser events: install token: %v", err)
	}
	defer release()
	if err != nil || strings.TrimSpace(token) == "" {
		// The enrollment cannot be confirmed, such as when the
		// configuration names another cloud: no record is taken until it
		// can, so none is counted for the wrong workspace.
		suspend()
		return "", fmt.Errorf("browser events: install token: %v", err)
	}
	dropped, ok, err := s.Store.BindAt(Binding(s.BaseURL, s.InstallationID, token), started)
	if err != nil {
		return "", err
	}
	if !ok {
		// The store was suspended while this read ran: the token it read
		// may be older than that suspension, so the next read confirms.
		return "", errors.New("browser events: the enrollment changed while the install token was read")
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
	now := s.clock()
	pending := s.Store.PendingExcept(s.limit, func(key string, version int) bool {
		h, ok := s.held[key]
		return ok && h.version == version && now().Before(h.until)
	})
	// A hold kept a day past its wait is for a row that is gone or long
	// sent; a newer hold keeps counting refusals, so its backoff grows.
	for key, h := range s.held {
		if now().Sub(h.until) > 24*time.Hour {
			delete(s.held, key)
		}
	}
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
		ahead := map[int]bool{}
		for _, r := range answer.Rejected {
			if aheadOfTheCloud(r.Reason) {
				ahead[r.Index] = true
			}
		}
		// A record refused as ahead of the cloud's clock stays pending and
		// goes again: acknowledged, it would be lost, as the extension
		// sends the same observation again without changing the row.
		taken, held := pending.partition(func(i int, _ CloudRecord) bool { return !ahead[i] })
		s.hold(held, now())
		for _, key := range taken.keys {
			delete(s.held, key)
		}
		// Nothing to mark when every row was held: a write would only
		// rewrite the store.
		if len(taken.Records) > 0 {
			if err := s.Store.Ack(taken); err != nil {
				return Sent, err
			}
		}
		// After a 413 the batch grows back, doubling with each success.
		s.limit = min(s.limit*2, MaxRecordsPerBatch)
		for _, r := range answer.Rejected {
			s.logf("browser events: the cloud rejected record %d: %s", r.Index, r.Reason)
		}
		if len(held.Records) > 0 {
			s.logf("browser events: %d records are ahead of the cloud's clock, sending them again later", len(held.Records))
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
		// With nothing else to send, a held row still goes again at the end
		// of its backoff, not an hour later.
		if due, ok := s.heldDue(); ok && (outcome == Nothing || outcome == Sent) && due.Before(plan.due) {
			plan.due = due
			if soon := now().Add(time.Second); plan.due.Before(soon) {
				plan.due = soon
			}
		}
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
// when it ends, and handedOff is true; its answer is dropped. abandon runs
// first, while the read cannot yet release.
func readToken(ctx context.Context, read func(context.Context) (string, error), release, abandon func()) (token string, err error, handedOff bool) {
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
		// The clock is checked as well as the context, which learns of
		// its deadline only when its timer runs.
		if deadline, ok := ctx.Deadline(); ctx.Err() == nil && (!ok || beforeDeadline(deadline)) {
			return r.token, r.err, false
		}
		// Ready together with the deadline: the deadline wins.
		abandon()
		return "", context.DeadlineExceeded, false
	case <-ctx.Done():
	}
	mu.Lock()
	defer mu.Unlock()
	select {
	case <-done:
		// It answered, but after the deadline: not taken, so the deadline
		// holds. The read has ended, so the caller keeps the slot.
		abandon()
		return "", ctx.Err(), false
	default:
		abandon()
		abandoned = true
		return "", ctx.Err(), true
	}
}

// beforeDeadline checks both clocks: the monotonic one stops while a Mac
// sleeps, so a deadline slept through is passed only by the wall clock.
func beforeDeadline(deadline time.Time) bool {
	now := time.Now()
	return now.Before(deadline) && now.Round(0).Before(deadline.Round(0))
}
