package managedobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/cloudhttp"
	"github.com/kontext-security/kontext/internal/codexroute"
	"github.com/kontext-security/kontext/internal/diagnostic"
)

// The states of the Codex route the daemon reports: Codex goes through the
// proxy; the daemon did not route it; or something else took the route away.
const (
	codexRouted    = "routed"
	codexNotRouted = "not_routed"
	codexTakenAway = "taken_away"
)

// routeState is where the Codex route stands, and why when it is not routed
// (see codexroute.ReasonMacOSOnly and the others).
type routeState struct{ state, reason string }

// codexReport is the body of POST
// /api/v1/installations/{id}/codex-proxy/reports.
type codexReport struct {
	State string `json:"state"`
	// Reason is null exactly while Codex is routed.
	Reason   *string             `json:"reason"`
	Counters codexReportCounters `json:"counters"`
	// CodexVersions are the versions of the Codex requests the proxy
	// carried since the last accepted report.
	CodexVersions []string `json:"codexVersions,omitempty"`
}

// codexReportCounters are what the proxy job counted since the last accepted
// report (see codexroute.Counters).
type codexReportCounters struct {
	UpstreamFailures int `json:"upstreamFailures"`
	PassThroughs     int `json:"passThroughs"`
	PartsMissing     int `json:"partsMissing"`
}

func newCodexReport(state routeState, counters codexroute.Counters) codexReport {
	report := codexReport{State: state.state, CodexVersions: counters.CodexVersions, Counters: codexReportCounters{
		UpstreamFailures: counters.UpstreamFailures, PassThroughs: counters.PassThroughs, PartsMissing: counters.PartsMissing}}
	if state.state != codexRouted {
		reason := state.reason
		if reason == "" {
			reason = codexroute.ReasonRouteError
		}
		report.Reason = &reason
	}
	return report
}

// codexReportInterval is how long the daemon goes without a report going
// through before it sends the latest state again, and the longest it waits
// to retry one that failed.
const codexReportInterval = time.Hour

// codexRouteState is what the reports read from the proxy's state, and clear
// there once reported: see codexroute.Router.
type codexRouteState interface {
	Counters() codexroute.Counters
	Reported(codexroute.Counters) error
	TakeAway() *codexroute.TakeAway
	ClearTakeAway(codexroute.TakeAway) error
}

// codexReports sends where the Codex route stands to the Kontext API, one
// report at a time, so they arrive in the order sent: what took the route
// away, when something did, then the route's latest state, and that again
// once no report went through for codexReportInterval. The API keeps only
// the latest report, so a state not yet sent gives way to a later one; a
// take-away waits in route.json until a report of it went through, and so
// outlives a daemon restart. Each report carries what the proxy job counted
// since the last one the API kept. Only the daemon's routing goroutine uses
// it; nil sends nothing.
type codexReports struct {
	send       func(context.Context, codexReport) error
	route      codexRouteState
	diagnostic diagnostic.Logger
	now        func() time.Time

	// current is the route's latest state, and sent the last the API took;
	// takeAway is the take-away to report first, if any, and reported one
	// whose report went through but that route.json still holds, since
	// clearing it there failed. reportedAt is when a report last went
	// through: kept, or turned away for good.
	current, sent      routeState
	takeAway, reported *codexroute.TakeAway
	reportedAt         time.Time
	// failures counts the sends that failed in a row: the next waits until
	// retryAt, unless the route changes first.
	failures                      int
	retryAt                       time.Time
	lastFailure, lastClearFailure string
}

// update takes the state an apply left the route in, with any take-away
// waiting in route.json, and sends what changed at once: a change waits for
// no retry.
func (r *codexReports) update(ctx context.Context, state routeState) {
	if r == nil {
		return
	}
	before := r.takeAway
	r.refreshTakeAway()
	changed := state != r.current || r.takeAway != nil && (before == nil || !r.takeAway.Same(*before))
	r.current = state
	if changed {
		r.flush(ctx)
	}
}

// tick sends what is due once a failed send's wait is over: a report that
// failed, a take-away route.json got since, and the latest state again once
// no report went through for codexReportInterval.
func (r *codexReports) tick(ctx context.Context) {
	if r == nil || r.now().Before(r.retryAt) {
		return
	}
	r.refreshTakeAway()
	r.flush(ctx)
}

// refreshTakeAway reads the take-away waiting in route.json, once a reported
// one is cleared there: one a failed clear left behind is cleared again,
// never reported again, and a later one that replaced it is reported next.
func (r *codexReports) refreshTakeAway() {
	if r.reported != nil {
		if err := r.route.ClearTakeAway(*r.reported); err != nil {
			if message := err.Error(); message != r.lastClearFailure {
				diagnostic.LogAlways(r.diagnostic, "codex proxy: reported take-away not cleared: %v\n", err)
				r.lastClearFailure = message
			}
			r.takeAway = nil
			return
		}
		r.reported, r.lastClearFailure = nil, ""
	}
	r.takeAway = r.route.TakeAway()
}

// next is the report due, if any: the take-away first, then the current
// state, when the API took another or took none for codexReportInterval.
func (r *codexReports) next() (routeState, bool) {
	switch {
	case r.takeAway != nil:
		return routeState{codexTakenAway, r.takeAway.Reason}, true
	case r.current.state != "" && (r.current != r.sent || r.now().Sub(r.reportedAt) >= codexReportInterval):
		return r.current, true
	}
	return routeState{}, false
}

// flush sends what is due, in order, and stops at a report that failed, to
// try it again later. A report the API turns away for good, because it keeps
// a later one or refuses this one, goes too: sent again, it would replace
// the later one, or be refused again.
func (r *codexReports) flush(ctx context.Context) {
	for {
		state, due := r.next()
		if !due {
			return
		}
		counters := r.route.Counters()
		err := r.send(ctx, newCodexReport(state, counters))
		if err != nil && !errors.Is(err, errReportSuperseded) && !errors.Is(err, errReportRejected) {
			r.failures++
			r.retryAt = r.now().Add(min(time.Minute<<min(r.failures-1, 6), codexReportInterval))
			if message := err.Error(); message != r.lastFailure {
				diagnostic.LogAlways(r.diagnostic, "codex proxy: route report not sent: %v\n", err)
				r.lastFailure = message
			}
			return
		}
		r.sent, r.reportedAt = state, r.now()
		r.failures, r.retryAt, r.lastFailure = 0, time.Time{}, ""
		if state.state == codexTakenAway && r.takeAway != nil {
			// A later take-away may have replaced it meanwhile: that one goes
			// next.
			r.reported = r.takeAway
			r.refreshTakeAway()
		}
		if err != nil {
			// Its counts go with the next report.
			diagnostic.LogAlways(r.diagnostic, "codex proxy: route report not kept: %v\n", err)
			continue
		}
		// The API has these counts now; what the job counted since stays.
		if err := r.route.Reported(counters); err != nil {
			diagnostic.LogAlways(r.diagnostic, "codex proxy: reported counts not taken off: %v\n", err)
		}
	}
}

// codexReportClient sends the daemon's Codex route reports with the install
// token, as the tool output compaction calls do.
type codexReportClient struct {
	endpoint string
	tokens   func(context.Context) (string, error)
	http     *http.Client
}

func newCodexReportClient(baseURL, installationID string, tokens func(context.Context) (string, error), httpClient *http.Client) (*codexReportClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("codex route reports: invalid base URL")
	}
	if strings.TrimSpace(installationID) == "" || tokens == nil {
		return nil, errors.New("codex route reports: installation ID and token source are required")
	}
	if httpClient == nil {
		httpClient = cloudhttp.NewClient(10 * time.Second)
	}
	return &codexReportClient{
		endpoint: strings.TrimRight(parsed.String(), "/") + "/api/v1/installations/" + url.PathEscape(installationID) + "/codex-proxy/reports",
		tokens:   tokens,
		http:     httpClient,
	}, nil
}

// errReportSuperseded is the API's 409: it keeps a report of the endpoint's
// that it received after this one, which it therefore did not keep. And
// errReportRejected is its 400 or 422: it does not take this report.
var (
	errReportSuperseded = errors.New("a later report is already kept")
	errReportRejected   = errors.New("not a report the API takes")
)

// send posts report; only 204, the API keeping it as the endpoint's latest,
// is success.
func (c *codexReportClient) send(ctx context.Context, report codexReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	token, err := c.tokens(ctx)
	if err != nil {
		return fmt.Errorf("install token: %w", err)
	}
	if token = strings.TrimSpace(token); token == "" {
		return errors.New("empty install token")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	switch response.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return errReportSuperseded
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: status %d", errReportRejected, response.StatusCode)
	}
	return fmt.Errorf("unexpected status %d", response.StatusCode)
}
