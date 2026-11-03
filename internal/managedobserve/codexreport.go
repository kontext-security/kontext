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

// codexReportInterval is how long the daemon goes without a report the API
// took before it sends the latest state again, and the longest it waits to
// retry one that failed.
const codexReportInterval = time.Hour

// maxPendingReports bounds the states kept while the API accepts none: the
// latest matter, the oldest go first.
const maxPendingReports = 8

// codexReports sends where the Codex route stands to the Kontext API, one
// report at a time, so they arrive in the order sent: every change, in order,
// and the latest again once the API took none for codexReportInterval. Each
// report carries what the proxy job counted since the last one the API kept,
// so the counts of one it did not keep go with the next. Only the daemon's
// routing goroutine uses it; nil sends nothing.
type codexReports struct {
	send       func(context.Context, codexReport) error
	router     *codexroute.Router
	diagnostic diagnostic.Logger
	now        func() time.Time

	// pending are the states yet to report, oldest first, and current the
	// latest queued; reportedAt is when the API last took a report: kept
	// it, or turned it away for a later one it keeps (see
	// errReportSuperseded).
	pending    []routeState
	current    routeState
	reportedAt time.Time
	// failures counts the sends that failed in a row: the next waits until
	// retryAt, unless the route changes first.
	failures    int
	retryAt     time.Time
	lastFailure string
}

// add queues the states an apply left the route in, each that differs from
// the one before it, and sends them at once: a change waits for no retry.
func (r *codexReports) add(ctx context.Context, states ...routeState) {
	if r == nil {
		return
	}
	changed := false
	for _, state := range states {
		if state != r.current {
			r.pending, r.current, changed = append(r.pending, state), state, true
		}
	}
	if extra := len(r.pending) - maxPendingReports; extra > 0 {
		r.pending = r.pending[extra:]
	}
	if changed {
		r.flush(ctx)
	}
}

// tick sends what is due: the states left by a send that failed, once its
// wait is over, and the latest state again once the API took none for
// codexReportInterval.
func (r *codexReports) tick(ctx context.Context) {
	if r == nil || r.now().Before(r.retryAt) {
		return
	}
	if len(r.pending) == 0 && r.current.state != "" && r.now().Sub(r.reportedAt) >= codexReportInterval {
		r.pending = append(r.pending, r.current)
	}
	r.flush(ctx)
}

// flush sends the pending states in order, and stops at the first that
// failed, to try it again later.
func (r *codexReports) flush(ctx context.Context) {
	for len(r.pending) > 0 {
		counters := r.router.Counters()
		err := r.send(ctx, newCodexReport(r.pending[0], counters))
		if err != nil && !errors.Is(err, errReportSuperseded) {
			r.failures++
			r.retryAt = r.now().Add(min(time.Minute<<min(r.failures-1, 6), codexReportInterval))
			if message := err.Error(); message != r.lastFailure {
				diagnostic.LogAlways(r.diagnostic, "codex proxy: route report not sent: %v\n", err)
				r.lastFailure = message
			}
			return
		}
		r.pending = r.pending[1:]
		r.reportedAt = r.now()
		r.failures, r.retryAt, r.lastFailure = 0, time.Time{}, ""
		if err != nil {
			// Sent again, the report would replace the later one the API
			// keeps; its counts go with the next.
			diagnostic.LogAlways(r.diagnostic, "codex proxy: route report not kept: %v\n", err)
			continue
		}
		// The API has these counts now; what the job counted since stays.
		if err := r.router.Reported(counters); err != nil {
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
// that it received after this one, which it therefore did not keep.
var errReportSuperseded = errors.New("a later report is already kept")

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
	}
	return fmt.Errorf("unexpected status %d", response.StatusCode)
}
