package managedobserve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/codexproxy"
	"github.com/kontext-security/kontext/internal/codexroute"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// fakeReportAPI keeps the reports it accepts, refuses them while down, and
// turns the next conflicts away for a later one it keeps, and the next
// rejects as reports it does not take.
type fakeReportAPI struct {
	mu                 sync.Mutex
	down               bool
	conflicts, rejects int
	accepted           []codexReport
	refused            int
	// accept, when set, is told of each report as it is accepted.
	accept func(codexReport)
}

func (a *fakeReportAPI) send(_ context.Context, report codexReport) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.down:
		a.refused++
		return errors.New("unexpected status 503")
	case a.conflicts > 0:
		a.conflicts--
		a.refused++
		return errReportSuperseded
	case a.rejects > 0:
		a.rejects--
		a.refused++
		return fmt.Errorf("%w: status 400", errReportRejected)
	}
	a.accepted = append(a.accepted, report)
	if a.accept != nil {
		a.accept(report)
	}
	return nil
}

// withTakeAway is a router's state with a take-away the test sets, as the
// proxy job, the session start hook or `kontext codex-proxy disable` would
// leave in route.json.
type withTakeAway struct {
	*codexroute.Router
	takeAway *codexroute.TakeAway
	// clearFails fails the next clears, and lineGone says Kontext's line is
	// not in config.toml.
	clearFails int
	lineGone   bool
}

func (w *withTakeAway) TakeAway() *codexroute.TakeAway { return w.takeAway }

func (w *withTakeAway) InPlace() (int, bool) { return 49321, !w.lineGone }

func (w *withTakeAway) ClearTakeAway(t codexroute.TakeAway) error {
	if w.clearFails > 0 {
		w.clearFails--
		return errors.New("route.lock: permission denied")
	}
	if w.takeAway != nil && w.takeAway.Same(t) {
		w.takeAway = nil
	}
	return nil
}

// newTestReports is reports through api of a job's counters in a state
// folder of their own, on a clock the test moves.
func newTestReports(t *testing.T, api *fakeReportAPI, clock *time.Time) (*codexReports, *withTakeAway) {
	t.Helper()
	route := &withTakeAway{Router: codexroute.New(codexroute.Options{Home: t.TempDir(), StateDir: t.TempDir(), GOOS: "darwin"})}
	return &codexReports{send: api.send, route: route, diagnostic: diagnostic.New(io.Discard, false),
		now: func() time.Time { return *clock }}, route
}

func (a *fakeReportAPI) take() []codexReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	taken := a.accepted
	a.accepted = nil
	return taken
}

func (a *fakeReportAPI) setDown(down bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.down = down
}

// describe is a report as "state/reason counts versions", for comparing.
func describe(reports []codexReport) string {
	var out []string
	for _, report := range reports {
		reason := "null"
		if report.Reason != nil {
			reason = *report.Reason
		}
		counters := report.Counters
		out = append(out, fmt.Sprintf("%s/%s %d,%d,%d %s", report.State, reason, counters.UpstreamFailures, counters.PassThroughs,
			counters.PartsMissing, strings.Join(report.CodexVersions, ",")))
	}
	return strings.Join(out, "; ")
}

// The daemon reports what took the route away first, then the route's latest
// state: a state not sent yet gives way to a later one, since the API keeps
// only the latest. After a send that failed it waits, longer each time,
// unless the route changes, and it reports the latest state again an hour
// after a report last went through. Each report carries what the job counted
// since the last accepted one, a failed one's counts included.
func TestCodexReportsSendTheTakeAwayThenTheLatestState(t *testing.T) {
	api := &fakeReportAPI{}
	clock := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	reports, route := newTestReports(t, api, &clock)
	count := func(counts codexproxy.Counts) {
		t.Helper()
		if err := route.Count(counts); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()

	count(codexproxy.Counts{PassThroughs: 1, CodexVersion: "0.163.0"})
	route.takeAway = &codexroute.TakeAway{Reason: codexroute.ReasonDaemonStopped, At: clock}
	reports.update(ctx, routeState{state: codexRouted})
	if got := describe(api.take()); got != "taken_away/daemon_stopped 0,1,0 0.163.0; routed/null 0,0,0 " || route.takeAway != nil {
		t.Fatalf("reports = %s; take-away left %+v", got, route.takeAway)
	}
	// The same state again is no change.
	reports.update(ctx, routeState{state: codexRouted})
	if got := api.take(); len(got) != 0 {
		t.Fatalf("an unchanged route was reported: %s", describe(got))
	}

	api.setDown(true)
	count(codexproxy.Counts{UpstreamFailures: 3})
	reports.update(ctx, routeState{codexNotRouted, codexroute.ReasonUpstreamUnreachable})
	for _, wait := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		refused := api.refused
		clock = clock.Add(wait - time.Second)
		reports.tick(ctx)
		reports.update(ctx, routeState{codexNotRouted, codexroute.ReasonUpstreamUnreachable})
		if api.refused != refused {
			t.Fatalf("retried before %s", wait)
		}
		clock = clock.Add(time.Second)
		reports.tick(ctx)
		if api.refused != refused+1 {
			t.Fatalf("not retried after %s", wait)
		}
	}
	// A take-away and a change go at once, whatever the wait. Once the API
	// takes reports again, the take-away goes first, with every count since
	// the last accepted report, and the state that was never sent gives way
	// to the latest.
	count(codexproxy.Counts{UpstreamFailures: 1, PartsMissing: 1, CodexVersion: "0.163.1"})
	route.takeAway = &codexroute.TakeAway{Reason: codexroute.ReasonDisabledLocally, At: clock}
	refused := api.refused
	reports.update(ctx, routeState{codexNotRouted, codexroute.ReasonCompactionOff})
	if api.refused != refused+1 {
		t.Fatalf("a take-away waited for the retry")
	}
	api.setDown(false)
	clock = clock.Add(codexReportInterval)
	reports.tick(ctx)
	if got := describe(api.take()); got != "taken_away/disabled_locally 4,0,1 0.163.1; not_routed/compaction_off 0,0,0 " {
		t.Fatalf("reports = %s", got)
	}

	clock = clock.Add(codexReportInterval - time.Minute)
	reports.tick(ctx)
	if got := api.take(); len(got) != 0 {
		t.Fatalf("reported again before the hour: %s", describe(got))
	}
	count(codexproxy.Counts{PassThroughs: 2})
	clock = clock.Add(time.Minute)
	reports.tick(ctx)
	if got := describe(api.take()); got != "not_routed/compaction_off 0,2,0 " {
		t.Fatalf("hourly report = %s", got)
	}
	if counters := route.Counters(); counters.PassThroughs != 0 || len(counters.CodexVersions) != 0 {
		t.Fatalf("counters left after the reports = %+v", counters)
	}
}

// A report the API turns away for good is never sent again: one it turned
// away for a later one it keeps would replace that one, and one it refuses
// would be refused again. Its counts go with the next report, at the next
// change or an hour on, and a take-away turned away is cleared like one
// reported.
func TestCodexReportsNeverResendAReportTurnedAway(t *testing.T) {
	for name, turnAway := range map[string]func(*fakeReportAPI){
		"for a later one": func(api *fakeReportAPI) { api.conflicts = 1 },
		"as no report":    func(api *fakeReportAPI) { api.rejects = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeReportAPI{}
			clock := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
			reports, route := newTestReports(t, api, &clock)
			ctx := context.Background()
			reports.update(ctx, routeState{state: codexRouted})
			if got := describe(api.take()); got != "routed/null 0,0,0 " {
				t.Fatalf("reports = %s", got)
			}

			if err := route.Count(codexproxy.Counts{PassThroughs: 1, CodexVersion: "0.163.0"}); err != nil {
				t.Fatal(err)
			}
			turnAway(api)
			route.takeAway = &codexroute.TakeAway{Reason: codexroute.ReasonDisabledLocally, At: clock}
			reports.update(ctx, routeState{state: codexRouted})
			// The take-away was turned away; the state after it went at once,
			// with its counts.
			if got := describe(api.take()); got != "routed/null 0,1,0 0.163.0" || api.refused != 1 || route.takeAway != nil {
				t.Fatalf("reports = %s, refused %d, take-away %+v", got, api.refused, route.takeAway)
			}

			turnAway(api)
			reports.update(ctx, routeState{codexNotRouted, codexroute.ReasonCompactionOff})
			// Within the hour, neither the minute ticks nor the same state again
			// send it.
			for range 59 {
				clock = clock.Add(time.Minute)
				reports.tick(ctx)
				reports.update(ctx, routeState{codexNotRouted, codexroute.ReasonCompactionOff})
			}
			if got := api.take(); len(got) != 0 || api.refused != 2 {
				t.Fatalf("a report turned away was sent again: %s (refused %d)", describe(got), api.refused)
			}
			clock = clock.Add(time.Minute)
			reports.tick(ctx)
			if got := describe(api.take()); got != "not_routed/compaction_off 0,0,0 " {
				t.Fatalf("report an hour on = %s", got)
			}
		})
	}
}

// A take-away route.json gets while the daemon reports an earlier one is
// reported next, as is one that comes between two applies, at the next tick.
// One whose report went through is never reported again, though clearing it
// from route.json failed: the clear is tried again instead.
func TestCodexReportsReportEachTakeAwayOnce(t *testing.T) {
	api := &fakeReportAPI{}
	clock := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	reports, route := newTestReports(t, api, &clock)
	ctx := context.Background()
	later := &codexroute.TakeAway{Reason: codexroute.ReasonProxyDownAtSessionStart, At: clock.Add(time.Second)}
	api.accept = func(report codexReport) {
		if report.State == codexTakenAway && *report.Reason == codexroute.ReasonDaemonStopped {
			route.takeAway = later
		}
	}
	route.takeAway = &codexroute.TakeAway{Reason: codexroute.ReasonDaemonStopped, At: clock}
	reports.update(ctx, routeState{state: codexRouted})
	if got := describe(api.take()); got != "taken_away/daemon_stopped 0,0,0 ; taken_away/proxy_down_at_session_start 0,0,0 ; routed/null 0,0,0 " || route.takeAway != nil {
		t.Fatalf("reports = %s; take-away left %+v", got, route.takeAway)
	}

	// Between applies: the next tick reports it, the line gone with it.
	route.takeAway = &codexroute.TakeAway{Reason: codexroute.ReasonUpstreamUnreachable, At: clock.Add(time.Minute)}
	route.lineGone = true
	clock = clock.Add(time.Minute)
	reports.tick(ctx)
	if got := describe(api.take()); got != "taken_away/upstream_unreachable 0,0,0 " || route.takeAway != nil {
		t.Fatalf("reports at the tick = %s; take-away left %+v", got, route.takeAway)
	}

	// Clearing fails once: the next tick clears it, and nothing is reported
	// twice. An apply routed Codex again meanwhile.
	route.takeAway = &codexroute.TakeAway{Reason: codexroute.ReasonDisabledLocally, At: clock.Add(time.Minute)}
	route.clearFails, route.lineGone = 1, false
	reports.update(ctx, routeState{state: codexRouted})
	if got := describe(api.take()); got != "taken_away/disabled_locally 0,0,0 ; routed/null 0,0,0 " || route.takeAway == nil {
		t.Fatalf("reports with a failed clear = %s; take-away %+v", got, route.takeAway)
	}
	for range 3 {
		clock = clock.Add(time.Minute)
		reports.tick(ctx)
		reports.update(ctx, routeState{state: codexRouted})
	}
	if got := api.take(); len(got) != 0 || route.takeAway != nil {
		t.Fatalf("after the clear was tried again: reports %s, take-away %+v", describe(got), route.takeAway)
	}
}

// A take-away found at a tick, between applies, leaves the route as the
// take-away left it: the reports never call it routed again until an apply
// finds the line back, nor while the line is gone for any other reason.
func TestCodexReportsCallTheRouteRoutedOnlyWhileTheLineIsThere(t *testing.T) {
	api := &fakeReportAPI{}
	clock := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	reports, route := newTestReports(t, api, &clock)
	ctx := context.Background()
	reports.update(ctx, routeState{state: codexRouted})
	if got := describe(api.take()); got != "routed/null 0,0,0 " {
		t.Fatalf("reports = %s", got)
	}

	route.takeAway = &codexroute.TakeAway{Reason: codexroute.ReasonUpstreamUnreachable, At: clock}
	route.lineGone = true
	for range codexReportInterval / time.Minute * 2 {
		clock = clock.Add(time.Minute)
		reports.tick(ctx)
	}
	if got := describe(api.take()); got != "taken_away/upstream_unreachable 0,0,0 " {
		t.Fatalf("reports after a take-away found at a tick = %s", got)
	}
	// The next apply holds Codex off, then a later one routes it again.
	reports.update(ctx, routeState{codexNotRouted, codexroute.ReasonUpstreamUnreachable})
	route.lineGone = false
	reports.update(ctx, routeState{state: codexRouted})
	if got := describe(api.take()); got != "not_routed/upstream_unreachable 0,0,0 ; routed/null 0,0,0 " {
		t.Fatalf("reports after the next applies = %s", got)
	}
	// A line gone with no take-away, as by hand, is not reported as routed
	// an hour on either.
	route.lineGone = true
	clock = clock.Add(codexReportInterval)
	reports.tick(ctx)
	if got := api.take(); len(got) != 0 {
		t.Fatalf("a route whose line went was reported: %s", describe(got))
	}
}

// A report says why exactly when Codex is not routed, and never sends an
// empty reason.
func TestCodexReportBodies(t *testing.T) {
	for state, want := range map[routeState]string{
		{state: codexRouted}: `{"state":"routed","reason":null,"counters":{"upstreamFailures":0,"passThroughs":2,"partsMissing":0},"codexVersions":["0.163.0"]}`,
		{codexTakenAway, codexroute.ReasonDisabledLocally}: `{"state":"taken_away","reason":"disabled_locally","counters":{"upstreamFailures":0,"passThroughs":2,"partsMissing":0},"codexVersions":["0.163.0"]}`,
		{state: codexNotRouted}:                            `{"state":"not_routed","reason":"route_error","counters":{"upstreamFailures":0,"passThroughs":2,"partsMissing":0},"codexVersions":["0.163.0"]}`,
	} {
		data, err := json.Marshal(newCodexReport(state, codexroute.Counters{PassThroughs: 2, CodexVersions: []string{"0.163.0"}}))
		if err != nil || string(data) != want {
			t.Errorf("report for %+v = %s, %v; want %s", state, data, err, want)
		}
	}
	if data, _ := json.Marshal(newCodexReport(routeState{state: codexRouted}, codexroute.Counters{})); strings.Contains(string(data), "codexVersions") {
		t.Errorf("a report without versions names some: %s", data)
	}
}

// Reports go to the endpoint's codex-proxy route with the install token, and
// only 204 counts as accepted.
func TestCodexReportClientPostsWithTheInstallToken(t *testing.T) {
	status := http.StatusNoContent
	var got struct {
		method, path, authorization, contentType string
		body                                     map[string]any
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.authorization, got.contentType = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		w.WriteHeader(status)
	}))
	defer server.Close()
	client, err := newCodexReportClient(server.URL+"/", "ins_0123456789abcdefghijklmnopqrstuv",
		func(context.Context) (string, error) { return " install-token\n", nil }, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	report := newCodexReport(routeState{state: codexRouted}, codexroute.Counters{})
	if err := client.send(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/api/v1/installations/ins_0123456789abcdefghijklmnopqrstuv/codex-proxy/reports" ||
		got.authorization != "Bearer install-token" || got.contentType != "application/json" || got.body["state"] != "routed" {
		t.Fatalf("request = %+v", got)
	}
	for _, status = range []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict,
		http.StatusUnprocessableEntity, http.StatusTooManyRequests} {
		if err := client.send(context.Background(), report); err == nil || errors.Is(err, errReportSuperseded) != (status == http.StatusConflict) ||
			errors.Is(err, errReportRejected) != (status == http.StatusBadRequest || status == http.StatusUnprocessableEntity) {
			t.Errorf("status %d: %v", status, err)
		}
	}
	failing, err := newCodexReportClient(server.URL, "ins_0123456789abcdefghijklmnopqrstuv",
		func(context.Context) (string, error) { return "", errors.New("keychain locked") }, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := failing.send(context.Background(), report); err == nil || !strings.Contains(err.Error(), "keychain locked") {
		t.Fatalf("send without a token = %v", err)
	}
}

// Codex is routed only while both switches are on; with both off,
// compaction's is the reason.
func TestCodexRoutingFollowsBothSwitches(t *testing.T) {
	for _, test := range []struct {
		compaction, codexProxy *bool
		want                   string
	}{
		{boolPtr(true), boolPtr(true), ""},
		{boolPtr(true), nil, ""},
		{boolPtr(true), boolPtr(false), codexroute.ReasonCodexProxyOff},
		{boolPtr(false), boolPtr(true), codexroute.ReasonCompactionOff},
		{boolPtr(false), boolPtr(false), codexroute.ReasonCompactionOff},
	} {
		c := &codexRouting{switched: make(chan string, 1)}
		config := endpointconfig.Config{PayloadCaptureMode: payloadcapture.ModeSummary, WorkTypeClassification: boolPtr(true),
			ToolOutputCompaction: test.compaction, CodexProxy: test.codexProxy}
		c.follow(endpointconfig.Snapshot{Config: config, Confirmed: true})
		if got := <-c.switched; got != test.want {
			t.Errorf("compaction %v, Codex proxy %v: off = %q, want %q", *test.compaction, test.codexProxy, got, test.want)
		}
	}
	c := &codexRouting{switched: make(chan string, 1)}
	c.follow(endpointconfig.Snapshot{Config: endpointconfig.Config{ToolOutputCompaction: boolPtr(true)}})
	select {
	case off := <-c.switched:
		t.Fatalf("an unconfirmed configuration switched the route: %q", off)
	default:
	}
}

func boolPtr(value bool) *bool { return &value }

// The routing loop reports where each switch leaves the route, and, before
// the route it restores, what took the last one away.
func TestCodexRoutingReportsWhereTheRouteStands(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the router locks the route and copies the binary on macOS and Linux only")
	}
	router, home := testRouter(t)
	api := &fakeReportAPI{}
	c := &codexRouting{router: router, diagnostic: diagnostic.New(io.Discard, false), switched: make(chan string, 1),
		reports: &codexReports{send: api.send, route: router, diagnostic: diagnostic.New(io.Discard, false), now: time.Now}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	reported := func(want string) {
		t.Helper()
		got := ""
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			api.mu.Lock()
			got = describe(api.accepted)
			api.mu.Unlock()
			if got == want {
				return
			}
		}
		t.Fatalf("reports = %s\nwant      %s", got, want)
	}

	c.switched <- ""
	reported("routed/null 0,0,0 ")
	// `kontext codex-proxy disable` takes the line away and keeps Codex off:
	// the daemon says so after what took it, until `kontext codex-proxy
	// enable`, and then routes Codex again.
	local := codexroute.New(codexroute.Options{Home: home, StateDir: filepath.Join(home, "state"), GOOS: "darwin",
		DisableReason: codexroute.ReasonDisabledLocally})
	if err := local.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.switched <- ""
	reported("routed/null 0,0,0 ; taken_away/disabled_locally 0,0,0 ; not_routed/disabled_locally 0,0,0 ")
	if _, err := local.EnableLocally(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.switched <- ""
	reported("routed/null 0,0,0 ; taken_away/disabled_locally 0,0,0 ; not_routed/disabled_locally 0,0,0 ; routed/null 0,0,0 ")
	c.switched <- codexroute.ReasonCodexProxyOff
	reported("routed/null 0,0,0 ; taken_away/disabled_locally 0,0,0 ; not_routed/disabled_locally 0,0,0 ; routed/null 0,0,0 ; " +
		"not_routed/codex_proxy_off 0,0,0 ")
}

// While the person keeps Codex off, that is the reason the daemon reports,
// whatever the switches say.
func TestCodexRoutingReportsTheirDisableWhateverTheSwitches(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the router locks the route and copies the binary on macOS and Linux only")
	}
	router, home := testRouter(t)
	c := &codexRouting{router: router, diagnostic: diagnostic.New(io.Discard, false), switched: make(chan string, 1)}
	local := codexroute.New(codexroute.Options{Home: home, StateDir: filepath.Join(home, "state"), GOOS: "darwin",
		DisableReason: codexroute.ReasonDisabledLocally})
	if err := local.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, off := range []string{"", codexroute.ReasonCodexProxyOff, codexroute.ReasonCompactionOff, ""} {
		if result, state := c.apply(context.Background(), off); state != (routeState{codexNotRouted, codexroute.ReasonDisabledLocally}) ||
			!strings.Contains(result, "disabled") {
			t.Errorf("apply(%q) = %q, %+v", off, result, state)
		}
	}
}

// A failed Enable or Disable that leaves Kontext's line in config.toml leaves
// Codex going through the proxy, and the route reports so.
func TestCodexRoutingReportsTheRouteCodexStillHas(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the router locks the route and copies the binary on macOS and Linux only")
	}
	router, home := testRouter(t)
	c := &codexRouting{router: router, diagnostic: diagnostic.New(io.Discard, false), switched: make(chan string, 1)}
	ctx := context.Background()
	if result, state := c.apply(ctx, ""); state != (routeState{state: codexRouted}) {
		t.Fatalf("apply = %s, %+v", result, state)
	}
	// Neither can take the route's lock now.
	lock := filepath.Join(home, "state", "route.lock")
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if result, state := c.apply(ctx, ""); state != (routeState{state: codexRouted}) || !strings.Contains(result, "routed through 127.0.0.1:49321, but") {
		t.Fatalf("apply after a failed Enable = %s, %+v", result, state)
	}
	if result, state := c.apply(ctx, codexroute.ReasonCompactionOff); state != (routeState{state: codexRouted}) || !strings.HasPrefix(result, "route not removed") {
		t.Fatalf("apply after a failed Disable = %s, %+v", result, state)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if result, state := c.apply(ctx, codexroute.ReasonCompactionOff); state != (routeState{codexNotRouted, codexroute.ReasonCompactionOff}) {
		t.Fatalf("apply once the line went = %s, %+v", result, state)
	}
}
