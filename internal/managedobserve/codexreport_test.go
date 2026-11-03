package managedobserve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
// turns the next conflicts away for a later one it keeps.
type fakeReportAPI struct {
	mu        sync.Mutex
	down      bool
	conflicts int
	accepted  []codexReport
	refused   int
}

func (a *fakeReportAPI) send(_ context.Context, report codexReport) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down {
		a.refused++
		return errors.New("unexpected status 503")
	}
	if a.conflicts > 0 {
		a.conflicts--
		a.refused++
		return errReportSuperseded
	}
	a.accepted = append(a.accepted, report)
	return nil
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

// The daemon reports each change of the route in order, waits after a
// refused report, longer each time, unless the route changes, and reports the
// latest again an hour after the API last accepted one. Each report carries
// what the job counted since the last accepted one, a refused one's counts
// included.
func TestCodexReportsSendEachChangeAndKeepCountsUntilAccepted(t *testing.T) {
	stateDir := t.TempDir()
	job := codexroute.New(codexroute.Options{Home: t.TempDir(), StateDir: stateDir, GOOS: "darwin"})
	api := &fakeReportAPI{}
	clock := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	reports := &codexReports{send: api.send, router: job, diagnostic: diagnostic.New(io.Discard, false), now: func() time.Time { return clock }}
	count := func(counts codexproxy.Counts) {
		t.Helper()
		if err := job.Count(counts); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()

	count(codexproxy.Counts{PassThroughs: 1, CodexVersion: "0.163.0"})
	reports.add(ctx, routeState{codexTakenAway, codexroute.ReasonDaemonStopped}, routeState{state: codexRouted})
	if got := describe(api.take()); got != "taken_away/daemon_stopped 0,1,0 0.163.0; routed/null 0,0,0 " {
		t.Fatalf("reports = %s", got)
	}
	// The same state again is no change.
	reports.add(ctx, routeState{state: codexRouted})
	if got := api.take(); len(got) != 0 {
		t.Fatalf("an unchanged route was reported: %s", describe(got))
	}

	api.setDown(true)
	count(codexproxy.Counts{UpstreamFailures: 3})
	reports.add(ctx, routeState{codexNotRouted, codexroute.ReasonUpstreamUnreachable})
	for _, wait := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		refused := api.refused
		clock = clock.Add(wait - time.Second)
		reports.tick(ctx)
		if api.refused != refused {
			t.Fatalf("retried before %s", wait)
		}
		clock = clock.Add(time.Second)
		reports.tick(ctx)
		if api.refused != refused+1 {
			t.Fatalf("not retried after %s", wait)
		}
	}
	// A change goes at once, whatever the wait; then the API takes both, in
	// order, with every count since the last accepted report.
	count(codexproxy.Counts{UpstreamFailures: 1, PartsMissing: 1, CodexVersion: "0.163.1"})
	api.setDown(false)
	reports.add(ctx, routeState{codexNotRouted, codexroute.ReasonCompactionOff})
	if got := describe(api.take()); got != "not_routed/upstream_unreachable 4,0,1 0.163.1; not_routed/compaction_off 0,0,0 " {
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
	if counters := job.Counters(); counters.PassThroughs != 0 || len(counters.CodexVersions) != 0 {
		t.Fatalf("counters left after the reports = %+v", counters)
	}
}

// A report the API turns away for a later one it keeps is never sent again,
// which would replace that one: its counts go with the next report, at the
// next change or an hour on.
func TestCodexReportsNeverResendAReportALaterOneReplaced(t *testing.T) {
	job := codexroute.New(codexroute.Options{Home: t.TempDir(), StateDir: t.TempDir(), GOOS: "darwin"})
	api := &fakeReportAPI{}
	clock := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	reports := &codexReports{send: api.send, router: job, diagnostic: diagnostic.New(io.Discard, false), now: func() time.Time { return clock }}
	ctx := context.Background()
	reports.add(ctx, routeState{state: codexRouted})
	if got := describe(api.take()); got != "routed/null 0,0,0 " {
		t.Fatalf("reports = %s", got)
	}

	if err := job.Count(codexproxy.Counts{PassThroughs: 1, CodexVersion: "0.163.0"}); err != nil {
		t.Fatal(err)
	}
	api.conflicts = 1
	reports.add(ctx, routeState{codexTakenAway, codexroute.ReasonDisabledLocally}, routeState{state: codexRouted})
	// The take-away was turned away; the state after it went at once, with
	// its counts.
	if got := describe(api.take()); got != "routed/null 0,1,0 0.163.0" || api.refused != 1 {
		t.Fatalf("reports = %s, refused %d", got, api.refused)
	}

	api.conflicts = 1
	reports.add(ctx, routeState{codexNotRouted, codexroute.ReasonCompactionOff})
	// Within the hour, neither the minute ticks nor the same state again
	// send it.
	for range 59 {
		clock = clock.Add(time.Minute)
		reports.tick(ctx)
		reports.add(ctx, routeState{codexNotRouted, codexroute.ReasonCompactionOff})
	}
	if got := api.take(); len(got) != 0 || api.refused != 2 {
		t.Fatalf("a report turned away was sent again: %s (refused %d)", describe(got), api.refused)
	}
	clock = clock.Add(time.Minute)
	reports.tick(ctx)
	if got := describe(api.take()); got != "not_routed/compaction_off 0,0,0 " {
		t.Fatalf("report an hour on = %s", got)
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
	for _, status = range []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict} {
		if err := client.send(context.Background(), report); err == nil || errors.Is(err, errReportSuperseded) != (status == http.StatusConflict) {
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
		reports: &codexReports{send: api.send, router: router, diagnostic: diagnostic.New(io.Discard, false), now: time.Now}}
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
	// `kontext codex-proxy disable` takes the line away; the daemon routes
	// Codex again, and says so after what took it.
	local := codexroute.New(codexroute.Options{Home: home, StateDir: filepath.Join(home, "state"), GOOS: "darwin",
		DisableReason: codexroute.ReasonDisabledLocally})
	if err := local.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.switched <- ""
	reported("routed/null 0,0,0 ; taken_away/disabled_locally 0,0,0 ; routed/null 0,0,0 ")
	c.switched <- codexroute.ReasonCodexProxyOff
	reported("routed/null 0,0,0 ; taken_away/disabled_locally 0,0,0 ; routed/null 0,0,0 ; not_routed/codex_proxy_off 0,0,0 ")
}
