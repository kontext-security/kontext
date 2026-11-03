package codexroute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/codexproxy"
)

// Each way Enable leaves Codex unrouted says why, in the words the daemon
// reports.
func TestEnableSaysWhyCodexIsNotRouted(t *testing.T) {
	admin := func(setting string) func(testRouter) {
		return func(r testRouter) {
			*r.admin = adminAnswer{blocker: codexmanaged.Blocker{Setting: setting, Text: "/etc/codex/managed_config.toml sets " + setting}}
		}
	}
	for _, test := range []struct {
		name   string
		config string
		setup  func(testRouter)
		want   string
	}{
		{"their base URL", "openai_base_url = \"https://gateway.example/v1\"\n", nil, ReasonUserOpenAIBaseURL},
		{"another provider", "model_provider = \"ollama\"\n", nil, ReasonUserModelProvider},
		{"their ChatGPT backend", "chatgpt_base_url = \"https://chatgpt.internal.example/backend-api\"\n", nil, ReasonUserChatGPTBaseURL},
		{"a config that does not parse", "model = \n", nil, ReasonCodexConfigUnparseable},
		// A line cannot go in front of a byte order mark.
		{"a config a line cannot go into", "\xef\xbb\xbf" + original, nil, ReasonCodexConfigNotEditable},
		{"a config Kontext cannot read", original, func(r testRouter) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a file no one may read")
			}
			path := filepath.Join(r.home, ".codex", "config.toml")
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		}, ReasonCodexConfigPermissions},
		{"an administrator's base URL", original, admin(codexmanaged.SettingOpenAIBaseURL), ReasonAdminOpenAIBaseURL},
		{"an administrator's provider", original, admin(codexmanaged.SettingModelProvider), ReasonAdminModelProvider},
		{"an administrator's ChatGPT backend", original, admin(codexmanaged.SettingChatGPTBaseURL), ReasonAdminChatGPTBaseURL},
		{"an administrator's layer Kontext cannot read", original, func(r testRouter) {
			*r.admin = adminAnswer{err: errors.New("/etc/codex/config.toml: permission denied")}
		}, ReasonAdminConfigUnreadable},
		{"a job launchd refuses", original, func(r testRouter) { r.launchd.refuse = 1 }, ReasonProxyJobNotLoaded},
		{"a proxy that does not answer", original, func(r testRouter) { *r.healthy = false }, ReasonProxyNotAnswering},
		{"a proxy that cannot reach OpenAI", original, func(r testRouter) { *r.reaches = false }, ReasonUpstreamUnreachable},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newTestRouter(t)
			writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), test.config, 0o600)
			if test.setup != nil {
				test.setup(r)
			}
			if status, err := r.Enable(context.Background()); status.Routed || status.Reason != test.want {
				t.Fatalf("Enable = %+v, %v; want reason %s", status, err, test.want)
			}
		})
	}

	r := newTestRouter(t)
	for name, opts := range map[string]func(*Options){
		ReasonMacOSOnly:          func(opts *Options) { opts.GOOS = "linux" },
		ReasonProxyInstallFailed: func(opts *Options) { opts.Binary = nil },
		ReasonRouteError:         func(opts *Options) { opts.FreePort = func() (int, error) { return 0, errors.New("no free port") } },
	} {
		options := r.opts
		opts(&options)
		if status, err := New(options).Enable(context.Background()); status.Routed || status.Reason != name {
			t.Errorf("Enable = %+v, %v; want reason %s", status, err, name)
		}
	}
}

// A proxy the routed line names that misses a health check is still where
// Codex goes, until it misses the last one Enable allows.
func TestEnableKeepsReportingARouteThatMissesAHealthCheck(t *testing.T) {
	r := newTestRouter(t)
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	*r.healthy = false
	for range maxHealthFailures - 1 {
		if status, err := r.Enable(context.Background()); err == nil || !status.Routed || status.Reason != "" {
			t.Fatalf("Enable after a missed check = %+v, %v", status, err)
		}
	}
	if status, err := r.Enable(context.Background()); err == nil || status.Routed || status.Reason != ReasonProxyNotAnswering {
		t.Fatalf("Enable after the last missed check = %+v, %v", status, err)
	}
}

// What takes the line away records why, and the record waits for the
// daemon's report of it, whatever the daemon's own checks find meanwhile:
// the proxy job, once no daemon holds the route or its requests cannot reach
// OpenAI; Codex's session start hook, once nothing answers on its port; and
// `kontext codex-proxy disable`, with --now as well. Clearing a record leaves
// a later one. What a daemon takes away itself it reports itself, and
// uninstall leaves nothing behind.
func TestEachTakeAwayWaitsForTheDaemonsReport(t *testing.T) {
	for _, test := range []struct {
		name string
		take func(t *testing.T, r testRouter)
		want string
		// routes says whether the daemon's next Enable routes Codex again.
		routes bool
	}{
		{"no daemon holds the route", func(t *testing.T, r testRouter) {
			r.processes.stop(os.Getpid())
			if held, err := r.job(leaseGrace + time.Minute).Held(context.Background()); err != nil || held {
				t.Fatalf("Held = %v, %v", held, err)
			}
			r.processes.run(os.Getpid(), time.Now())
		}, ReasonDaemonStopped, true},
		{"the job's requests cannot reach OpenAI", func(t *testing.T, r testRouter) {
			if taken, err := r.job(0).Unreachable(context.Background()); err != nil || !taken {
				t.Fatalf("Unreachable = %v, %v", taken, err)
			}
		}, ReasonUpstreamUnreachable, false},
		{"nothing answers as a session starts", func(t *testing.T, r testRouter) {
			if unrouted, err := r.hook(refused, nil).UnrouteUnanswered(context.Background()); err != nil || !unrouted {
				t.Fatalf("UnrouteUnanswered = %v, %v", unrouted, err)
			}
		}, ReasonProxyDownAtSessionStart, true},
		{"the person disables it", func(t *testing.T, r testRouter) {
			if err := r.local().Disable(context.Background()); err != nil {
				t.Fatal(err)
			}
		}, ReasonDisabledLocally, true},
		{"the person disables it now", func(t *testing.T, r testRouter) {
			if _, err := r.local().Remove(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
		}, ReasonDisabledLocally, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newTestRouter(t)
			configPath := filepath.Join(r.home, ".codex", "config.toml")
			writeFile(t, configPath, original, 0o600)
			if status, err := r.Enable(context.Background()); err != nil || !status.Routed || r.TakeAway() != nil {
				t.Fatalf("Enable = %+v, %v; take-away %+v", status, err, r.TakeAway())
			}
			test.take(t, r)
			if readFile(t, configPath) != original {
				t.Fatalf("line kept:\n%s", readFile(t, configPath))
			}
			for range 2 {
				if status, _ := r.Enable(context.Background()); status.Routed != test.routes {
					t.Fatalf("Enable after the take-away = %+v", status)
				}
				if taken := r.TakeAway(); taken == nil || taken.Reason != test.want || taken.At.IsZero() {
					t.Fatalf("take-away = %+v, want %s until reported", taken, test.want)
				}
			}
			reported := *r.TakeAway()
			if err := r.ClearTakeAway(reported); err != nil || r.TakeAway() != nil {
				t.Fatalf("ClearTakeAway = %v; take-away %+v", err, r.TakeAway())
			}
		})
	}

	// A take-away that came after the one reported stays for the next
	// report.
	r := newTestRouter(t)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.local().Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := *r.TakeAway()
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if unrouted, err := r.hook(refused, nil).UnrouteUnanswered(context.Background()); err != nil || !unrouted {
		t.Fatalf("UnrouteUnanswered = %v, %v", unrouted, err)
	}
	if err := r.ClearTakeAway(first); err != nil {
		t.Fatal(err)
	}
	if taken := r.TakeAway(); taken == nil || taken.Reason != ReasonProxyDownAtSessionStart {
		t.Fatalf("take-away after clearing an earlier one = %+v", taken)
	}

	// The daemon's own take-aways, as when its switch goes off, record
	// nothing; neither does uninstall, which leaves no state behind.
	r = newTestRouter(t)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Disable(context.Background()); err != nil || r.TakeAway() != nil {
		t.Fatalf("the daemon's Disable = %v; take-away %+v", err, r.TakeAway())
	}
	if _, err := r.Remove(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.opts.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall left the state behind: %v", err)
	}
}

// `kontext codex-proxy disable --now` removes the proxy's state but keeps
// what the daemon has yet to report: the last take-away and the job's
// counts, also when the route and the job were gone already.
func TestDisablingNowKeepsWhatTheDaemonHasYetToReport(t *testing.T) {
	r := newTestRouter(t)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.job(0).Count(codexproxy.Counts{PassThroughs: 2, CodexVersion: "0.163.0"}); err != nil {
		t.Fatal(err)
	}
	// A daemon may be waiting on the route's lock as the state goes: the
	// lock stays the one it waits on.
	lock, err := os.Stat(r.lockPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.local().Remove(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{TokenPath(r.opts.StateDir), filepath.Dir(BinaryPath(r.opts.StateDir))} {
		if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stayed: %v", gone, err)
		}
	}
	if after, err := os.Stat(r.lockPath()); err != nil || !os.SameFile(lock, after) {
		t.Fatalf("the route's lock was replaced: %v", err)
	}
	taken := r.TakeAway()
	if counters := r.Counters(); taken == nil || taken.Reason != ReasonDisabledLocally || counters.PassThroughs != 2 ||
		!slices.Equal(counters.CodexVersions, []string{"0.163.0"}) {
		t.Fatalf("after disable --now: take-away %+v, counters %+v", taken, counters)
	}
	// Again, with nothing left to take away: the record and the counts stay
	// as they were.
	if _, err := r.local().Remove(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if again := r.TakeAway(); again == nil || !again.Same(*taken) || r.Counters().PassThroughs != 2 {
		t.Fatalf("after a second disable --now: take-away %+v, counters %+v", again, r.Counters())
	}
	// The daemon routes Codex again from what is left.
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed || r.TakeAway() == nil {
		t.Fatalf("Enable after disable --now = %+v, %v; take-away %+v", status, err, r.TakeAway())
	}
}

// local is the router of the person's own commands, as `kontext codex-proxy
// disable` builds it.
func (r testRouter) local() *Router {
	opts := r.opts
	opts.DisableReason = ReasonDisabledLocally
	return New(opts)
}

// The job counts under a lock of its own, never waiting on a daemon that
// holds the route's; the daemon takes off what it reported, and what the job
// counted since stays.
func TestCountersRunUntilReported(t *testing.T) {
	r := newTestRouter(t)
	job := r.job(0)
	if counters := r.Counters(); counters.UpstreamFailures != 0 || len(counters.CodexVersions) != 0 {
		t.Fatalf("counters before any request = %+v", counters)
	}
	if err := job.Count(codexproxy.Counts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.countersPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a request that counted nothing wrote the counters: %v", err)
	}

	// A daemon changing the route holds its lock for as long as that takes.
	unlock, err := r.lock()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counts := codexproxy.Counts{UpstreamFailures: i % 2, PassThroughs: 1, CodexVersion: "0.163." + strconv.Itoa(i%3)}
			if i%5 == 0 {
				counts.PartsMissing = 1
			}
			if err := job.Count(counts); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	unlock()
	reported := r.Counters()
	slices.Sort(reported.CodexVersions)
	if reported.UpstreamFailures != 25 || reported.PassThroughs != 50 || reported.PartsMissing != 10 ||
		!slices.Equal(reported.CodexVersions, []string{"0.163.0", "0.163.1", "0.163.2"}) {
		t.Fatalf("counters = %+v", reported)
	}

	if err := job.Count(codexproxy.Counts{PassThroughs: 2, CodexVersion: "0.163.1"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Reported(reported); err != nil {
		t.Fatal(err)
	}
	if counters := r.Counters(); counters.UpstreamFailures != 0 || counters.PassThroughs != 2 || counters.PartsMissing != 0 || len(counters.CodexVersions) != 0 {
		t.Fatalf("counters after the report = %+v", counters)
	}
	// A version the daemon reported comes back with its next request.
	if err := job.Count(codexproxy.Counts{CodexVersion: "0.163.1"}); err != nil {
		t.Fatal(err)
	}
	if counters := r.Counters(); !slices.Equal(counters.CodexVersions, []string{"0.163.1"}) {
		t.Fatalf("versions after the next request = %v", counters.CodexVersions)
	}
}

// The counters stay within what the Kontext API takes: each count at most a
// billion, and at most eight versions, the first ones seen.
func TestCountersStayWithinWhatTheAPITakes(t *testing.T) {
	r := newTestRouter(t)
	job := r.job(0)
	for i := range maxCodexVersions + 2 {
		if err := job.Count(codexproxy.Counts{PassThroughs: maxCount / 2, CodexVersion: "1." + strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	counters := r.Counters()
	if counters.PassThroughs != maxCount || len(counters.CodexVersions) != maxCodexVersions || counters.CodexVersions[0] != "1.0" {
		t.Fatalf("counters = %+v", counters)
	}
	// A file the job could not have written loads within what the API takes.
	writeFile(t, r.countersPath(), `{"upstreamFailures":-3,"passThroughs":5000000000,"partsMissing":2,`+
		`"codexVersions":["0.1","0.1","bad version","","`+strings.Repeat("9", 33)+`","1","2","3","4","5","6","7","8"]}`, 0o600)
	if counters := r.Counters(); counters.UpstreamFailures != 0 || counters.PassThroughs != maxCount || counters.PartsMissing != 2 ||
		!slices.Equal(counters.CodexVersions, []string{"0.1", "1", "2", "3", "4", "5", "6", "7"}) {
		t.Fatalf("counters from a file the job could not have written = %+v", counters)
	}
	// A file that does not parse starts the counts again.
	writeFile(t, r.countersPath(), "{", 0o600)
	if counters := r.Counters(); counters.PassThroughs != 0 || len(counters.CodexVersions) != 0 {
		t.Fatalf("counters from a broken file = %+v", counters)
	}
	// Off macOS there is nothing to count.
	options := r.opts
	options.GOOS = "linux"
	if err := New(options).Count(codexproxy.Counts{PassThroughs: 1}); err != nil || New(options).Counters().PassThroughs != 0 {
		t.Fatalf("counted off macOS: %v", err)
	}
}
