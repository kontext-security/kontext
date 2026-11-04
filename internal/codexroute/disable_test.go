package codexroute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kontext-security/kontext/internal/codexmanaged"
)

// `kontext codex-proxy disable` keeps Codex off the proxy: the daemon's
// Enable leaves it unrouted and says why, in the words it reports, after a
// drain and in a daemon started again, until `kontext codex-proxy enable`.
func TestCodexStaysOffOnceTheyDisableIt(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	if err := r.local().Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if done, err := r.Drain(context.Background()); err != nil || !done {
		t.Fatalf("Drain = %v, %v", done, err)
	}
	for _, daemon := range []*Router{r.Router, r.daemon(t)} {
		for range 2 {
			status, err := daemon.Enable(context.Background())
			if err != nil || status.Routed || status.Reason != ReasonDisabledLocally || !status.DisabledLocally ||
				!strings.Contains(status.Skipped, "kontext codex-proxy enable") {
				t.Fatalf("Enable after disable = %+v, %v", status, err)
			}
		}
	}
	if readFile(t, configPath) != original || r.launchd.loaded {
		t.Fatalf("a daemon routed Codex again after disable (job loaded: %v):\n%s", r.launchd.loaded, readFile(t, configPath))
	}
	status := r.Status(context.Background())
	if status.Routed || !status.DisabledLocally || status.DisabledAt.IsZero() || !strings.Contains(status.Skipped, "kontext codex-proxy enable") {
		t.Fatalf("Status after disable = %+v", status)
	}
	if at, disabled := r.DisabledLocally(); !disabled || !at.Equal(status.DisabledAt) {
		t.Fatalf("DisabledLocally = %v, %v; Status says %v", at, disabled, status.DisabledAt)
	}

	if enabled, err := r.local().EnableLocally(context.Background()); err != nil || !enabled {
		t.Fatalf("EnableLocally = %v, %v", enabled, err)
	}
	if status := r.Status(context.Background()); status.DisabledLocally || !status.DisabledAt.IsZero() {
		t.Fatalf("Status after enable = %+v", status)
	}
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed || status.DisabledLocally {
		t.Fatalf("Enable after enable = %+v, %v", status, err)
	}
	// Enabling a route nobody disabled changes nothing.
	if enabled, err := r.local().EnableLocally(context.Background()); err != nil || enabled {
		t.Fatalf("EnableLocally again = %v, %v", enabled, err)
	}
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable after a second enable = %+v, %v", status, err)
	}
}

// While Codex is kept off, that is the reason the daemon reports, whatever
// else would keep it unrouted.
func TestTheirDisableIsTheReasonWhateverElseHolds(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, r testRouter)
	}{
		{"their base URL", func(t *testing.T, r testRouter) {
			writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), "openai_base_url = \"https://gateway.example/v1\"\n", 0o600)
		}},
		{"an administrator's provider", func(t *testing.T, r testRouter) {
			*r.admin = adminAnswer{blocker: codexmanaged.Blocker{Setting: codexmanaged.SettingModelProvider, Text: "an administrator sets model_provider"}}
		}},
		{"a proxy that cannot reach OpenAI", func(t *testing.T, r testRouter) { *r.reaches = false }},
		{"a config Kontext cannot read", func(t *testing.T, r testRouter) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a file no one may read")
			}
			path := filepath.Join(r.home, ".codex", "config.toml")
			writeFile(t, path, original, 0o600)
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newTestRouter(t)
			if err := r.local().Disable(context.Background()); err != nil {
				t.Fatal(err)
			}
			test.setup(t, r)
			if status, _ := r.Enable(context.Background()); status.Routed || status.Reason != ReasonDisabledLocally {
				t.Fatalf("Enable = %+v; want reason %s", status, ReasonDisabledLocally)
			}
		})
	}
}

// A line that comes back while Codex is kept off, as a daemon of a build from
// before the marker writes it, goes again at the next Enable.
func TestALineBackWhileDisabledGoesAgain(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	if err := r.local().Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeFile(t, configPath, routed, 0o600)
	if status, err := r.Enable(context.Background()); err != nil || status.Routed || status.Reason != ReasonDisabledLocally {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	if readFile(t, configPath) != original {
		t.Fatalf("line kept:\n%s", readFile(t, configPath))
	}
}

// A disable that lands while the daemon's Enable is under way, before Enable
// takes the route's lock, keeps Codex off all the same.
func TestADisableDuringEnableKeepsCodexOff(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	var once sync.Once
	opts := r.opts
	opts.AdminRoute = func(string) (codexmanaged.Blocker, error) {
		// Enable asks first before it takes the lock.
		once.Do(func() {
			if err := r.local().Disable(context.Background()); err != nil {
				t.Error(err)
			}
		})
		return codexmanaged.Blocker{}, nil
	}
	if status, err := New(opts).Enable(context.Background()); err != nil || status.Routed || status.Reason != ReasonDisabledLocally {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	if readFile(t, configPath) != original {
		t.Fatalf("routed after disable:\n%s", readFile(t, configPath))
	}
}

// The daemon's own Disable, as its switches go off, keeps nothing off: they
// alone decide again.
func TestTheSwitchesGoingOffKeepNothingOff(t *testing.T) {
	r := newTestRouter(t)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, disabled := r.DisabledLocally(); disabled {
		t.Fatal("the daemon's Disable kept Codex off")
	}
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable after the switches came back = %+v, %v", status, err)
	}
}

// `kontext codex-proxy disable --now` keeps Codex off as well; uninstall
// takes the marker away with the rest of the proxy's state, whether or not a
// line was left to take.
func TestDisablingNowKeepsCodexOffUntilUninstall(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	if _, err := r.local().Remove(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if status, _ := r.Enable(context.Background()); status.Routed || status.Reason != ReasonDisabledLocally || r.launchd.loaded {
		t.Fatalf("Enable after disable --now = %+v (job loaded: %v)", status, r.launchd.loaded)
	}
	// Nothing routed and no job: uninstall's short way.
	if _, err := r.Remove(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.opts.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall left the state behind: %v", err)
	}
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable after uninstall = %+v, %v", status, err)
	}

	// A line put back while Codex was kept off: uninstall's long way.
	if err := r.local().Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeFile(t, configPath, routed, 0o600)
	if _, err := r.Remove(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if readFile(t, configPath) != original {
		t.Fatalf("uninstall left the line:\n%s", readFile(t, configPath))
	}
	if _, err := os.Stat(r.opts.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall left the state behind: %v", err)
	}
}
