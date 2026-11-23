package managedobserve

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/payloadcapture"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

type fakeHookScan struct {
	calls    int
	recorded int
	discards int
	// discardErr is what the purge returns.
	discardErr error
	// confirmed is whether the switch comes from a confirmed config.
	confirmed bool
	tag       string
	opts      agentauthority.HookScanOptions
}

func (f *fakeHookScan) holder(on *bool, keys *hookKeyBox) *hookHolder {
	return &hookHolder{
		keys:      keys,
		enabled:   func() bool { return *on },
		confirmed: func() bool { return f.confirmed },
		home:      func() (string, error) { return "/Users/dana", nil },
		scan: func(_ context.Context, opts agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error) {
			f.calls++
			f.opts = opts
			return agentauthority.HookAgent{ID: "claude_code"}, agentauthority.SourceResult{ID: "claude_code/hooks", Status: agentauthority.StatusComplete}, nil
		},
		record: func(_ agentauthority.HookAgent, _ agentauthority.SourceResult, tag string, _ uint64) {
			f.recorded++
			f.tag = tag
		},
		discard: func() error { f.discards++; return f.discardErr },
	}
}

// Nothing is read while the switch is off or the key is unknown; once on, a
// scan is recorded with the key and the agent's version; turning it off
// discards the pending results once. A confirmed config that says off drops
// results a previous run stored, even on the first tick.
func TestHookHolderFollowsSwitchAndKey(t *testing.T) {
	fake := &fakeHookScan{}
	on := false
	keys := newHookKeyBox()
	h := fake.holder(&on, keys)
	version := "2.1.329"
	inv := agentinventory.Inventory{Agents: []agentinventory.Agent{{ID: "claude_code", Version: &version}}}

	h.refresh(context.Background(), inv)
	if fake.calls != 0 || fake.discards != 0 {
		t.Fatalf("unconfirmed off: %+v", fake)
	}
	fake.confirmed = true
	h.refresh(context.Background(), inv)
	h.refresh(context.Background(), inv)
	if fake.calls != 0 || fake.discards != 1 {
		t.Fatalf("confirmed off at start: %+v", fake)
	}
	fake.discards = 0
	on = true
	h.refresh(context.Background(), inv)
	if fake.calls != 0 {
		t.Fatal("scanned without K_dev")
	}
	keys.set([]byte("k"), "t")
	h.refresh(context.Background(), inv)
	if fake.tag == "" || fake.tag != hookKeyTag([]byte("k")) || fake.tag == hookKeyTag([]byte("k2")) {
		t.Fatalf("key tag %q", fake.tag)
	}
	if fake.calls != 1 || fake.recorded != 1 || string(fake.opts.Key) != "k" || fake.opts.AgentVersion != version || fake.opts.Home != "/Users/dana" {
		t.Fatalf("switch on: %+v", fake)
	}
	on = false
	h.refresh(context.Background(), inv)
	h.refresh(context.Background(), inv)
	if fake.discards != 1 || fake.calls != 1 {
		t.Fatalf("switch off again: %+v", fake)
	}
}

// A scan that finishes after the switch went off records nothing.
func TestHookHolderDropsAScanFinishedAfterTurnOff(t *testing.T) {
	fake := &fakeHookScan{}
	on := true
	keys := newHookKeyBox()
	keys.set([]byte("k"), "t")
	h := fake.holder(&on, keys)
	scan := h.scan
	h.scan = func(ctx context.Context, opts agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error) {
		on = false
		return scan(ctx, opts)
	}
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 1 || fake.recorded != 0 {
		t.Fatalf("%+v", fake)
	}
}

// A scan read under a key the workspace no longer has records nothing, and
// nothing uploads while the key is withheld.
func TestHookHolderDropsAScanUnderAnOldKey(t *testing.T) {
	fake := &fakeHookScan{}
	on := true
	keys := newHookKeyBox()
	keys.set([]byte("k"), "t")
	h := fake.holder(&on, keys)
	scan := h.scan
	h.scan = func(ctx context.Context, opts agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error) {
		keys.clear()
		return scan(ctx, opts)
	}
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 1 || fake.recorded != 0 || h.uploading() {
		t.Fatalf("%+v uploading=%v", fake, h.uploading())
	}
}

// A confirmed off drops stored results at start even when no key can be
// derived: run checks the switch before it waits for the key.
func TestHookHolderRunDiscardsBeforeTheKey(t *testing.T) {
	fake := &fakeHookScan{confirmed: true}
	on := false
	h := fake.holder(&on, newHookKeyBox())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.run(ctx, &agentInventoryHolder{})
	if fake.discards != 1 || fake.calls != 0 {
		t.Fatalf("%+v", fake)
	}
}

// After a re-enrolment the cache still holds the previous workspace's opt-in
// until the new workspace's settings arrive: nothing is scanned or sent under
// the new key until then.
func TestHookHolderWaitsForTheNewEnrolmentsSettings(t *testing.T) {
	// The server answers each enrolment with its own workspace's switch: A
	// has opted in, B has not yet.
	optedIn := map[string]bool{"Bearer token-a": true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		on, mode, yes, no := optedIn[r.Header.Get("Authorization")], payloadcapture.ModeSummary, true, false
		config := endpointconfig.Config{PayloadCaptureMode: mode, WorkTypeClassification: &yes, ToolOutputCompaction: &no, CodexProxy: &yes, HookInventory: &on, HookState: &endpointconfig.UnmanagedHookState}
		identity, err := endpointconfig.ComputeIdentity(config)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("ETag", `"`+identity+`"`)
		_ = json.NewEncoder(w).Encode(endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity})
	}))
	defer server.Close()
	client, err := endpointconfig.NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	cache := endpointconfig.NewCache("")
	token := "token-a"
	refresher := endpointconfig.Refresher{Client: client, Cache: cache, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		TokenSource: func(context.Context) (string, error) { return token, nil }}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Re-enrolled into B: the cache still holds A's opt-in.
	fake := &fakeHookScan{confirmed: true}
	keys := newHookKeyBox()
	keys.set([]byte("k-b"), "token-b")
	on := true
	h := fake.holder(&on, keys)
	h.enabled = func() bool { return cache.Current().Config.HookInventoryEnabled() }
	h.authorized = func() bool { return hookAuthorized(cache.Current(), keys.enrolment()) }
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 0 || h.uploading() {
		t.Fatalf("scanned under A's opt-in: %+v uploading=%v", fake, h.uploading())
	}
	// B's own settings arrive off: still nothing.
	token = "token-b"
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 0 || h.uploading() {
		t.Fatalf("scanned with B off: %+v", fake)
	}
	// B opts in.
	optedIn["Bearer token-b"] = true
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 1 || fake.recorded != 1 || !h.uploading() {
		t.Fatalf("B's settings arrived: %+v", fake)
	}
}

func TestHookSwitchWatchWakesOnChangesOnly(t *testing.T) {
	var w hookSwitchWatch
	steps := []struct {
		on, confirmed, want bool
	}{{false, true, true}, {false, true, false}, {false, true, false}, {true, true, true}, {true, true, false}}
	for i, step := range steps {
		if got := w.config(step.on, step.confirmed); got != step.want {
			t.Fatalf("step %d: woke=%v", i, got)
		}
	}
	if !w.enrolment("a") || w.enrolment("a") || !w.enrolment("b") {
		t.Fatal("enrolment changes")
	}
}

func TestClaudeConfigDirFollowsTheEnvironment(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	if got, err := ClaudeConfigDir(); got != "" || err != nil {
		t.Fatalf("unset: %q %v", got, err)
	}
	// A relative value is refused, never read as the default profile.
	t.Setenv("CLAUDE_CONFIG_DIR", "profiles/work")
	if got, err := ClaudeConfigDir(); got != "" || !errors.Is(err, ErrClaudeConfigDir) {
		t.Fatalf("relative dir: %q %v", got, err)
	}
	// Whitespace alone is no profile; a path is read as written, as Claude
	// reads it.
	t.Setenv("CLAUDE_CONFIG_DIR", "  ")
	if got, err := ClaudeConfigDir(); got != "" || !errors.Is(err, ErrClaudeConfigDir) {
		t.Fatalf("blank dir: %q %v", got, err)
	}
	dir := t.TempDir()
	spaced := dir + string(filepath.Separator) + "work "
	t.Setenv("CLAUDE_CONFIG_DIR", spaced)
	if got, err := ClaudeConfigDir(); got != filepath.Clean(spaced) || got[len(got)-1] != ' ' || err != nil {
		t.Fatalf("trailing space: %q %v", got, err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", dir+"/")
	if got, err := ClaudeConfigDir(); got != filepath.Clean(dir) || err != nil {
		t.Fatalf("got %q %v", got, err)
	}
}

// An invalid CLAUDE_CONFIG_DIR scans nothing rather than the default profile.
func TestHookHolderSkipsAnInvalidProfile(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "profiles/work")
	fake := &fakeHookScan{confirmed: true}
	on := true
	keys := newHookKeyBox()
	keys.set([]byte("k"), "t")
	fake.holder(&on, keys).refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 0 || fake.recorded != 0 {
		t.Fatalf("%+v", fake)
	}
}

// The switch and its confirmation come from one snapshot: an unconfirmed
// off read beside a newly confirmed on must not purge.
func TestHookHolderReadsTheSwitchOnce(t *testing.T) {
	fake := &fakeHookScan{}
	on := false
	h := fake.holder(&on, newHookKeyBox())
	reads := 0
	h.switches = func() (bool, bool) {
		reads++
		return false, false
	}
	h.enabled = func() bool { t.Fatal("enabled read beside switches"); return false }
	h.confirmed = func() bool { return true }
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.discards != 0 || reads != 1 {
		t.Fatalf("discards=%d reads=%d", fake.discards, reads)
	}
}

// A purge that could not write tries again on the next tick, and only until
// it succeeds.
func TestHookHolderRetriesAFailedPurge(t *testing.T) {
	fake := &fakeHookScan{confirmed: true, discardErr: errors.New("disk full")}
	on := false
	holder := fake.holder(&on, newHookKeyBox())
	holder.refresh(context.Background(), agentinventory.Inventory{})
	holder.refresh(context.Background(), agentinventory.Inventory{})
	if fake.discards != 2 {
		t.Fatalf("discards after failures = %d, want 2", fake.discards)
	}
	fake.discardErr = nil
	holder.refresh(context.Background(), agentinventory.Inventory{})
	holder.refresh(context.Background(), agentinventory.Inventory{})
	if fake.discards != 3 {
		t.Fatalf("discards after success = %d, want 3", fake.discards)
	}
}

func TestSameCloudURL(t *testing.T) {
	if !sameCloudURL("https://api.kontext.security/", "https://api.kontext.security") || sameCloudURL("https://a.example", "https://b.example") {
		t.Fatal("sameCloudURL")
	}
}

// A server that has since refused v6 can't keep a v6 opt-in in force.
func TestHookAuthorizedNeedsAServerThatStillServesV6(t *testing.T) {
	yes := true
	snapshot := endpointconfig.Snapshot{Confirmed: true, Config: endpointconfig.Config{HookInventory: &yes}, Owner: endpointconfig.Owner("t")}
	if !hookAuthorized(snapshot, "t") {
		t.Fatal("confirmed opt-in refused")
	}
	snapshot.Status.NewestUnsupported = true
	if hookAuthorized(snapshot, "t") {
		t.Fatal("opt-in kept after a v6 refusal")
	}
}

// Capture settings confirmed by the startup cloud never authorize uploads to
// another cloud the installation was enrolled at since: nothing is sent
// until a restart confirms that cloud's own settings.
func TestUploadsWaitForRestartAfterCloudURLChange(t *testing.T) {
	dir := t.TempDir()
	writeTestManagedConfigWithCloudURL(t, filepath.Join(dir, "managed.json"), "https://new.example")
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("sent %s to the new cloud", r.URL)
		return nil, errors.New("unreachable")
	})}
	err := flushManagedStream(context.Background(), DaemonOptions{StreamHTTPClient: client}, filepath.Join(dir, "guard.db"), "https://old.example", "ins_0123456789abcdefghijklmnopqrstuv", &deviceKeySource{}, nil, nil, nil, nil)
	if !errors.Is(err, errCloudURLChanged) {
		t.Fatalf("flush = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A cloud change holds hook scans too, not only uploads.
func TestHookScansWaitForRestartAfterCloudURLChange(t *testing.T) {
	writeTestManagedConfigWithCloudURL(t, filepath.Join(t.TempDir(), "managed.json"), "https://new.example")
	if enrolledAtStartupCloud("https://old.example") {
		t.Fatal("a scan is authorized at another cloud")
	}
	if !enrolledAtStartupCloud("https://new.example/") {
		t.Fatal("the startup cloud is refused")
	}
}

// The scan carries the generation from before any check, so an opt-out and
// discard between the checks voids it.
func TestHookHolderTakesTheGenerationFirst(t *testing.T) {
	fake := &fakeHookScan{confirmed: true}
	on := true
	keys := newHookKeyBox()
	keys.set([]byte("k"), "t")
	h := fake.holder(&on, keys)
	var generation uint64
	var got uint64
	h.generation = func() uint64 { return generation }
	h.authorized = func() bool {
		// A discard lands while the checks run.
		generation++
		return true
	}
	h.record = func(_ agentauthority.HookAgent, _ agentauthority.SourceResult, _ string, g uint64) { got = g }
	h.refresh(context.Background(), agentinventory.Inventory{})
	if got != 0 || generation == 0 {
		t.Fatalf("recorded under generation %d, store at %d", got, generation)
	}
}

// A scan hands the watcher its files; while hook inventory is off or not
// authorized the watcher is emptied, so nothing is held open (ENG-1105).
func TestHookHolderWatchesOnlyWhileOn(t *testing.T) {
	fake := &fakeHookScan{confirmed: true}
	on := true
	keys := newHookKeyBox()
	keys.set([]byte("k"), "t")
	h := fake.holder(&on, keys)
	var sets [][]string
	h.watch = func(paths []string) { sets = append(sets, paths) }
	scan := h.scan
	h.scan = func(ctx context.Context, opts agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error) {
		if opts.Watch != nil {
			opts.Watch([]string{"/Users/dana/.claude/settings.json"})
		}
		return scan(ctx, opts)
	}
	h.refresh(context.Background(), agentinventory.Inventory{})
	if len(sets) != 1 || len(sets[0]) != 1 {
		t.Fatalf("on: %v", sets)
	}
	authorized := false
	h.authorized = func() bool { return authorized }
	h.refresh(context.Background(), agentinventory.Inventory{})
	if len(sets) != 2 || sets[1] != nil {
		t.Fatalf("unauthorized: %v", sets)
	}
	authorized, on = true, false
	h.refresh(context.Background(), agentinventory.Inventory{})
	if len(sets) != 3 || sets[2] != nil {
		t.Fatalf("off: %v", sets)
	}
}

// A purge that failed to write runs again on the next refresh, though the
// switch hasn't changed; a decided on, or an undecided off, never purges.
func TestAFailedOptOutPurgeRetriesOnAnUnchangedSwitch(t *testing.T) {
	calls, fail := 0, true
	p := hookOptOutPurge{discard: func() error {
		calls++
		if fail {
			return errors.New("disk full")
		}
		return nil
	}}
	p.follow(true, true, false)
	if calls != 1 {
		t.Fatalf("first opt-out: %d purges", calls)
	}
	fail = false
	p.follow(false, true, false)
	if calls != 2 {
		t.Fatalf("after a failed purge: %d purges, want a retry", calls)
	}
	p.follow(false, true, false)
	if calls != 2 {
		t.Fatalf("after a purge that worked: %d purges, want none", calls)
	}
	p.follow(true, false, false)
	p.follow(true, true, true)
	if calls != 2 {
		t.Fatalf("undecided off or decided on purged: %d purges", calls)
	}
}

// A scan still running when the Mac opts out names its files, but they are
// never watched: the holder watches only after its last check passes.
func TestHookHolderWatchesNothingAfterAnOptOutMidScan(t *testing.T) {
	fake := &fakeHookScan{confirmed: true}
	on := true
	keys := newHookKeyBox()
	keys.set([]byte("k"), "t")
	h := fake.holder(&on, keys)
	var sets [][]string
	h.watch = func(paths []string) { sets = append(sets, paths) }
	scan := h.scan
	h.scan = func(ctx context.Context, opts agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error) {
		opts.Watch([]string{"/Users/dana/.claude/settings.json"})
		// The switch goes off while the scan finishes.
		on = false
		return scan(ctx, opts)
	}
	h.refresh(context.Background(), agentinventory.Inventory{})
	for _, set := range sets {
		if set != nil {
			t.Fatalf("watched %v after the opt-out", set)
		}
	}
}
