package managedobserve

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext/internal/guard/hookruntime"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/tooloutput"
)

const (
	sessionStartWait = 400 * time.Millisecond
	// The original 250 ms window remains reserved for the authoritative
	// policy path. The local shadow model has a separately bounded allowance
	// (250 ms by default, 500 ms maximum) plus IPC scheduling headroom. Agent
	// hook configurations allow 20 seconds, so this prevents a shadow timeout
	// from being misclassified as an unavailable daemon and skipping the
	// policy check for an otherwise decidable call.
	preToolUseWait = time.Second
	asyncHookWait  = 120 * time.Millisecond
	probeTimeout   = 60 * time.Millisecond
)

// daemonRestartWait bounds how long a gating hook waits for the daemon's
// socket to come back. A dead or restarting daemon refuses the dial at once,
// so this only spends time while the daemon is genuinely away (brew upgrade,
// launchd reload, the plist self-heal), never on a slow one: the decision
// itself still gets its own budget from the moment the socket accepts. The
// agents give the hook 20 s, so waiting a few of them beats letting the call
// through unchecked.
var daemonRestartWait = 3 * time.Second

var launchdMu sync.Mutex

type Lifecycle struct {
	SocketPath string
	Label      string
	Kickstart  func(context.Context, string) error
	Diagnostic diagnostic.Logger
	// Mode is the managed rollout posture ("observe", "enforce", or
	// "remote"). Empty is treated as observe. In enforce the daemon's decision
	// is authoritative and passes through unchanged; in observe the hook can
	// never block. In remote the daemon's per-decision posture stamp decides:
	// decisions the daemon marked enforce (the fetched policy deployment says
	// enforce) pass through, everything else gets observe semantics. Whatever
	// the mode, a daemon that cannot decide fails open.
	Mode string
}

func NewLifecycle() Lifecycle {
	return Lifecycle{
		SocketPath: DefaultSocketPath(),
		Label:      DefaultLabel(),
		Kickstart:  KickstartLaunchd,
		Mode:       loadManagedMode(),
	}
}

// loadManagedMode reads the managed rollout posture from the installed managed
// config, defaulting to observe when the config is absent or unreadable (the
// caller only reaches here when Active() already succeeded, so this is a
// defensive fallback).
func loadManagedMode() string {
	cfg, err := managedconfig.Load()
	if err != nil {
		return managedconfig.Mode
	}
	switch cfg.Config.Mode {
	case managedconfig.ModeEnforce, managedconfig.ModeRemote:
		return cfg.Config.Mode
	default:
		return managedconfig.Mode
	}
}

func (l Lifecycle) enforcing() bool {
	return l.Mode == managedconfig.ModeEnforce
}

func (l Lifecycle) remote() bool {
	return l.Mode == managedconfig.ModeRemote
}

func Active() bool {
	_, err := managedconfig.Load()
	return err == nil
}

func (l Lifecycle) Process(ctx context.Context, event hook.Event) hook.Result {
	if l.SocketPath == "" {
		l.SocketPath = DefaultSocketPath()
	}
	if l.Label == "" {
		l.Label = DefaultLabel()
	}
	if l.Kickstart == nil {
		l.Kickstart = KickstartLaunchd
	}

	switch event.HookName {
	case hook.HookSessionStart:
		return l.processWithKickstart(ctx, event, sessionStartWait)
	case hook.HookPreToolUse, hook.HookUserPromptSubmit:
		// Both gate something the person is waiting on, so both get the
		// decision budget and a kickstart of a dead daemon.
		return l.processWithKickstart(ctx, event, preToolUseWait)
	default:
		result := l.processIfAvailable(ctx, event, asyncHookWait)
		if tooloutput.LiveCandidate(event) {
			result.UpdatedToolOutput = l.compactToolOutput(ctx, event)
		}
		return result
	}
}

// compactToolOutput asks the daemon, beside the ordinary PostToolUse above,
// for a compacted tool output within tooloutput.HookWait. A daemon that is
// away, slow or has nothing to say leaves the output unchanged.
func (l Lifecycle) compactToolOutput(ctx context.Context, event hook.Event) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, tooloutput.HookWait)
	defer cancel()
	client := localruntime.NewClient(l.SocketPath)
	client.Timeout = tooloutput.HookWait
	updated, err := client.CompactToolOutput(ctx, event)
	if err != nil {
		l.Diagnostic.Printf("managed observe compaction: %v\n", err)
		return nil
	}
	return updated
}

func (l Lifecycle) processWithKickstart(ctx context.Context, event hook.Event, budget time.Duration) hook.Result {
	restartCtx, cancel := context.WithTimeout(ctx, daemonRestartWait)
	defer cancel()

	for attempt := 0; ; attempt++ {
		if !l.reach(restartCtx) {
			return daemonUnavailable()
		}
		callCtx, cancelCall := context.WithTimeout(ctx, budget)
		result, err := l.call(callCtx, event)
		cancelCall()
		if err == nil {
			return l.finalize(event, result)
		}
		// The daemon went away between the probe and its reply, which is what
		// a restart looks like from here. One more round through reach waits
		// for the successor. A slow reply is not retried; that would double
		// the decision budget.
		if attempt == 0 && connectionLost(err) {
			continue
		}
		return daemonUnavailable()
	}
}

// reach makes sure something is listening on the socket, kickstarting launchd
// when nothing is, and waits for the listener within ctx.
func (l Lifecycle) reach(ctx context.Context) bool {
	if l.probe(ctx) {
		return true
	}
	launchdMu.Lock()
	if !l.probe(ctx) {
		if err := l.Kickstart(ctx, l.Label); err != nil {
			l.Diagnostic.Printf("managed observe kickstart: %v\n", err)
		}
	}
	launchdMu.Unlock()
	return l.waitForProbe(ctx)
}

func connectionLost(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNREFUSED)
}

func (l Lifecycle) processIfAvailable(ctx context.Context, event hook.Event, budget time.Duration) hook.Result {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if !l.probe(ctx) {
		return daemonUnavailable()
	}
	result, err := l.call(ctx, event)
	if err != nil {
		return daemonUnavailable()
	}
	return l.finalize(event, result)
}

// finalize applies the client-side posture to a daemon result. Enforce accepts
// only an explicit enforce-mode allow or deny; a stale daemon or malformed RPC
// result is not authoritative and fails open. Non-blocking hooks are always
// normalized to allow. In observe the hook can never block, so the decision
// is forced to allow with a "would" note. Remote passes through only decisions
// the daemon stamped enforce — the daemon stamps those exactly when the
// fetched policy deployment claims enforcement — and treats everything else
// as observe.
func (l Lifecycle) finalize(event hook.Event, result hook.Result) hook.Result {
	if l.enforcing() {
		if !guardhookruntime.AuthoritativeEnforce(result) {
			return daemonUnavailable()
		}
		if !event.HookName.CanBlock() {
			result.Decision = hook.DecisionAllow
		}
		return result
	}
	if l.remote() {
		return guardhookruntime.ApplyRemote(event, result)
	}
	return guardhookruntime.ObserveResult(event, result)
}

// daemonUnavailable is the result whenever the managed daemon cannot decide:
// it is unreachable, restarting, too slow, or answered with something it
// cannot stand behind. Every mode and every hook fails open. Kontext steps
// aside and the agent's own permission flow applies, so an unhealthy daemon
// never blocks the person.
func daemonUnavailable() hook.Result {
	return hook.FailOpen("managed policy daemon unavailable")
}

func (l Lifecycle) probe(ctx context.Context) bool {
	dialer := net.Dialer{Timeout: probeTimeout}
	conn, err := dialer.DialContext(ctx, "unix", l.SocketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (l Lifecycle) waitForProbe(ctx context.Context) bool {
	for {
		if l.probe(ctx) {
			return true
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

func (l Lifecycle) call(ctx context.Context, event hook.Event) (hook.Result, error) {
	client := localruntime.NewClient(l.SocketPath)
	client.Timeout = time.Until(deadlineOr(ctx, time.Now().Add(asyncHookWait)))
	if client.Timeout <= 0 {
		client.Timeout = asyncHookWait
	}
	result, err := client.Process(ctx, event)
	if err != nil {
		l.Diagnostic.Printf("managed observe call: %v\n", err)
		return hook.Result{}, err
	}
	return result, nil
}

func deadlineOr(ctx context.Context, fallback time.Time) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return fallback
}

func KickstartLaunchd(ctx context.Context, label string) error {
	return kickstartLaunchd(ctx, label, false)
}

// KickstartLaunchdKill runs launchctl kickstart with -k, which kills the
// running instance first; used to replace a daemon still running a stale binary.
func KickstartLaunchdKill(ctx context.Context, label string) error {
	return kickstartLaunchd(ctx, label, true)
}

func kickstartLaunchd(ctx context.Context, label string, kill bool) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if label == "" {
		return errors.New("launchd label is required")
	}
	args := []string{"kickstart"}
	if kill {
		args = append(args, "-k")
	}
	args = append(args, "gui/"+itoa(os.Getuid())+"/"+label)
	cmd := exec.CommandContext(ctx, "launchctl", args...)
	return cmd.Run()
}

// LaunchctlPrintMeansAbsent reports whether `launchctl print` failed because
// the service is not loaded, as opposed to failing to answer at all.
func LaunchctlPrintMeansAbsent(output string) bool {
	normalized := strings.ToLower(output)
	return strings.Contains(normalized, "could not find service") ||
		strings.Contains(normalized, "service is not loaded") ||
		strings.Contains(normalized, "no such service")
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
