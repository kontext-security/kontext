package managedobserve

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/diagnostic"
	guardhookruntime "github.com/kontext-security/kontext/internal/guard/hookruntime"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/internal/managedconfig"
)

const (
	sessionStartWait = 400 * time.Millisecond
	preToolUseWait   = 250 * time.Millisecond
	asyncHookWait    = 120 * time.Millisecond
	probeTimeout     = 60 * time.Millisecond
)

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
	// enforce) pass through, everything else gets observe semantics.
	Mode string
	// RemoteEnforce reports whether the cached policy distribution currently
	// claims enforcement. It is consulted only in remote mode when the daemon
	// is unreachable, to pick between failing open (observe posture) and
	// failing closed (enforce posture) — an unreachable daemon must not
	// downgrade an enforcing endpoint to observe.
	RemoteEnforce func() bool
}

func NewLifecycle() Lifecycle {
	return Lifecycle{
		SocketPath:    DefaultSocketPath(),
		Label:         DefaultLabel(),
		Kickstart:     KickstartLaunchd,
		Mode:          loadManagedMode(),
		RemoteEnforce: remoteEnforceFromCache,
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

// remoteEnforceFromCache reads the daemon's on-disk policy cache directly —
// the daemon is unreachable when this is consulted. A missing or unreadable
// cache reports no enforcement claim: with no trustworthy record of the
// organization's intent, a self-serve endpoint fails open rather than
// hard-blocking the agent.
//
// The cache location derives from DefaultDBPath(), the same env-overridable
// default (KONTEXT_MANAGED_OBSERVE_DB) the daemon derives its cache path
// from, mirroring how SocketPath resolution already keeps the two processes
// aligned. The programmatic DaemonOptions path overrides are test seams; a
// deployment that relocates the daemon state must export the env var to hook
// processes too, or outage fallback will not see the enforcement claim.
func remoteEnforceFromCache() bool {
	return cedarpolicy.PersistedDeploymentClaimsEnforce(
		cedarpolicy.DefaultCachePathForDB(DefaultDBPath()),
	)
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
	case hook.HookPreToolUse:
		return l.processWithKickstart(ctx, event, preToolUseWait)
	default:
		return l.processIfAvailable(ctx, event, asyncHookWait)
	}
}

func (l Lifecycle) processWithKickstart(ctx context.Context, event hook.Event, budget time.Duration) hook.Result {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	if !l.probe(ctx) {
		launchdMu.Lock()
		if !l.probe(ctx) {
			if err := l.Kickstart(ctx, l.Label); err != nil {
				l.Diagnostic.Printf("managed observe kickstart: %v\n", err)
			}
		}
		launchdMu.Unlock()
	}
	if l.waitForProbe(ctx) {
		result, err := l.call(ctx, event)
		if err != nil {
			return l.daemonUnavailable(event)
		}
		return l.finalize(event, result)
	}
	return l.daemonUnavailable(event)
}

func (l Lifecycle) processIfAvailable(ctx context.Context, event hook.Event, budget time.Duration) hook.Result {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if !l.probe(ctx) {
		return l.daemonUnavailable(event)
	}
	result, err := l.call(ctx, event)
	if err != nil {
		return l.daemonUnavailable(event)
	}
	return l.finalize(event, result)
}

// finalize applies the client-side posture to a daemon result. Enforce accepts
// only an explicit enforce-mode allow or deny; a stale daemon or malformed RPC
// result is not authoritative. Non-blocking hooks are always normalized to
// allow. In observe the hook can never block, so the decision is forced to
// allow with a "would" note. Remote passes through only decisions the daemon
// stamped enforce — the daemon stamps those exactly when the fetched policy
// deployment claims enforcement — and treats everything else as observe.
func (l Lifecycle) finalize(event hook.Event, result hook.Result) hook.Result {
	if l.enforcing() {
		if !guardhookruntime.AuthoritativeEnforce(result) {
			return l.daemonUnavailable(event)
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

// daemonUnavailable is the fail path when the managed daemon cannot be reached.
// Observe fails open (it never blocks). Enforce fails closed for blocking
// hooks: enforcement requires an authoritative decision and an unreachable
// daemon cannot provide one. Non-blocking lifecycle hooks remain informational.
// Remote fails closed only while the cached policy distribution claims
// enforcement; otherwise it fails open like observe, so a fresh self-serve
// install without an enforcing deployment never hard-blocks the agent.
func (l Lifecycle) daemonUnavailable(event hook.Event) hook.Result {
	if l.remote() && l.RemoteEnforce != nil && l.RemoteEnforce() {
		decision := hook.DecisionAllow
		if event.HookName.CanBlock() {
			decision = hook.DecisionDeny
		}
		return hook.Result{
			Decision: decision,
			Mode:     managedconfig.ModeEnforce,
			Reason:   "Kontext enforce: managed policy daemon unavailable",
		}
	}
	if l.enforcing() {
		decision := hook.DecisionAllow
		if event.HookName.CanBlock() {
			decision = hook.DecisionDeny
		}
		return hook.Result{
			Decision: decision,
			Mode:     managedconfig.ModeEnforce,
			Reason:   "Kontext enforce: managed policy daemon unavailable",
		}
	}
	return guardhookruntime.ObserveResult(event, hook.Result{Decision: hook.DecisionAllow, Reason: "managed observe daemon unavailable"})
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
