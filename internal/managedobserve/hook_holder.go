package managedobserve

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/deviceid"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/installation"
	"github.com/kontext-security/kontext/internal/managedstream"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// hookKeyBox hands K_dev (ADR-0011) from the stream goroutine, which derives
// it beside the device key, to the hook scan. The key never leaves the Mac.
//
// K_dev is per workspace, so a hook id read under one workspace's key must
// never reach another. The box is emptied while a new config identity is
// being resolved, and a key that differs from the last one calls changed,
// which drops the results read under the old key.
type hookKeyBox struct {
	mu  sync.Mutex
	key []byte
	// token is the install token K_dev was derived under: the enrolment
	// the key belongs to.
	token   string
	last    []byte
	ready   chan struct{}
	once    sync.Once
	changed func()
	// wake runs when the key's enrolment changes, so the scan follows it.
	wake func()
}

func newHookKeyBox() *hookKeyBox { return &hookKeyBox{ready: make(chan struct{})} }

func (b *hookKeyBox) set(key []byte, token string) {
	if b == nil || len(key) == 0 {
		return
	}
	b.mu.Lock()
	replaced := len(b.last) > 0 && !bytes.Equal(b.last, key)
	moved := b.token != token
	b.key, b.last, b.token = key, key, token
	changed, wake := b.changed, b.wake
	b.mu.Unlock()
	if replaced && changed != nil {
		changed()
	}
	if moved && wake != nil {
		wake()
	}
	b.once.Do(func() { close(b.ready) })
}

// clear withholds the key until the next set: no scan runs and nothing is
// uploaded until the current identity's key is known.
func (b *hookKeyBox) clear() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.key, b.token = nil, ""
	b.mu.Unlock()
}

// enrolment is the install token the current key was derived under; empty
// while no key is known.
func (b *hookKeyBox) enrolment() string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.token
}

// hookAuthorized reports, from one snapshot, that the switch is on and that
// the enrolment K_dev belongs to confirmed it. After a re-enrolment the cache
// can still hold the previous workspace's opt-in until the new one's
// settings arrive.
func hookAuthorized(snapshot endpointconfig.Snapshot, enrolment string) bool {
	owner := endpointconfig.Owner(enrolment)
	return snapshot.HookInventoryEnabled() && owner != "" && snapshot.Owner == owner
}

func (b *hookKeyBox) get() []byte {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.key
}

// hookHolder scans Claude Code's hooks while the deployment's endpoint config
// turns hook inventory on, at the authority scan's times, and records each
// scan for upload.
type hookHolder struct {
	// actions holds the hook reconciler's report for the stream.
	actions *hookReconciler
	keys    *hookKeyBox
	enabled func() bool
	// confirmed reports whether enabled reads a config the cloud confirmed.
	// Nil counts as confirmed.
	confirmed func() bool
	// authorized reports whether the switch is on in a config the current
	// enrolment, the one K_dev was derived under, confirmed, read from one
	// snapshot. Nil counts as authorized.
	authorized func() bool
	available  <-chan struct{}
	beginRead  func() func()
	// ownBinary verifies a handler's program is this Kontext binary.
	ownBinary func(string) bool
	// evidence adds runtime evidence to Kontext's own hooks in each scan.
	evidence *hookRuntime
	// record stores a scan with the tag of the key it was read under.
	// The last argument is what generation said before the scan began.
	record func(agentauthority.HookAgent, agentauthority.SourceResult, string, uint64)
	// generation names the store's hook state, so a discard while a scan
	// runs voids the scan.
	generation func() uint64
	// switches reads the switch and its confirmation from one snapshot; it
	// replaces enabled and confirmed when set.
	switches func() (on, confirmed bool)
	// discard drops pending results; on an error the next tick tries again.
	discard func() error
	scan    func(context.Context, agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error)
	home    func() (string, error)
	// watch receives the paths each scan read, so a change to one wakes
	// the next scan within seconds (ENG-1105); nil watches nothing. It
	// gets nil while no scan may run, which releases what it holds.
	watch func([]string)
	// discarded remembers that results were dropped for this off period, so
	// it happens once rather than on every tick. It starts false: results a
	// previous run stored are dropped too once a confirmed config says off.
	discarded bool
}

// uploading reports whether pending hook results may be sent now: the switch
// is on and the key for the current workspace is known.
func (h *hookHolder) uploading() bool {
	on, _ := h.switchState()
	return on && h.isAuthorized() && len(h.keys.get()) > 0
}

func (h *hookHolder) isAuthorized() bool { return h.authorized == nil || h.authorized() }

// switchState reads the switch and whether a confirmed config says it, from
// one snapshot where the daemon supplies one: two reads could pair an
// unconfirmed off with a newly confirmed on and purge pending results.
func (h *hookHolder) switchState() (on, confirmed bool) {
	if h.switches != nil {
		return h.switches()
	}
	on = h.enabled != nil && h.enabled()
	confirmed = h.confirmed == nil || h.confirmed()
	return on, confirmed
}

func (h *hookHolder) refresh(ctx context.Context, inv agentinventory.Inventory) {
	// Taken before any check: a discard after this point, an opt-out
	// between the checks included, voids the scan.
	var generation uint64
	if h.generation != nil {
		generation = h.generation()
	}
	if on, confirmed := h.switchState(); !on {
		h.unwatch()
		if !h.discarded && confirmed {
			h.discarded = h.discard == nil || h.discard() == nil
		}
		return
	}
	h.discarded = false
	if !h.isAuthorized() {
		h.unwatch()
		return
	}
	key := h.keys.get()
	if len(key) == 0 {
		return
	}
	homeOf := h.home
	if homeOf == nil {
		homeOf = os.UserHomeDir
	}
	home, err := homeOf()
	if err != nil {
		return
	}
	scan := h.scan
	if scan == nil {
		scan = agentauthority.ScanHooks
	}
	configDir, err := ClaudeConfigDir()
	if err != nil {
		// Reading another profile would report hooks Claude Code doesn't load.
		return
	}
	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// The scan names its files as it ends; they are watched only once the
	// checks below pass, so a Mac that opted out mid-scan watches nothing.
	var toWatch []string
	named := false
	agent, result, err := scan(scanCtx, agentauthority.HookScanOptions{
		Home: home, ConfigDir: configDir, Key: key, AgentVersion: agentVersionOf(inv, "claude_code"), OwnBinary: h.ownBinary, Now: time.Now(), BeginRead: h.beginRead,
		Watch: func(paths []string) { toWatch, named = paths, true },
	})
	if errors.Is(err, agentauthority.ErrNoHookKey) || err != nil || ctx.Err() != nil {
		return
	}
	// The switch may have gone off, or the workspace changed, while the
	// scan ran.
	if on, _ := h.switchState(); !on || !h.isAuthorized() || !bytes.Equal(h.keys.get(), key) {
		h.unwatch()
		return
	}
	if named && h.watch != nil {
		h.watch(toWatch)
	}
	h.evidence.apply(&agent)
	if h.record != nil {
		h.record(agent, result, hookKeyTag(key), generation)
	}
}

// unwatch stops watching while hook inventory is off or not authorized, so
// an opted-out Mac holds nothing open for it.
func (h *hookHolder) unwatch() {
	if h.watch != nil {
		h.watch(nil)
	}
}

// hookKeyTag names a K_dev without revealing it, so a stored hook result can
// say which workspace's key made its ids. Empty for no key.
func hookKeyTag(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("kontext/hook-inventory/key-tag/v1"))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// currentKeyTag is the tag pending hook results must carry to be sent.
func (h *hookHolder) currentKeyTag() string { return hookKeyTag(h.keys.get()) }

// ownBinaryCheck verifies a hook's program against the running binary, the
// same file and not only the same name.
func ownBinaryCheck() func(string) bool {
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	return agentauthority.SameFileAs(self)
}

func agentVersionOf(inv agentinventory.Inventory, id string) string {
	for _, agent := range inv.Agents {
		if agent.ID == id && agent.Version != nil {
			return *agent.Version
		}
	}
	return ""
}

// run checks the switch at once, scans once the key is known, then hourly
// and on each rescan signal, which includes a change to a file the last scan
// read. The hourly scan stays the fallback for a missed notification. It does not wait for the key first: a confirmed
// off must drop stored results even while no key can be derived.
func (h *hookHolder) run(ctx context.Context, inv *agentInventoryHolder) {
	scan := func() {
		current, _ := inv.Fact()
		h.refresh(ctx, current)
	}
	scan()
	ready := h.keys.ready
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ready:
			ready = nil
			scan()
		case <-h.available:
			scan()
		case <-ticker.C:
			scan()
		}
	}
}

// Hook key scopes, as `kontext hooks inventory` names them.
const (
	HookKeyWorkspace = "workspace"
	HookKeyLocal     = "local"
)

// LocalHookKey derives K_dev for a scan run outside the daemon. Enrolled, it is
// the daemon's key, so ids match what the dashboard shows; otherwise it is
// keyed to this Mac alone and says so.
func LocalHookKey(ctx context.Context) ([]byte, string, error) {
	uuid, err := platformUUIDFn(ctx)
	if err != nil {
		return nil, "", err
	}
	if loaded, token, err := loadManagedConfig(ctx); err == nil {
		state, stateErr := installation.LoadFile(installationPathForScope(loaded.Scope))
		pingCtx, cancel := context.WithTimeout(ctx, deviceKeyPingTimeout)
		defer cancel()
		if stateErr == nil {
			if ping, err := workspacePingFn(pingCtx, nil, loaded.Config.CloudURL, token, state.InstallationID); err == nil {
				key, err := deviceid.HookInventoryKey(uuid, ping.OrganizationID)
				return key, HookKeyWorkspace, err
			}
		}
	}
	key, err := deviceid.HookInventoryKey(uuid, HookKeyLocal)
	return key, HookKeyLocal, err
}

// hookSwitchWatch tells the hook scan to wake when its switch, the config's
// confirmation or the enrolment changes, not on every refresh: an unchanged
// configuration (a 304) also reaches OnChanged, every minute.
type hookSwitchWatch struct {
	seen, on, confirmed bool
	token               string
}

func (w *hookSwitchWatch) config(on, confirmed bool) bool {
	changed := !w.seen || w.on != on || w.confirmed != confirmed
	w.seen, w.on, w.confirmed = true, on, confirmed
	return changed
}

// hookOptOutPurge drops pending hook results once a config decides the
// switch is off, and tries again on each later refresh until a purge
// succeeds: an unchanged switch otherwise never retries one that failed to
// write, and a later opt-in could upload results from before the opt-out.
type hookOptOutPurge struct {
	discard func() error
	failed  bool
}

// purge runs for a decided off; it reports whether it ran.
func (p *hookOptOutPurge) purge(decided, enabled bool) bool {
	if !decided || enabled {
		p.failed = false
		return false
	}
	p.failed = p.discard() != nil
	return true
}

// follow purges when the switch changed, or when the last purge failed.
func (p *hookOptOutPurge) follow(changed, decided, enabled bool) {
	if changed || p.failed {
		p.purge(decided, enabled)
	}
}

func (w *hookSwitchWatch) enrolment(token string) bool {
	changed := w.token != token
	w.token = token
	return changed
}

// ErrClaudeConfigDir is a CLAUDE_CONFIG_DIR that names no absolute folder.
// Claude Code's own resolver refuses it rather than fall back to another
// profile, and so does the scan.
var ErrClaudeConfigDir = errors.New("CLAUDE_CONFIG_DIR is not an absolute path")

// ClaudeConfigDir is CLAUDE_CONFIG_DIR, the profile Claude Code runs with;
// empty means the default ~/.claude. A value that is set but not absolute is
// an error, never the default profile.
func ClaudeConfigDir() (string, error) {
	// Read as written: a trimmed path can name a neighbouring profile, and
	// a whitespace-only value is no profile at all, not ~/.claude.
	dir := os.Getenv("CLAUDE_CONFIG_DIR")
	if dir == "" {
		return "", nil
	}
	if strings.TrimSpace(dir) == "" || !filepath.IsAbs(dir) {
		return "", ErrClaudeConfigDir
	}
	return filepath.Clean(dir), nil
}

// describeHookChange is one line for the daemon log: the kind and the opaque
// ids, never a command or a path.
func describeHookChange(change agentauthority.HookChange) string {
	// Event is a known name or "other"; ids and reasons are opaque codes.
	line := change.Kind + " scope=" + change.ScopeID
	if change.HookID != "" {
		line += " hook=" + change.HookID + " event=" + change.Event
	}
	if len(change.Reasons) > 0 {
		line += " reasons=" + strings.Join(change.Reasons, ",")
	}
	return line
}

// hookActions is the reconciler's pending report for a post that goes with
// installToken.
func (h *hookHolder) hookActions(installToken string) (*managedstream.HookActions, func()) {
	if h == nil {
		return nil, nil
	}
	return h.actions.take(endpointconfig.Owner(installToken))
}
