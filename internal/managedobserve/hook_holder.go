package managedobserve

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/deviceid"
	"github.com/kontext-security/kontext/internal/installation"
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
	mu      sync.Mutex
	key     []byte
	last    []byte
	ready   chan struct{}
	once    sync.Once
	changed func()
}

func newHookKeyBox() *hookKeyBox { return &hookKeyBox{ready: make(chan struct{})} }

func (b *hookKeyBox) set(key []byte) {
	if b == nil || len(key) == 0 {
		return
	}
	b.mu.Lock()
	replaced := len(b.last) > 0 && !bytes.Equal(b.last, key)
	b.key, b.last = key, key
	changed := b.changed
	b.mu.Unlock()
	if replaced && changed != nil {
		changed()
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
	b.key = nil
	b.mu.Unlock()
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
	keys    *hookKeyBox
	enabled func() bool
	// confirmed reports whether enabled reads a config the cloud confirmed.
	// Nil counts as confirmed.
	confirmed func() bool
	available <-chan struct{}
	beginRead func() func()
	// ownBinary verifies a handler's program is this Kontext binary.
	ownBinary func(string) bool
	// record stores a scan with the tag of the key it was read under.
	record  func(agentauthority.HookAgent, agentauthority.SourceResult, string)
	discard func()
	scan    func(context.Context, agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error)
	home    func() (string, error)
	// discarded remembers that results were dropped for this off period, so
	// it happens once rather than on every tick. It starts false: results a
	// previous run stored are dropped too once a confirmed config says off.
	discarded bool
}

// uploading reports whether pending hook results may be sent now: the switch
// is on and the key for the current workspace is known.
func (h *hookHolder) uploading() bool {
	return h.enabled != nil && h.enabled() && len(h.keys.get()) > 0
}

func (h *hookHolder) refresh(ctx context.Context, inv agentinventory.Inventory) {
	if h.enabled == nil || !h.enabled() {
		if !h.discarded && (h.confirmed == nil || h.confirmed()) {
			if h.discard != nil {
				h.discard()
			}
			h.discarded = true
		}
		return
	}
	h.discarded = false
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
	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	agent, result, err := scan(scanCtx, agentauthority.HookScanOptions{
		Home: home, Key: key, AgentVersion: agentVersionOf(inv, "claude_code"), OwnBinary: h.ownBinary, Now: time.Now(), BeginRead: h.beginRead,
	})
	if errors.Is(err, agentauthority.ErrNoHookKey) || err != nil || ctx.Err() != nil {
		return
	}
	// The switch may have gone off, or the workspace changed, while the
	// scan ran.
	if !h.enabled() || !bytes.Equal(h.keys.get(), key) {
		return
	}
	if h.record != nil {
		h.record(agent, result, hookKeyTag(key))
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
// and on each rescan signal. It does not wait for the key first: a confirmed
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
