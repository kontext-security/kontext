package managedobserve

import (
	"context"
	"errors"
	"net/http"
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
type hookKeyBox struct {
	mu    sync.Mutex
	key   []byte
	ready chan struct{}
	once  sync.Once
}

func newHookKeyBox() *hookKeyBox { return &hookKeyBox{ready: make(chan struct{})} }

func (b *hookKeyBox) set(key []byte) {
	if b == nil || len(key) == 0 {
		return
	}
	b.mu.Lock()
	b.key = key
	b.mu.Unlock()
	b.once.Do(func() { close(b.ready) })
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
	keys      *hookKeyBox
	enabled   func() bool
	available <-chan struct{}
	beginRead func() func()
	// ownBinary verifies a handler's program is this Kontext binary.
	ownBinary func(string) bool
	record    func(agentauthority.HookAgent, agentauthority.SourceResult)
	discard   func()
	scan      func(context.Context, agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error)
	home      func() (string, error)
	// wasOn remembers the switch, so the results are discarded once per
	// turn-off rather than on every tick.
	wasOn bool
}

func (h *hookHolder) refresh(ctx context.Context, inv agentinventory.Inventory) {
	if h.enabled == nil || !h.enabled() {
		if h.wasOn && h.discard != nil {
			h.discard()
		}
		h.wasOn = false
		return
	}
	h.wasOn = true
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
	// The switch may have gone off while the scan ran.
	if !h.enabled() {
		return
	}
	if h.record != nil {
		h.record(agent, result)
	}
}

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

// run scans once the key is known, then hourly and on each rescan signal.
func (h *hookHolder) run(ctx context.Context, inv *agentInventoryHolder) {
	select {
	case <-ctx.Done():
		return
	case <-h.keys.ready:
	}
	scan := func() {
		current, _ := inv.Fact()
		h.refresh(ctx, current)
	}
	scan()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
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
			if ping, err := workspacePingFn(pingCtx, http.DefaultClient, loaded.Config.CloudURL, token, state.InstallationID); err == nil {
				key, err := deviceid.HookInventoryKey(uuid, ping.OrganizationID)
				return key, HookKeyWorkspace, err
			}
		}
	}
	key, err := deviceid.HookInventoryKey(uuid, HookKeyLocal)
	return key, HookKeyLocal, err
}
