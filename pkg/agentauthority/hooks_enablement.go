package agentauthority

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// Enablement reason codes (ADR-0011). Each rule below names the Claude Code
// behaviour it follows; hooks_test.go tests each one by example. The
// per-rule matrix pinned to a Claude Code version comes with ENG-1092. A
// setting whose effect isn't established here leaves the hook unresolved
// instead of guessing.
const (
	HookReasonDisableAllHooks         = "disable_all_hooks"
	HookReasonManagedOnly             = "managed_only"
	HookReasonRemoteManagedUnverified = "remote_managed_unverified"
	HookReasonManagedTierShadowed     = "managed_tier_shadowed"
	HookReasonDropInUnlistable        = "dropin_unlistable"
	HookReasonPluginDisabled          = "plugin_disabled"
	HookReasonPluginOnly              = "plugin_only_customization"
	HookReasonHTTPURLNotAllowed       = "http_url_not_allowed"
	HookReasonAwaitingTrust           = "awaiting_trust"
	HookReasonBinaryMissing           = "binary_missing"
	HookReasonUnresolved              = "unresolved"
)

const (
	hookEnabled     = "enabled"
	hookDisabled    = "disabled"
	hookConditional = "conditional"
	hookUnresolved  = "unresolved"
)

func managedKind(kind string) bool {
	return kind == HookScopeManaged || kind == HookScopeManagedDropIn
}

func projectKind(kind string) bool {
	return kind == HookScopeProject || kind == HookScopeProjectLocal
}

// switches is what the layers a hook sees say, merged in Claude's order:
// managed settings, then drop-ins by name, for machine-wide values; user,
// then project, then local project for the rest, a later value replacing an
// earlier one.
type switches struct {
	managedDisableAll bool
	otherDisableAll   bool
	managedOnly       bool
	pluginOnly        bool
	pluginOnlyUnclear bool
	httpAllow         *[]string
	unreadable        bool
}

func (s *hookScan) switchesFor(project string) switches {
	var sw switches
	merge := func(target *bool, layer hookLayer) {
		if layer.settings.DisableAllHooksSet {
			*target = layer.settings.DisableAllHooks != nil && *layer.settings.DisableAllHooks
		}
	}
	for _, layer := range s.layers {
		if projectKind(layer.kind) && layer.project != project {
			// Another project's settings never apply here, read or not.
			continue
		}
		if !layer.ok {
			// A failed read can hide a switch, but an absent file has none.
			if s.scopeStatus(layer.scope) != StatusComplete {
				sw.unreadable = true
			}
			continue
		}
		switch {
		case managedKind(layer.kind) && s.shadowed:
			// An MDM profile replaced these files: their switches aren't in
			// force.
		case managedKind(layer.kind):
			merge(&sw.managedDisableAll, layer)
			if v := layer.settings.AllowManagedHooksOnly; v != nil {
				sw.managedOnly = *v
			}
			if raw := layer.settings.StrictPluginOnlyCustomization; len(raw) > 0 {
				sw.pluginOnly, sw.pluginOnlyUnclear = pluginOnlyCoversHooks(raw)
			}
			if layer.settings.AllowedHTTPHookURLs != nil {
				sw.httpAllow = layer.settings.AllowedHTTPHookURLs
			}
		case layer.kind == HookScopeUser:
			merge(&sw.otherDisableAll, layer)
		case projectKind(layer.kind) && layer.project == project && project != "":
			merge(&sw.otherDisableAll, layer)
		}
	}
	return sw
}

// pluginOnlyCoversHooks reads strictPluginOnlyCustomization: true locks every
// surface, a list locks the surfaces it names.
func pluginOnlyCoversHooks(raw json.RawMessage) (covers, unclear bool) {
	var all bool
	if json.Unmarshal(raw, &all) == nil {
		return all, false
	}
	var surfaces []string
	if json.Unmarshal(raw, &surfaces) == nil {
		return slices.Contains(surfaces, "hooks"), false
	}
	return false, true
}

func (s *hookScan) scopeStatus(id string) string {
	for _, scope := range s.agent.Scopes {
		if scope.ID == id {
			return scope.Status
		}
	}
	return StatusComplete
}

// evaluateEnablement sets each record's state and reasons.
func evaluateEnablement(s *hookScan) {
	cache := map[string]switches{}
	for i := range s.agent.Hooks {
		r, info := &s.agent.Hooks[i], s.raw[i]
		kind := HookScopePlugin
		if info.layer >= 0 {
			kind = s.layers[info.layer].kind
		}
		sw, ok := cache[info.project]
		if !ok {
			sw = s.switchesFor(info.project)
			cache[info.project] = sw
		}
		var disabled, unresolved, conditional []string
		// disableAllHooks in managed settings turns off every hook; elsewhere
		// it turns off all but managed ones (Claude Code hooks reference,
		// "Disable or remove hooks").
		if sw.managedDisableAll || sw.otherDisableAll && !managedKind(kind) {
			disabled = append(disabled, HookReasonDisableAllHooks)
		}
		// allowManagedHooksOnly keeps managed hooks and drops user and project
		// ones. Plugin hooks under it changed between versions, so they stay
		// unresolved rather than guessed.
		if sw.managedOnly {
			switch {
			case kind == HookScopePlugin:
				unresolved = append(unresolved, HookReasonManagedOnly)
			case !managedKind(kind):
				disabled = append(disabled, HookReasonManagedOnly)
			}
		}
		if sw.pluginOnly && !managedKind(kind) && kind != HookScopePlugin {
			disabled = append(disabled, HookReasonPluginOnly)
		}
		if sw.pluginOnlyUnclear && !managedKind(kind) {
			unresolved = append(unresolved, HookReasonPluginOnly)
		}
		if info.pluginDisabled {
			disabled = append(disabled, HookReasonPluginDisabled)
		}
		if r.Type == "http" && sw.httpAllow != nil && !urlAllowed(info.url, *sw.httpAllow) {
			disabled = append(disabled, HookReasonHTTPURLNotAllowed)
		}
		if projectKind(kind) {
			if trusted := s.trust[info.project]; trusted == nil || !*trusted {
				conditional = append(conditional, HookReasonAwaitingTrust)
			}
		}
		if r.Type == "command" && programMissing(s.g.ctx, s.opts.Home, info.program) {
			disabled = append(disabled, HookReasonBinaryMissing)
		}
		// Claude Code uses one managed source: an MDM profile replaces the
		// files, whose hooks then may not run. The profile itself can't be
		// read here, and its switches could turn off any hook, so every hook
		// stays unresolved rather than enabled.
		if s.shadowed {
			unresolved = append(unresolved, HookReasonManagedTierShadowed)
		}
		if s.mdmMerged {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		if s.unlisted {
			unresolved = append(unresolved, HookReasonDropInUnlistable)
		}
		if sw.unreadable {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		if r.Type == "unknown" {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		reasons := slices.Concat(disabled, unresolved, conditional)
		if s.signedIn {
			// Server-managed settings for a claude.ai organization can't be
			// read here, so they are named without changing the state.
			reasons = append(reasons, HookReasonRemoteManagedUnverified)
		}
		state := hookEnabled
		switch {
		case len(disabled) > 0:
			state = hookDisabled
		case len(unresolved) > 0:
			state = hookUnresolved
		case len(conditional) > 0:
			state = hookConditional
		}
		slices.Sort(reasons)
		// Never null on the wire: the cloud's schema wants a list.
		r.Enablement = HookEnablement{State: state, Reasons: append([]string{}, slices.Compact(reasons)...)}
		if state != hookUnresolved {
			r.Evidence.Level = HookEvidenceConfigChecked
			checked := r.Evidence.DiscoveredAt
			r.Evidence.ConfigCheckedAt = &checked
		}
	}
}

// urlAllowed follows allowedHttpHookUrls: each entry is a URL pattern where *
// matches any run of characters.
func urlAllowed(raw string, patterns []string) bool {
	for _, pattern := range patterns {
		expr := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
		if matched, _ := regexp.MatchString(expr, raw); matched {
			return true
		}
	}
	return false
}

// programStatTimeout bounds one binary check: a stalled network path must
// not hold the scan past its deadline.
const programStatTimeout = 250 * time.Millisecond

// programMissing checks a command's program only where that is safe: a
// canonical absolute path outside privacy-guarded folders, by metadata
// alone, within a short deadline. A symlink followed by ".." resolves
// elsewhere for the OS than the cleaned path the guard checks, so another
// spelling is never checked. Anything it can't settle in time is not missing.
func programMissing(ctx context.Context, home, program string) bool {
	if !filepath.IsAbs(program) || program != filepath.Clean(program) {
		return false
	}
	return settledWithin(ctx, func() bool {
		if privacyfolder.Guarded(home, program) {
			return false
		}
		_, err := os.Stat(program)
		return os.IsNotExist(err)
	})
}

// settledWithin runs a metadata check that may touch a stalled filesystem
// within programStatTimeout. A check that doesn't finish in time, or once the
// scan is cancelled, answers false: unverified, never assumed.
func settledWithin(ctx context.Context, check func() bool) bool {
	done := make(chan bool, 1)
	go func() { done <- check() }()
	timer := time.NewTimer(programStatTimeout)
	defer timer.Stop()
	select {
	case ok := <-done:
		return ok
	case <-timer.C:
	case <-ctx.Done():
	}
	return false
}
