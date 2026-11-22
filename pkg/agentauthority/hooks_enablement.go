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
// behaviour it follows; hooks_enablement_test.go pins each one to the Claude
// Code version it was checked against. A setting whose effect isn't
// established here leaves the hook unresolved instead of guessing.
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
	// httpAllow holds allowedHttpHookUrls compiled once per project, not
	// once per hook.
	httpAllow  *[]*regexp.Regexp
	unreadable bool
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
		if layer.settings.SwitchInvalid && !(managedKind(layer.kind) && s.shadowed) {
			sw.unreadable = true
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
			// Managed files combine their lists: a later drop-in adds
			// surfaces and URLs, it never lifts an earlier restriction. A
			// Boolean is a scalar, and a later one replaces it.
			if raw := layer.settings.StrictPluginOnlyCustomization; len(raw) > 0 {
				var all bool
				if json.Unmarshal(raw, &all) == nil {
					sw.pluginOnly, sw.pluginOnlyUnclear = all, false
				} else {
					covers, unclear := pluginOnlyCoversHooks(raw)
					sw.pluginOnly = sw.pluginOnly || covers
					sw.pluginOnlyUnclear = sw.pluginOnlyUnclear || unclear
				}
			}
			s.allowHTTP(&sw, layer)
		case layer.kind == HookScopeUser:
			merge(&sw.otherDisableAll, layer)
			s.allowHTTP(&sw, layer)
		case projectKind(layer.kind) && layer.project == project && project != "":
			merge(&sw.otherDisableAll, layer)
			s.allowHTTP(&sw, layer)
		}
	}
	return sw
}

// allowHTTP adds a layer's allowedHttpHookUrls to the allowlist. Claude Code
// reads the key in any settings file and runs an HTTP hook only if its URL
// matches the list merged from every level that defines it (hooks reference,
// "Hook locations"): a later file adds URLs, it never removes one.
func (s *hookScan) allowHTTP(sw *switches, layer hookLayer) {
	allow := layer.settings.AllowedHTTPHookURLs
	if allow == nil {
		return
	}
	merged := []*regexp.Regexp{}
	if sw.httpAllow != nil {
		merged = append(merged, *sw.httpAllow...)
	}
	for _, pattern := range *allow {
		merged = append(merged, s.urlPattern(pattern))
	}
	sw.httpAllow = &merged
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

// trusted reports whether Claude trusts dir: its own acceptance, or one a
// parent folder recorded, which Claude applies to the folders below it.
func (s *hookScan) trusted(dir string) bool {
	for dir != "" {
		if trusted := s.trust[dir]; trusted != nil && *trusted {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

// evaluateEnablement sets each record's state and reasons.
func evaluateEnablement(s *hookScan) {
	cache := map[string]switches{}
	// With a managed setting unread, a later managed file can lift a switch
	// that turned a hook off, so only a missing program still settles it.
	managedSettled := s.managedReadable()
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
		if info.projectUnread {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		if info.manifestUnread {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		if r.Type == "http" && sw.httpAllow != nil && !urlAllowed(info.url, *sw.httpAllow) {
			disabled = append(disabled, HookReasonHTTPURLNotAllowed)
		}
		if projectKind(kind) {
			if !s.trusted(info.project) {
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
		if s.mdmMerged || s.policyHelper {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		if s.unlisted {
			unresolved = append(unresolved, HookReasonDropInUnlistable)
		}
		// A managed file past the scope cap was not read, and its switches
		// could turn off any hook.
		if s.managedCut {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		if sw.unreadable {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		if r.Type == "unknown" {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		// Claude evaluates `if` against a tool call, so on an event without
		// one the handler may never run: not shown as expected to run.
		if info.conditional && !toolEvent(r.Event) {
			unresolved = append(unresolved, HookReasonUnresolved)
		}
		reasons := slices.Concat(disabled, unresolved, conditional)
		if s.signedIn {
			// Server-managed settings for a claude.ai organization can't be
			// read here, so they are named without changing the state.
			reasons = append(reasons, HookReasonRemoteManagedUnverified)
		}
		// A user or project switch can be lifted by a file that went unread
		// (`disableAllHooks` or `enabledPlugins` in a local file); a managed
		// one can't, and a missing binary is missing whatever the files say.
		// An allowlist can't settle it either: any unread file may add the
		// URL to it.
		byManaged := sw.managedDisableAll || slices.ContainsFunc(disabled, func(reason string) bool {
			return reason == HookReasonManagedOnly || reason == HookReasonPluginOnly
		})
		settledOff := slices.Contains(disabled, HookReasonBinaryMissing) ||
			managedSettled && !info.projectUnread && (!sw.unreadable || byManaged)
		state := hookEnabled
		switch {
		case len(disabled) > 0 && settledOff:
			state = hookDisabled
		case len(disabled) > 0 || len(unresolved) > 0:
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

// urlPattern follows allowedHttpHookUrls: each entry is a URL pattern where
// * matches any run of characters. A pattern is compiled once per scan, not
// once per project.
func (s *hookScan) urlPattern(pattern string) *regexp.Regexp {
	if compiled, ok := s.urlPatterns[pattern]; ok {
		return compiled
	}
	compiled := regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$")
	if s.urlPatterns == nil {
		s.urlPatterns = map[string]*regexp.Regexp{}
	}
	s.urlPatterns[pattern] = compiled
	return compiled
}

func urlAllowed(raw string, patterns []*regexp.Regexp) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(raw) {
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
		info, err := os.Stat(program)
		if err != nil {
			return os.IsNotExist(err)
		}
		// A program that can't be launched is as good as missing: a
		// folder, or a file the user can't execute.
		return info.IsDir() || !launchable(home, info)
	})
}

// settledWithin runs a metadata check that may touch a stalled filesystem
// within programStatTimeout. A check that doesn't finish in time, or once the
// scan is cancelled, answers false: unverified, never assumed.
func settledWithin(ctx context.Context, check func() bool) bool {
	return settled(ctx, false, check)
}

// settled is fn's answer if it comes within programStatTimeout and before
// ctx ends, else fallback. A late answer is dropped.
func settled[T any](ctx context.Context, fallback T, fn func() T) T {
	// A cancelled scan starts no more checks: one blocked on a stalled
	// mount would stay blocked after the scan returns.
	if ctx.Err() != nil {
		return fallback
	}
	done := make(chan T, 1)
	go func() { done <- fn() }()
	timer := time.NewTimer(programStatTimeout)
	defer timer.Stop()
	select {
	case value := <-done:
		return value
	case <-timer.C:
	case <-ctx.Done():
	}
	return fallback
}

// toolEvent is an event about one tool call, where a handler's `if` rule is
// evaluated.
func toolEvent(event string) bool {
	return strings.Contains(event, "ToolUse") || event == "PermissionRequest" || event == "PermissionDenied"
}
