package agentauthority

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
	// HookReasonWhileActive is in hooks_frontmatter.go.
	HookReasonUnresolved = "unresolved"
)

// HookEnablementReasons is every reason code above, in the cloud
// contract's order (HOOK_ENABLEMENT_REASONS in kontext-cloud).
var HookEnablementReasons = []string{
	HookReasonDisableAllHooks, HookReasonManagedOnly, HookReasonRemoteManagedUnverified,
	HookReasonManagedTierShadowed, HookReasonDropInUnlistable, HookReasonPluginDisabled,
	HookReasonPluginOnly, HookReasonHTTPURLNotAllowed, HookReasonAwaitingTrust,
	HookReasonBinaryMissing, HookReasonWhileActive, HookReasonUnresolved,
}

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
	// httpAllow holds the allowedHttpHookUrls patterns merged from every
	// level that defines the key; nil when none does. httpAllowManaged says
	// a managed file defines it.
	httpAllow        *[]string
	httpAllowManaged bool
	unreadable       bool
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
// "Hook locations"): a later file adds URLs, it never removes one. Patterns
// are compiled only when an HTTP hook is checked against them.
func (s *hookScan) allowHTTP(sw *switches, layer hookLayer) {
	allow := layer.settings.AllowedHTTPHookURLs
	if allow == nil {
		return
	}
	merged := []string{}
	if sw.httpAllow != nil {
		merged = append(merged, *sw.httpAllow...)
	}
	merged = append(merged, *allow...)
	sw.httpAllow = &merged
	if managedKind(layer.kind) {
		sw.httpAllowManaged = true
	}
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
	switchesOf := func(project string) switches {
		sw, ok := cache[project]
		if !ok {
			sw = s.switchesFor(project)
			cache[project] = sw
		}
		return sw
	}
	// With a managed setting unread, a later managed file can lift a switch
	// that turned a hook off, so only a missing program still settles it.
	managedSettled := s.managedReadable()
	for i := range s.agent.Hooks {
		r, info := &s.agent.Hooks[i], s.raw[i]
		// A skill or subagent follows the rules of the folder that holds it.
		kind := info.rules
		sw := switchesOf(info.project)
		var disabled, unresolved, conditional []string
		// disableAllHooks in managed settings turns off every hook; elsewhere
		// it turns off all but managed ones (Claude Code hooks reference,
		// "Disable or remove hooks").
		if sw.managedDisableAll || sw.otherDisableAll && !managedKind(kind) {
			disabled = append(disabled, HookReasonDisableAllHooks)
		}
		// allowManagedHooksOnly keeps managed hooks and drops user, project,
		// local and plugin ones, except the hooks of a plugin managed
		// enabledPlugins force-enables (hooks reference, Claude Code 2.1.229
		// and later). Under an MDM profile the managed switches went unread.
		if sw.managedOnly && !managedKind(kind) {
			switch {
			case kind != HookScopePlugin:
				disabled = append(disabled, HookReasonManagedOnly)
			case s.plugins.managed[info.pluginKey]:
				// Force-enabled: exempt from 2.1.229 on, blocked before.
				switch managedOnlyExempt(s.opts.AgentVersion) {
				case versionBefore:
					disabled = append(disabled, HookReasonManagedOnly)
				case versionUnknown:
					unresolved = append(unresolved, HookReasonManagedOnly)
				}
			case s.plugins.managedUnknown:
				// A managed enabledPlugins that went unread may
				// force-enable it.
				unresolved = append(unresolved, HookReasonManagedOnly)
			default:
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
		if r.Type == "http" {
			switch s.httpVerdict(info, kind, sw, switchesOf) {
			case httpBlocked:
				disabled = append(disabled, HookReasonHTTPURLNotAllowed)
			case httpUnsettled:
				unresolved = append(unresolved, HookReasonHTTPURLNotAllowed)
			case httpSomeProjects:
				conditional = append(conditional, HookReasonHTTPURLNotAllowed)
			}
		}
		if projectKind(kind) {
			if !s.trusted(info.project) {
				conditional = append(conditional, HookReasonAwaitingTrust)
			}
		}
		// A skill's or subagent's hooks run only while it is active.
		if frontmatterKind(info.kind) {
			conditional = append(conditional, HookReasonWhileActive)
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

const (
	httpAllowed = iota
	httpBlocked
	// httpUnsettled: blocked by a list that may not apply, or one past the
	// scan's pattern budget.
	httpUnsettled
	// httpSomeProjects: blocked where the hook is declared, allowed in a
	// listed project that adds its URL.
	httpSomeProjects
)

// httpVerdict checks an HTTP hook's URL against the allowlist in force where
// it runs. A hook outside any project runs in every project too, under that
// project's own list and switches, so it is judged in each listed project as
// well: allowed somewhere and blocked elsewhere is "some projects". Where
// that can't be known (a project's settings or the project list unread), a
// block is unsettled.
func (s *hookScan) httpVerdict(info hookRaw, kind string, sw switches, switchesOf func(string) switches) int {
	base, known := httpAllowed, true
	if sw.httpAllow != nil {
		var allowed bool
		allowed, known = s.urlAllowed(info.url, *sw.httpAllow, nil)
		switch {
		case !known:
			return httpUnsettled
		case !allowed && managedKind(kind) && !sw.httpAllowManaged:
			// Only user or project files define the list. Whether Claude
			// Code applies those to a managed hook isn't settled here.
			return httpUnsettled
		case !allowed:
			base = httpBlocked
		}
	}
	if info.project != "" || projectKind(kind) {
		return base
	}
	unsettled := false
	for _, project := range keys(s.trust) {
		psw := switchesOf(project)
		// A hook the project turns off runs there under no list.
		if psw.managedDisableAll || psw.otherDisableAll && !managedKind(kind) {
			continue
		}
		if psw.unreadable {
			unsettled = true
			continue
		}
		// The project's list holds the base list plus its own, so a URL
		// the base list allowed is allowed there too, and only the
		// project's own patterns are left to try.
		allowed := true
		switch {
		case psw.httpAllow == nil:
		case base == httpAllowed && sw.httpAllow != nil:
		default:
			var ok bool
			if allowed, ok = s.urlAllowed(info.url, *psw.httpAllow, sw.httpAllow); !ok {
				unsettled = true
				continue
			}
		}
		if allowed != (base == httpAllowed) {
			return httpSomeProjects
		}
	}
	if base == httpBlocked && (unsettled || s.projectsUnread || s.projectsCut) {
		return httpUnsettled
	}
	return base
}

// maxURLPatterns bounds the allowlist patterns one scan compiles, and
// maxURLMatches the matches it tries. Past either, a URL the patterns tried
// don't allow is unsettled.
const (
	maxURLPatterns = 512
	maxURLMatches  = 1 << 16
)

// urlPattern follows allowedHttpHookUrls: each entry is a URL pattern where
// * matches any run of characters. The scheme and host match in any case
// and without a trailing dot, as Claude Code normalizes them; user
// information and the path keep their case. A pattern is compiled once per
// scan, and nil past the budget.
func (s *hookScan) urlPattern(pattern string) *regexp.Regexp {
	if compiled, ok := s.urlPatterns[pattern]; ok {
		return compiled
	}
	if len(s.urlPatterns) >= maxURLPatterns {
		return nil
	}
	scheme, user, host, rest := splitURL(pattern)
	quote := func(text string) string { return strings.ReplaceAll(regexp.QuoteMeta(text), `\*`, ".*") }
	// Every part is quoted, so the expression always compiles.
	compiled := regexp.MustCompile("^(?i:" + quote(scheme) + ")" + quote(user) + "(?i:" + quote(host) + ")" + quote(rest) + "$")
	if s.urlPatterns == nil {
		s.urlPatterns = map[string]*regexp.Regexp{}
	}
	s.urlPatterns[pattern] = compiled
	return compiled
}

// urlAllowed reports whether a pattern allows the URL; known is false when a
// budget left a pattern untried and none of the others allows it. Patterns
// in skip were already tried, and a pattern repeated in the list is tried
// once.
func (s *hookScan) urlAllowed(raw string, patterns []string, skip *[]string) (allowed, known bool) {
	scheme, user, host, rest := splitURL(raw)
	candidate := scheme + user + host + rest
	tried := map[string]bool{}
	if skip != nil {
		for _, pattern := range *skip {
			tried[pattern] = true
		}
	}
	known = true
	for _, pattern := range patterns {
		if tried[pattern] {
			continue
		}
		tried[pattern] = true
		compiled := s.urlPattern(pattern)
		if compiled == nil || s.urlMatches >= maxURLMatches || s.g.ctx.Err() != nil {
			known = false
			continue
		}
		s.urlMatches++
		if compiled.MatchString(candidate) {
			return true, true
		}
	}
	return false, known
}

// splitURL cuts a URL, or a pattern, into its scheme with "://", its user
// information with "@", its host and port without a trailing host dot, and
// the rest. One without a scheme is all rest.
func splitURL(raw string) (scheme, user, host, rest string) {
	name, after, ok := strings.Cut(raw, "://")
	if !ok {
		return "", "", "", raw
	}
	authority := after
	if i := strings.IndexAny(after, "/?#"); i >= 0 {
		authority, rest = after[:i], after[i:]
	}
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		user, authority = authority[:i+1], authority[i+1:]
	}
	hostname, port, hasPort := strings.Cut(authority, ":")
	if strings.HasSuffix(hostname, ".") && hostname != "." {
		hostname = strings.TrimSuffix(hostname, ".")
	}
	host = hostname
	if hasPort {
		host += ":" + port
	}
	return name + "://", user, host, rest
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

// Version checks for rules Claude Code changed in a release.
const (
	versionAtOrAfter = iota
	versionBefore
	versionUnknown
)

// managedOnlyExempt says whether the agent version exempts a force-enabled
// plugin's hooks from allowManagedHooksOnly: Claude Code 2.1.229 and later.
func managedOnlyExempt(version string) int { return versionSince(version, []int{2, 1, 229}) }

// versionSince compares a dotted version, like "2.1.329" or "2.1.329 (Claude
// Code)", with since. A version it can't read is unknown.
func versionSince(version string, since []int) int {
	version, _, _ = strings.Cut(strings.TrimSpace(version), " ")
	version, _, _ = strings.Cut(version, "-")
	parts := strings.Split(version, ".")
	if version == "" || len(parts) < len(since) {
		return versionUnknown
	}
	for i, want := range since {
		got, err := strconv.Atoi(parts[i])
		if err != nil || got < 0 {
			return versionUnknown
		}
		if got != want {
			if got < want {
				return versionBefore
			}
			return versionAtOrAfter
		}
	}
	return versionAtOrAfter
}
