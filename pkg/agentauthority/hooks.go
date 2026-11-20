package agentauthority

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/privacyfolder"
	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// Hook inventory (ADR-0011): one record per hook entry an agent loads, with
// health per scope, sent as device.hook_inventory beside the <agent>/hooks
// inventory source. The cloud side is kontext-cloud
// packages/shared/src/features/enterprise-dashboard/hook-inventory.ts, and
// both pin testdata/hook-inventory-v1.json.
const (
	HookInventorySchema = "hook-inventory-v1"
	HookIDScheme        = 1
	// Per agent. Past them the agent is truncated and its source partial.
	MaxHookRecords = 512
	MaxHookScopes  = 128
	// Projects Claude Code lists in ~/.claude.json, as the authority scan.
	maxHookProjects = 32
)

// Scope kinds.
const (
	HookScopeManaged       = "managed"
	HookScopeManagedDropIn = "managed_dropin"
	HookScopeUser          = "user"
	HookScopeProject       = "project"
	HookScopeProjectLocal  = "project_local"
	HookScopePlugin        = "plugin"
)

// Origins.
const (
	HookOriginKontext  = "kontext"
	HookOriginPlugin   = "plugin"
	HookOriginSettings = "settings"
	HookOriginUnknown  = "unknown"
)

// Evidence levels.
const (
	HookEvidenceDiscovered          = "discovered"
	HookEvidenceConfigChecked       = "config_checked"
	HookEvidenceInvocationObserved  = "invocation_observed"
	HookEvidencePolicyEvaluated     = "policy_evaluated"
	HookEvidenceEnforcementVerified = "enforcement_verified"
)

// ErrNoHookKey means the per-Mac key could not be derived. The endpoint then
// sends no hook inventory rather than weaker ids.
var ErrNoHookKey = errors.New("hook inventory needs the per-Mac key")

type HookInventory struct {
	Schema   string      `json:"schema"`
	IDScheme int         `json:"id_scheme"`
	Agents   []HookAgent `json:"agents"`
}

type HookAgent struct {
	ID           string         `json:"id"`
	AgentVersion *string        `json:"agent_version"`
	Truncated    bool           `json:"truncated"`
	KontextHooks KontextHookSet `json:"kontext_hooks"`
	Scopes       []HookScope    `json:"scopes"`
	Hooks        []HookRecord   `json:"hooks"`
}

// KontextHookSet says whether Kontext's own handlers cover every event it
// installs: complete, needs_update (some missing, ENG-694) or missing.
type KontextHookSet struct {
	State         string   `json:"state"`
	MissingEvents []string `json:"missing_events"`
}

type HookScope struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Status    string   `json:"status"`
	Reasons   []string `json:"reasons"`
	CheckedAt string   `json:"checked_at"`
}

type HookRecord struct {
	ID            string         `json:"id"`
	ScopeID       string         `json:"scope_id"`
	PreviousID    string         `json:"previous_id,omitempty"`
	Event         string         `json:"event"`
	Matcher       *string        `json:"matcher"`
	Type          string         `json:"type"`
	Summary       *string        `json:"summary"`
	TimeoutS      *int           `json:"timeout_s"`
	Plugin        *HookPlugin    `json:"plugin"`
	Origin        string         `json:"origin"`
	ClaimsKontext bool           `json:"claims_kontext"`
	ContentFP     string         `json:"content_fp"`
	Match         string         `json:"match"`
	Enablement    HookEnablement `json:"enablement"`
	Evidence      HookEvidence   `json:"evidence"`
}

type HookPlugin struct {
	Name        string  `json:"name"`
	Marketplace *string `json:"marketplace"`
	Version     *string `json:"version"`
}

type HookEnablement struct {
	State   string   `json:"state"`
	Reasons []string `json:"reasons"`
}

type HookEvidence struct {
	Level             string            `json:"level"`
	DiscoveredAt      string            `json:"discovered_at"`
	ConfigCheckedAt   *string           `json:"config_checked_at"`
	InvocationAt      *string           `json:"invocation_at"`
	PolicyEvaluatedAt *string           `json:"policy_evaluated_at"`
	PolicyDecision    *string           `json:"policy_decision"`
	VerifiedAt        *string           `json:"verified_at"`
	Verification      *HookVerification `json:"verification"`
}

type HookVerification struct {
	AgentVersion   *string `json:"agent_version"`
	ContentFP      string  `json:"content_fp"`
	PolicyRevision *string `json:"policy_revision"`
}

// HookScanOptions are the inputs of one Claude Code hook scan.
type HookScanOptions struct {
	Home string
	// ConfigDir is Claude Code's user folder, CLAUDE_CONFIG_DIR; empty means
	// ~/.claude. With it set, Claude Code keeps .claude.json there too.
	ConfigDir string
	// Key is the per-Mac secret from deviceid.HookInventoryKey.
	Key          []byte
	AgentVersion string
	// OwnBinary reports whether path is the installed Kontext binary, the
	// same file and not only the same name. Nil verifies nothing.
	OwnBinary func(path string) bool
	Now       time.Time
	// BeginRead applies the daemon's disk policy to each read.
	BeginRead func() func()
	managed   string
	// mdmPolicy reports a Claude Code policy from an MDM profile; nil checks
	// this Mac's managed preferences.
	mdmPolicy func() bool
}

// HookSourceID is the inventory source the scan's result reports under.
func HookSourceID(agent string) string { return agent + "/hooks" }

// ScanHooks reads Claude Code's hook sources: machine-wide managed settings
// and drop-ins, the user's settings, the two settings files of each project
// Claude Code lists, and each installed plugin's hooks. It reads only those
// fixed files, under the same guard as the authority scan.
func ScanHooks(ctx context.Context, opts HookScanOptions) (HookAgent, SourceResult, error) {
	if opts.managed == "" {
		opts.managed = managedRoot
	}
	return scanHooks(ctx, opts)
}

var hookEventName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

type hookScan struct {
	g      *guard
	opts   HookScanOptions
	source *SourceHealth
	agent  HookAgent
	// buckets count identical entries for the ordinal; see hookID.
	buckets map[string]int
	// settings in Claude's precedence order, for enablement.
	layers   []hookLayer
	plugins  pluginSwitches
	unlisted bool
	// raw holds what enablement needs per record, beside agent.Hooks.
	raw []hookRaw
	// trust is each listed project's trust dialog answer, by folder.
	trust map[string]*bool
	// signedIn is the claude.ai organization ~/.claude.json names, if any.
	signedIn bool
	project  string
	// shadowed: an MDM profile supplies Claude Code's managed tier, so the
	// managed-settings files on disk are not the policy in force.
	shadowed bool
}

type hookRaw struct {
	url     string
	program string
	// matcher is the group's matcher as written; conditional is a
	// handler-level `if`. Coverage reads these, never the redacted copy.
	matcher     string
	conditional bool
	// async: the agent doesn't wait for the handler, so it can't block.
	async bool
	kind  string
	// layer indexes layers; -1 for a plugin.
	layer          int
	project        string
	pluginDisabled bool
}

// hookLayer is one settings file that took part in the scan.
type hookLayer struct {
	kind     string
	scope    string
	settings readers.HookSettings
	ok       bool
	project  string
}

func scanHooks(ctx context.Context, opts HookScanOptions) (HookAgent, SourceResult, error) {
	agentID := "claude_code"
	if len(opts.Key) == 0 {
		return HookAgent{}, SourceResult{}, ErrNoHookKey
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	home := filepath.Clean(opts.Home)
	base := opts.ConfigDir
	if base == "" {
		base = filepath.Join(home, ".claude")
	}
	report := &Report{Coverage: Coverage{UnknownFormat: []string{}, Errors: []string{}}}
	rootConfig := filepath.Join(home, ".claude.json")
	if opts.ConfigDir != "" {
		rootConfig = filepath.Join(base, ".claude.json")
	}
	g := &guard{ctx: ctx, home: home, managed: opts.managed, roots: []string{opts.managed, base, rootConfig}, report: report, beginRead: opts.BeginRead, seen: map[string]bool{}}
	s := &hookScan{g: g, opts: opts, source: NewSourceHealth(HookSourceID(agentID), opts.Now), buckets: map[string]int{}, plugins: pluginSwitches{managed: map[string]bool{}, user: map[string]bool{}, project: map[string]map[string]bool{}}, trust: map[string]*bool{}}
	s.agent = HookAgent{ID: agentID, Scopes: []HookScope{}, Hooks: []HookRecord{}}
	if opts.mdmPolicy == nil {
		opts.mdmPolicy = claudeMDMPolicy
	}
	s.shadowed = opts.mdmPolicy()
	if version := safe(opts.AgentVersion, 64); version != "" {
		s.agent.AgentVersion = &version
	}

	// Machine-wide first, in Claude's merge order, then the user, projects
	// and plugins. Later layers never outrank managed settings.
	s.settingsScope(HookScopeManaged, filepath.Join(opts.managed, "managed-settings.json"), false)
	dropins := filepath.Join(opts.managed, "managed-settings.d")
	s.only()
	before := len(s.source.reasons)
	entries := g.entries(dropins)
	s.unlisted = len(s.source.reasons) > before
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		s.settingsScope(HookScopeManagedDropIn, filepath.Join(dropins, name), true)
	}
	s.settingsScope(HookScopeUser, filepath.Join(base, "settings.json"), false)

	s.only()
	root, _ := readConfig(g, agentID, rootConfig, readers.Claude)
	s.signedIn = root.OAuthAccount.OrganizationUUID != ""
	projects := keys(root.Projects)
	if len(projects) > maxHookProjects {
		s.source.Fail(ReasonWalkLimit)
		s.agent.Truncated = true
		projects = projects[:maxHookProjects]
	}
	listed := map[string]bool{}
	for _, project := range projects {
		dir := filepath.Clean(project)
		// Two spellings of one directory (a trailing slash) are one project,
		// and one scope.
		if !filepath.IsAbs(dir) || listed[dir] {
			continue
		}
		listed[dir] = true
		// Only these two files, never a walk: the one place a path found in
		// configuration is read (ADR-0011).
		shared, local := filepath.Join(dir, ".claude", "settings.json"), filepath.Join(dir, ".claude", "settings.local.json")
		g.roots = append(g.roots, shared, local)
		s.trust[dir] = root.Projects[project].HasTrustDialogAccepted
		s.project = dir
		s.settingsScope(HookScopeProject, shared, false)
		s.settingsScope(HookScopeProjectLocal, local, false)
	}
	s.project = ""
	s.pluginScopes(base)
	s.finish()
	s.only()
	result := s.source.Result(time.Now())
	if s.agent.Truncated && result.Status == StatusComplete {
		result.Status = StatusPartial
		result.Reasons = []string{ReasonSizeLimit}
	}
	return s.agent, result, nil
}

// only makes the following reads count for the source alone.
func (s *hookScan) only() { s.g.active = []*SourceHealth{s.source} }

// scope opens a scope and makes the following reads count for it too. It
// returns nil past the scope cap.
func (s *hookScan) scope(kind, canonical string) (*SourceHealth, string) {
	if len(s.agent.Scopes) >= MaxHookScopes {
		s.agent.Truncated = true
		s.source.Fail(ReasonSizeLimit)
		return nil, ""
	}
	h := NewSourceHealth(kind, s.opts.Now)
	s.g.active = []*SourceHealth{s.source, h}
	return h, scopeID(s.opts.Key, kind, canonical)
}

func (s *hookScan) closeScope(h *SourceHealth, id, kind string) {
	result := h.Result(s.opts.Now)
	s.agent.Scopes = append(s.agent.Scopes, HookScope{ID: id, Kind: kind, Status: result.Status, Reasons: append([]string{}, result.Reasons...), CheckedAt: result.FinishedAt})
	s.only()
}

func (s *hookScan) settingsScope(kind, path string, listed bool) {
	h, id := s.scope(kind, filepath.Clean(path))
	if h == nil {
		return
	}
	var settings readers.HookSettings
	var ok bool
	if listed {
		settings, ok = readListed(s.g, s.agent.ID, path, readers.Hooks)
	} else {
		settings, ok = readConfig(s.g, s.agent.ID, path, readers.Hooks)
	}
	s.layers = append(s.layers, hookLayer{kind: kind, scope: id, settings: settings, ok: ok, project: s.project})
	if ok {
		for key, value := range settings.EnabledPlugins {
			switch {
			case managedKind(kind):
				s.plugins.managed[key] = value
			case projectKind(kind):
				// Read shared before local, so local wins.
				if s.plugins.project[s.project] == nil {
					s.plugins.project[s.project] = map[string]bool{}
				}
				s.plugins.project[s.project][key] = value
			default:
				s.plugins.user[key] = value
			}
		}
		s.records(id, kind, settings.Hooks, nil, len(s.layers)-1)
	}
	s.closeScope(h, id, kind)
}

// pluginScopes reads each installed plugin's hooks. Claude Code loads the
// default hooks/hooks.json and, beside it, whatever the manifest's hooks
// field adds: a file, an inline object, or a list of either.
func (s *hookScan) pluginScopes(base string) {
	type pluginIndex struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
			Version     string `json:"version"`
			ProjectPath string `json:"projectPath"`
		} `json:"plugins"`
	}
	type pluginManifest struct {
		Name    string          `json:"name"`
		Version string          `json:"version"`
		Hooks   json.RawMessage `json:"hooks"`
		// DefaultEnabled false leaves the plugin off until a setting turns
		// it on.
		DefaultEnabled *bool `json:"defaultEnabled"`
	}
	s.only()
	index, ok := readConfig(s.g, s.agent.ID, filepath.Join(base, "plugins/installed_plugins.json"), parseJSON[pluginIndex])
	if !ok {
		return
	}
	cache := filepath.Join(base, "plugins/cache")
	seen := map[string]bool{}
	for _, key := range keys(index.Plugins) {
		for _, entry := range index.Plugins[key] {
			installed := filepath.Clean(entry.InstallPath)
			if !within(cache, installed) {
				s.source.Fail(ReasonPermissionDenied)
				continue
			}
			// Keyed by name and marketplace, so an update to a new cache
			// folder keeps the scope; an install for one project is its own
			// scope. The same install listed twice is read once, so no two
			// scopes share an id.
			canonical := "plugin|" + key
			if entry.ProjectPath != "" {
				canonical += "|" + filepath.Clean(entry.ProjectPath)
			}
			if seen[canonical] {
				continue
			}
			seen[canonical] = true
			h, id := s.scope(HookScopePlugin, canonical)
			if h == nil {
				return
			}
			manifest, _ := readConfig(s.g, s.agent.ID, filepath.Join(installed, ".claude-plugin/plugin.json"), parseJSON[pluginManifest])
			name, market, _ := strings.Cut(key, "@")
			if manifest.Name != "" {
				name = manifest.Name
			}
			version := manifest.Version
			if version == "" {
				version = entry.Version
			}
			plugin := &HookPlugin{Name: safe(name, 128), Marketplace: pointer(safe(market, 128)), Version: pointer(safe(version, 64))}
			if plugin.Name == "" {
				plugin.Name = "<redacted>"
			}
			enabled, set := s.plugins.lookup(key, filepath.Clean(entry.ProjectPath))
			hooks := s.pluginHooks(h, installed, manifest.Hooks)
			disabled := set && !enabled || !set && manifest.DefaultEnabled != nil && !*manifest.DefaultEnabled
			// A project install runs under that project's settings.
			if entry.ProjectPath != "" {
				s.project = filepath.Clean(entry.ProjectPath)
			}
			s.records(id, HookScopePlugin, hooks, &pluginRef{plugin: plugin, key: key, disabled: disabled}, -1)
			s.project = ""
			s.closeScope(h, id, HookScopePlugin)
		}
	}
}

// pluginHooks gathers a plugin's hooks from hooks/hooks.json and the
// manifest's hooks field, in that order.
func (s *hookScan) pluginHooks(h *SourceHealth, installed string, declared json.RawMessage) map[string][]readers.HookGroup {
	hooks := map[string][]readers.HookGroup{}
	add := func(more map[string][]readers.HookGroup) {
		for _, event := range keys(more) {
			hooks[event] = append(hooks[event], more[event]...)
		}
	}
	malformed := func() {
		h.Fail(ReasonMalformed)
		s.source.Fail(ReasonMalformed)
	}
	defaultFile := filepath.Join(installed, "hooks", "hooks.json")
	read := map[string]bool{}
	file := func(path string, declared bool) {
		path = filepath.Clean(path)
		if read[path] {
			return
		}
		read[path] = true
		if !within(installed, path) {
			h.Fail(ReasonPermissionDenied)
			s.source.Fail(ReasonPermissionDenied)
			return
		}
		s.g.roots = append(s.g.roots, path)
		if parsed, ok := readConfig(s.g, s.agent.ID, path, readers.Hooks); ok {
			add(parsed.Hooks)
		} else if declared {
			// The manifest names it, so its absence is no empty file: hooks
			// it holds may exist, and nothing of the scope is withdrawn.
			h.Fail(ReasonReadError)
			s.source.Fail(ReasonReadError)
		}
	}
	inline := func(raw json.RawMessage) {
		if parsed, err := readers.Hooks([]byte(`{"hooks":` + string(raw) + `}`)); err == nil {
			add(parsed.Hooks)
		} else {
			malformed()
		}
	}
	file(defaultFile, false)
	var entry func(raw json.RawMessage, nested bool)
	entry = func(raw json.RawMessage, nested bool) {
		switch trimmed := strings.TrimSpace(string(raw)); {
		case trimmed == "" || trimmed == "null":
		case strings.HasPrefix(trimmed, "{"):
			inline(raw)
		case strings.HasPrefix(trimmed, `"`):
			var rel string
			if json.Unmarshal(raw, &rel) != nil {
				malformed()
				return
			}
			file(filepath.Join(installed, rel), true)
		case strings.HasPrefix(trimmed, "[") && !nested:
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) != nil {
				malformed()
				return
			}
			for _, item := range list {
				entry(item, true)
			}
		default:
			malformed()
		}
	}
	entry(declared, false)
	return hooks
}

// pluginSwitches holds enabledPlugins by layer. Claude Code's precedence:
// managed settings, then the plugin's own project (local over shared), then
// the user's settings.
type pluginSwitches struct {
	managed, user map[string]bool
	project       map[string]map[string]bool
}

func (p pluginSwitches) lookup(key, project string) (enabled, set bool) {
	if v, ok := p.managed[key]; ok {
		return v, true
	}
	if project != "." && project != "" {
		if v, ok := p.project[project][key]; ok {
			return v, true
		}
	}
	v, ok := p.user[key]
	return v, ok
}

type pluginRef struct {
	plugin   *HookPlugin
	key      string
	disabled bool
}

// records adds one record per handler, in declaration order within each event.
func (s *hookScan) records(scope, kind string, hooks map[string][]readers.HookGroup, plugin *pluginRef, layer int) {
	for _, event := range keys(hooks) {
		// An event is a name in the agent's vocabulary; one that reads as a
		// secret is a generator's mistake and never reported.
		if !hookEventName.MatchString(event) || secret(event, "args") {
			s.g.fail(ReasonUnsupportedFormat)
			continue
		}
		for _, group := range hooks[event] {
			matcher := ""
			if group.Matcher != nil {
				matcher = *group.Matcher
			}
			for _, raw := range group.Hooks {
				if len(s.agent.Hooks) >= MaxHookRecords {
					s.agent.Truncated = true
					s.g.fail(ReasonSizeLimit)
					return
				}
				record, info := s.record(scope, kind, event, matcher, raw, plugin)
				info.layer, info.project, info.kind = layer, s.project, kind
				info.pluginDisabled = plugin != nil && plugin.disabled
				s.agent.Hooks = append(s.agent.Hooks, record)
				s.raw = append(s.raw, info)
			}
		}
	}
}

var knownHookTypes = []string{"command", "http", "mcp_tool", "prompt", "agent"}

func (s *hookScan) record(scope, kind, event, matcher string, raw json.RawMessage, plugin *pluginRef) (HookRecord, hookRaw) {
	h := readers.Handler(raw)
	info := hookRaw{url: h.URL}
	kind_ := h.Type
	if !slices.Contains(knownHookTypes, kind_) {
		kind_ = "unknown"
	}
	info.matcher, info.conditional, info.async = matcher, strings.TrimSpace(h.If) != "", h.Async
	r := HookRecord{ScopeID: scope, Event: event, Type: kind_, Origin: HookOriginSettings, Enablement: HookEnablement{State: "unresolved", Reasons: []string{"unresolved"}}}
	if m := safeMatcher(matcher); m != "" {
		r.Matcher = &m
	}
	if h.Timeout != nil && *h.Timeout >= 0 && *h.Timeout <= 86400 {
		seconds := int(*h.Timeout)
		r.TimeoutS = &seconds
	}
	anchor := kind_
	if kind_ == "unknown" {
		anchor = "unknown:" + safe(h.Type, 64)
	}
	switch kind_ {
	case "command":
		// Exec form whenever args is present, even empty: Claude Code then runs
		// command as the executable's name, never splits it.
		fields, ok := agenthooks.SplitCommand(h.Command)
		if h.Args != nil {
			fields, ok = append([]string{h.Command}, h.Args...), h.Command != ""
		}
		if h.Args == nil {
			// `NAME=value cmd` sets a variable for cmd: the value can be a
			// secret and is never the program.
			fields = withoutAssignments(fields)
		}
		if ok && len(fields) > 0 {
			program := fields[0]
			info.program = program
			anchor = "cmd:" + filepath.Base(program)
			r.Summary = pointer(hookSummary(program, fields[1:]))
			alias, known := claudemanaged.AliasForEvent(hook.HookName(event))
			// Ownership needs one literal command: a newline or an operator
			// makes the shell run something else than the words it splits to.
			literal, single := fields, ok
			if h.Args == nil {
				literal, single = agenthooks.SplitLiteralCommand(h.Command)
			}
			call := known && single && len(literal) == 3 && agenthooks.IsKontextBinary(literal[0]) && literal[1] == "hook" && literal[2] == alias
			if call {
				// Its arguments are Kontext's own, so they read in full.
				r.Summary = pointer(hookSummary(program, nil) + " hook " + alias)
			}
			r.ClaimsKontext = call || agenthooks.IsKontextBinary(program)
			// Verified by metadata only, and never inside a privacy-guarded
			// folder: the check must not prompt the user.
			// The path must be canonical: the guard reads it cleaned, while
			// a symlink followed by ".." resolves elsewhere for the OS.
			if call && s.opts.OwnBinary != nil && filepath.IsAbs(program) && program == filepath.Clean(program) && !privacyfolder.Guarded(s.opts.Home, program) && s.opts.OwnBinary(program) {
				r.Origin = HookOriginKontext
			}
		} else {
			anchor = "cmd:"
		}
	case "http":
		if u, err := url.Parse(h.URL); err == nil && u.Scheme != "" && u.Hostname() != "" {
			anchor = "http:" + strings.ToLower(u.Hostname())
			r.Summary = pointer(safe(u.Scheme+"://"+u.Host, 256))
		}
	case "mcp_tool":
		name := safe(h.Server, 128) + "/" + safe(h.Tool, 128)
		anchor = "mcp:" + name
		r.Summary = pointer(safe(name, 256))
	}
	if plugin != nil {
		r.Plugin = plugin.plugin
		if r.Origin != HookOriginKontext {
			r.Origin = HookOriginPlugin
		}
	}
	pluginKey := ""
	if plugin != nil {
		pluginKey = plugin.key
	}
	bucket := strings.Join([]string{s.agent.ID, scope, pluginKey, event, matcher, kind_, anchor}, "\x00")
	ordinal := s.buckets[bucket]
	s.buckets[bucket] = ordinal + 1
	r.ID = hookID(s.opts.Key, bucket, ordinal)
	r.ContentFP = contentFP(s.opts.Key, event, matcher, raw)
	r.Match = bucket // resolved in finish, once every entry is counted
	r.Evidence = HookEvidence{Level: HookEvidenceDiscovered, DiscoveredAt: s.opts.Now.UTC().Format(time.RFC3339Nano)}
	return r, info
}

// finish resolves what needs every entry: whether an id is unique by anchor,
// enablement, and Kontext's own set.
func (s *hookScan) finish() {
	for i := range s.agent.Hooks {
		r := &s.agent.Hooks[i]
		if s.buckets[r.Match] > 1 {
			r.Match = "positional"
		} else {
			r.Match = "anchor"
		}
	}
	evaluateEnablement(s)
	s.agent.KontextHooks = kontextHookSet(s.agent.Hooks, s.raw, s.projectDisablesHooks())
}

// projectDisablesHooks reports whether a listed project's own settings turn
// off its non-managed hooks: user-scope handlers then don't run there.
func (s *hookScan) projectDisablesHooks() bool {
	for _, layer := range s.layers {
		if projectKind(layer.kind) && layer.ok && layer.settings.DisableAllHooksSet && layer.settings.DisableAllHooks != nil && *layer.settings.DisableAllHooks {
			return true
		}
	}
	return false
}

// kontextHookSet compares Kontext's verified, enabled handlers with the
// events it installs. Only a handler that runs for every call of its event,
// everywhere on the Mac, covers it: one in managed or user settings, with no
// narrowing matcher and no handler-level `if`. A project's hooks run in that
// project alone, so they never cover the device.
func kontextHookSet(records []HookRecord, raw []hookRaw, projectDisables bool) KontextHookSet {
	covered := map[string]bool{}
	for i, r := range records {
		if i >= len(raw) || r.Origin != HookOriginKontext || r.Enablement.State != hookEnabled {
			continue
		}
		info := raw[i]
		// A user handler is device-wide only while no project turns user
		// hooks off; disableAllHooks there leaves managed ones running.
		deviceWide := info.kind == HookScopeManaged || info.kind == HookScopeManagedDropIn || info.kind == HookScopeUser && !projectDisables
		matcher := strings.TrimSpace(info.matcher)
		if deviceWide && !info.conditional && !info.async && (matcher == "" || matcher == "*") {
			covered[r.Event] = true
		}
	}
	set := KontextHookSet{State: "complete", MissingEvents: []string{}}
	for _, event := range claudemanaged.SupportedEvents {
		if !covered[event.Name.String()] {
			set.MissingEvents = append(set.MissingEvents, event.Name.String())
		}
	}
	switch {
	case len(set.MissingEvents) == len(claudemanaged.SupportedEvents):
		set.State = "missing"
	case len(set.MissingEvents) > 0:
		set.State = "needs_update"
	}
	return set
}

// withoutAssignments drops the leading NAME=value words of a shell command.
func withoutAssignments(fields []string) []string {
	for len(fields) > 0 && isAssignment(fields[0]) {
		fields = fields[1:]
	}
	return fields
}

func isAssignment(word string) bool {
	name, _, found := strings.Cut(word, "=")
	if !found || name == "" {
		return false
	}
	for i, c := range name {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// SameFileAs is the OwnBinary check against one installed binary.
func SameFileAs(installed string) func(string) bool {
	return func(path string) bool {
		a, errA := os.Stat(path)
		b, errB := os.Stat(installed)
		return errA == nil && errB == nil && os.SameFile(a, b)
	}
}
