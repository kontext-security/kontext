package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The GitHub MCP catalog (internal/toolcatalog/github-mcp.json) follows the
// same rules as the provider catalogs: every upstream tool is catalogued with
// a product and an access tier, a new tool lands as write (delete when its
// annotations say destructive, admin for repository settings), annotations
// only ever tighten a tier, and a changed definition is flagged for review.
// GitHub resolves calls by input schema, so each tool also carries its pinned
// required fields and property types, and the catalog is re-pinned to
// upstream HEAD whenever a tool changes.

const (
	githubMCPRepository = "https://github.com/github/github-mcp-server"
	githubMCPSourceName = "github/github-mcp-server"
	githubToolsnaps     = "pkg/github/__toolsnaps__"
)

type githubCatalog struct {
	Source string       `json:"source"`
	Tools  []githubTool `json:"tools"`
}

type githubTool struct {
	Name    string `json:"name"`
	Product string `json:"product"`
	Access  string `json:"access"`
	Named   bool   `json:"named,omitempty"`
	// Removed marks a tool GitHub no longer serves. It stays catalogued for
	// older servers; recording the removal is what puts it up for review.
	Removed    bool              `json:"removed,omitempty"`
	Required   []string          `json:"required"`
	Properties map[string]string `json:"properties"`
	Definition string            `json:"definition,omitempty"`
}

// githubSnapshot is one upstream tool as its __toolsnaps__ describe it.
type githubSnapshot struct {
	required   []string
	properties map[string]string
	hint       string
	definition string
}

var (
	githubPinPattern = regexp.MustCompile(`GitHubMCPSourceCommit\s*=\s*"([0-9a-f]{40})"`)
	githubAdminTool  = regexp.MustCompile(`ruleset|custom_properties_write|delete_repository|collaborator_write|webhook|deploy_key|secret_write|branch_protection|repository_settings`)
	githubProducts   = []struct {
		pattern *regexp.Regexp
		product string
	}{
		{regexp.MustCompile(`^actions_|job_logs|workflow`), "actions"},
		{regexp.MustCompile(`release|_tag$|_tags$`), "releases"},
		{regexp.MustCompile(`code_scanning|dependabot|secret_scanning|security_advisor|code_quality`), "security"},
		{regexp.MustCompile(`discussion`), "discussions"},
		{regexp.MustCompile(`notification`), "notifications"},
		{regexp.MustCompile(`^projects_`), "projects"},
		{regexp.MustCompile(`gist`), "gists"},
		{regexp.MustCompile(`pull_request|review`), "pull_requests"},
		{regexp.MustCompile(`issue|label|find_duplicate`), "issues"},
		{regexp.MustCompile(`^(create|delete|fork)_repository|repository_collaborators|ruleset|custom_properties|collaborator|star`), "repository"},
		{regexp.MustCompile(`^get_me$|team|search_users|search_orgs`), "users"},
		{regexp.MustCompile(`^ui_`), "other"},
	}
)

// githubProduct names the part of GitHub a tool acts on, so presets can
// slice by it (releases and workflows, repository settings).
func githubProduct(name string) string {
	for _, candidate := range githubProducts {
		if candidate.pattern.MatchString(name) {
			return candidate.product
		}
	}
	return "code"
}

func (r *refresher) refreshGitHub(catalogPath, sourcePath string) error {
	pinned, err := pinnedGitHubCommit(sourcePath)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(catalogPath)
	if err != nil {
		return err
	}
	var catalog githubCatalog
	if err := json.Unmarshal(content, &catalog); err != nil {
		return fmt.Errorf("%s: %w", catalogPath, err)
	}

	checkout, err := os.MkdirTemp("", "github-mcp-server-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(checkout)
	head, err := sparseClone(checkout)
	if err != nil {
		return err
	}
	upstream, err := readToolsnaps(checkout)
	if err != nil {
		return err
	}

	// A catalog without tiers is being tiered for the first time; upstream
	// read-only annotations were reviewed by hand for that one run.
	seeding := true
	for _, item := range catalog.Tools {
		seeding = seeding && item.Access == ""
	}
	index := map[string]int{}
	for i, item := range catalog.Tools {
		index[item.Name] = i
	}
	var added, unconfirmed, changed, tightened, removed []string
	for _, name := range sortedKeys(upstream) {
		snap := upstream[name]
		i, known := index[name]
		if !known || seeding {
			access := "write"
			switch {
			case snap.hint == "delete", snap.hint == "read" && seeding:
				access = snap.hint
			case snap.hint == "read":
				unconfirmed = append(unconfirmed, "`"+name+"`")
			}
			if githubAdminTool.MatchString(name) && access != "read" {
				access = "admin"
			}
			item := githubTool{Name: name, Product: githubProduct(name), Access: access, Required: snap.required, Properties: snap.properties, Definition: snap.definition}
			if known {
				item.Named = catalog.Tools[i].Named
				catalog.Tools[i] = item
			} else {
				catalog.Tools = append(catalog.Tools, item)
				index[name] = len(catalog.Tools) - 1
				if !seeding {
					added = append(added, fmt.Sprintf("`%s` (%s)", name, access))
				}
			}
			r.githubChanged = true
			continue
		}
		item := &catalog.Tools[i]
		if item.Removed {
			item.Removed = false
			r.githubChanged = true
		}
		if item.Definition != snap.definition {
			changed = append(changed, fmt.Sprintf("`%s` (%s)", name, item.Access))
			item.Required, item.Properties, item.Definition = snap.required, snap.properties, snap.definition
			r.githubChanged = true
		}
		if accessRank[snap.hint] > accessRank[item.Access] && item.Access != "admin" {
			tightened = append(tightened, fmt.Sprintf("`%s` %s → %s", name, item.Access, snap.hint))
			item.Access = snap.hint
			r.githubChanged = true
		}
	}
	if removed = markRemoved(catalog.Tools, upstream); len(removed) > 0 {
		r.githubChanged = true
	}

	r.note("- github/github-mcp-server: pinned %s, upstream HEAD %s; %d upstream tools, %d catalogued", pinned[:12], head[:12], len(upstream), len(catalog.Tools))
	if seeding {
		r.note("  - tiered every tool for the first time (upstream read-only annotations trusted for this run only)")
	}
	for _, line := range []struct {
		label string
		items []string
	}{
		{"added", added},
		{"upstream says read-only; added as write until a reviewer confirms", unconfirmed},
		{"definition changed; re-check the tier", changed},
		{"tier raised by upstream annotations", tightened},
		{"no longer upstream (kept for older servers)", removed},
	} {
		if len(line.items) > 0 {
			r.note("  - %s: %s", line.label, strings.Join(line.items, ", "))
		}
	}
	if r.githubChanged {
		sort.Slice(catalog.Tools, func(i, j int) bool { return catalog.Tools[i].Name < catalog.Tools[j].Name })
		catalog.Source = githubMCPSourceName + "@" + head
		r.githubCatalog = &catalog
		r.githubHead = head
	}
	return nil
}

// markRemoved flags catalogued tools upstream no longer serves and returns
// the ones newly gone, so a removal opens a review once rather than weekly.
func markRemoved(tools []githubTool, upstream map[string]githubSnapshot) []string {
	var removed []string
	for i := range tools {
		if _, ok := upstream[tools[i].Name]; !ok && !tools[i].Removed {
			tools[i].Removed = true
			removed = append(removed, "`"+tools[i].Name+"`")
		}
	}
	return removed
}

func pinnedGitHubCommit(sourcePath string) (string, error) {
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", err
	}
	match := githubPinPattern.FindSubmatch(source)
	if match == nil {
		return "", fmt.Errorf("%s: GitHubMCPSourceCommit not found", sourcePath)
	}
	return string(match[1]), nil
}

// writeGitHubCatalog writes the re-pinned catalog and moves the pinned
// commit in the CLI source with it.
func writeGitHubCatalog(catalogPath, sourcePath string, catalog *githubCatalog, head string) error {
	content, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(catalogPath, append(content, '\n'), 0o644); err != nil {
		return err
	}
	pinned, err := pinnedGitHubCommit(sourcePath)
	if err != nil {
		return err
	}
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	return os.WriteFile(sourcePath, []byte(strings.Replace(string(source), pinned, head, 1)), 0o644)
}

// sparseClone checks out only the tool snapshots at upstream HEAD: a
// blobless clone limited to the __toolsnaps__ directory.
func sparseClone(dir string) (string, error) {
	steps := [][]string{
		{"clone", "--quiet", "--filter=blob:none", "--no-checkout", githubMCPRepository, dir},
		{"-C", dir, "sparse-checkout", "set", "--no-cone", githubToolsnaps},
		{"-C", dir, "checkout", "--quiet", "HEAD"},
	}
	for _, args := range steps {
		if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	output, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

type githubVariant struct {
	required   []string
	properties map[string]string
	hint       string
	canonical  string
}

// readToolsnaps reads every tool's input schema and annotations. Output
// snapshots (no input schema) are skipped. A tool with several input
// variants is held to all of them: fields any variant takes, fields every
// variant requires, and the strictest annotation, where a variant without
// annotations counts as a write. UI metadata (_meta) is not part of the
// fingerprint; it does not change what a call does.
func readToolsnaps(dir string) (map[string]githubSnapshot, error) {
	paths, err := filepath.Glob(filepath.Join(dir, githubToolsnaps, "*.snap"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	variants := map[string][]githubVariant{}
	for _, snapPath := range paths {
		name, each, ok, err := readToolsnap(snapPath)
		if err != nil {
			return nil, err
		}
		if ok {
			variants[name] = append(variants[name], each)
		}
	}
	tools := map[string]githubSnapshot{}
	for name, all := range variants {
		tools[name] = mergeVariants(all)
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("no tool snapshots in %s", githubToolsnaps)
	}
	return tools, nil
}

func readToolsnap(snapPath string) (string, githubVariant, bool, error) {
	content, err := os.ReadFile(snapPath)
	if err != nil {
		return "", githubVariant{}, false, err
	}
	var snap map[string]any
	if err := json.Unmarshal(content, &snap); err != nil {
		return "", githubVariant{}, false, fmt.Errorf("%s: %w", filepath.Base(snapPath), err)
	}
	name, _ := snap["name"].(string)
	schema, _ := snap["inputSchema"].(map[string]any)
	if name == "" || schema == nil {
		return "", githubVariant{}, false, nil
	}
	delete(snap, "_meta")
	canonical, err := json.Marshal(snap)
	if err != nil {
		return "", githubVariant{}, false, err
	}
	annotations, err := json.Marshal(snap["annotations"])
	if err != nil {
		return "", githubVariant{}, false, err
	}
	each := githubVariant{properties: map[string]string{}, hint: hintAccess(string(annotations)), canonical: string(canonical)}
	if fields, ok := schema["properties"].(map[string]any); ok {
		for field, definition := range fields {
			kind := "any"
			if definition, ok := definition.(map[string]any); ok {
				if value, ok := definition["type"].(string); ok {
					kind = value
				}
			}
			each.properties[field] = kind
		}
	}
	if fields, ok := schema["required"].([]any); ok {
		for _, field := range fields {
			if field, ok := field.(string); ok {
				each.required = append(each.required, field)
			}
		}
	}
	return name, each, true, nil
}

func mergeVariants(all []githubVariant) githubSnapshot {
	merged := githubSnapshot{properties: map[string]string{}, required: []string{}}
	canonical := make([]string, 0, len(all))
	requiredCount := map[string]int{}
	for i, each := range all {
		canonical = append(canonical, each.canonical)
		for field, kind := range each.properties {
			if existing, ok := merged.properties[field]; ok && existing != kind {
				kind = "any"
			}
			merged.properties[field] = kind
		}
		for _, field := range each.required {
			requiredCount[field]++
		}
		hint := each.hint
		if hint == "" && len(all) > 1 {
			hint = "write"
		}
		if i == 0 || accessRank[hint] > accessRank[merged.hint] {
			merged.hint = hint
		}
	}
	for field, count := range requiredCount {
		if count == len(all) {
			merged.required = append(merged.required, field)
		}
	}
	sort.Strings(merged.required)
	merged.definition = fingerprint([]byte(strings.Join(canonical, "\n")))
	return merged
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
