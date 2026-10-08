package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The GitHub MCP catalog (internal/toolcatalog/github-mcp.json) is pinned to
// one upstream commit and resolves calls by input schema, and the GitHub
// presets name tool ids. A tool the catalog adds therefore leaves the
// unrecognized guard without joining any preset, so the refresh never adds
// GitHub tools itself. It tracks every upstream tool's definition in
// github-upstream.json, and a new, removed or changed tool updates that file
// and opens the review PR; re-pinning the catalog and the presets stays a
// reviewed change.

const (
	githubMCPRepository = "https://github.com/github/github-mcp-server"
	githubToolsnaps     = "pkg/github/__toolsnaps__"
)

type githubUpstream struct {
	Source string               `json:"source"`
	Tools  []githubUpstreamTool `json:"tools"`
}

type githubUpstreamTool struct {
	Name string `json:"name"`
	// Catalogued tools resolve to github-mcp/<name>; the rest resolve to
	// github-mcp/unrecognized, which the guard blocks.
	Catalogued bool `json:"catalogued"`
	// Hint is the tier upstream annotations claim: read, write, delete or "".
	Hint       string `json:"hint"`
	Definition string `json:"definition"`
}

func (r *refresher) refreshGitHub(upstreamPath, catalogPath, sourcePath string) error {
	pinned, err := pinnedGitHubCommit(sourcePath)
	if err != nil {
		return err
	}
	catalogued, err := githubCatalogNames(catalogPath)
	if err != nil {
		return err
	}
	var recorded githubUpstream
	if content, err := os.ReadFile(upstreamPath); err == nil {
		if err := json.Unmarshal(content, &recorded); err != nil {
			return fmt.Errorf("%s: %w", upstreamPath, err)
		}
	} else if !os.IsNotExist(err) {
		return err
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
	current, err := readToolsnaps(checkout, head)
	if err != nil {
		return err
	}
	atPin, err := readToolsnaps(checkout, pinned)
	if err != nil {
		return err
	}

	previous := map[string]githubUpstreamTool{}
	for _, item := range recorded.Tools {
		previous[item.Name] = item
	}
	next := githubUpstream{Source: "github/github-mcp-server"}
	var added, changed, tightened, removed, stalePin []string
	for _, name := range sortedKeys(current) {
		item := current[name]
		item.Catalogued = catalogued[name]
		next.Tools = append(next.Tools, item)
		before, known := previous[name]
		switch {
		case !known && len(recorded.Tools) > 0:
			added = append(added, fmt.Sprintf("`%s` (%s)", name, githubToolState(item)))
		case known && before.Definition != item.Definition:
			changed = append(changed, fmt.Sprintf("`%s` (%s)", name, githubToolState(item)))
		}
		if known && accessRank[item.Hint] > accessRank[before.Hint] {
			tightened = append(tightened, fmt.Sprintf("`%s` %s → %s", name, orNone(before.Hint), item.Hint))
		}
		if pin, ok := atPin[name]; item.Catalogued && ok && pin.Definition != item.Definition {
			stalePin = append(stalePin, "`"+name+"`")
		}
	}
	for _, name := range sortedKeys(previous) {
		if _, ok := current[name]; !ok {
			removed = append(removed, "`"+name+"`")
		}
	}
	missing := 0
	for _, item := range next.Tools {
		if !item.Catalogued {
			missing++
		}
	}

	r.note("- github/github-mcp-server: pinned %s, upstream HEAD %s; %d upstream tools, %d catalogued. The other %d resolve to github-mcp/unrecognized and are blocked by the guard.",
		pinned[:12], head[:12], len(next.Tools), len(next.Tools)-missing, missing)
	if len(recorded.Tools) == 0 {
		r.note("  - first run: recorded every upstream definition as the baseline")
		r.githubChanged = true
	}
	for _, line := range []struct {
		label string
		items []string
	}{
		{"new upstream tools (not catalogued; re-pin to add them, and add writes to the GitHub presets)", added},
		{"definitions changed since the last review", changed},
		{"annotations now claim a stricter tier", tightened},
		{"removed upstream (kept in the catalog for older servers)", removed},
		{"catalogued tools whose definition differs from the pinned commit", stalePin},
	} {
		if len(line.items) > 0 {
			r.note("  - %s: %s", line.label, strings.Join(line.items, ", "))
		}
	}
	if len(added)+len(changed)+len(tightened)+len(removed) > 0 {
		r.githubChanged = true
	}
	r.githubUpstream = &next
	return nil
}

func githubToolState(item githubUpstreamTool) string {
	state := "upstream hint " + orNone(item.Hint)
	if item.Catalogued {
		return "catalogued, " + state
	}
	return "uncatalogued, " + state
}

func orNone(hint string) string {
	if hint == "" {
		return "none"
	}
	return hint
}

func pinnedGitHubCommit(sourcePath string) (string, error) {
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", err
	}
	match := regexp.MustCompile(`GitHubMCPSourceCommit\s*=\s*"([0-9a-f]{40})"`).FindSubmatch(source)
	if match == nil {
		return "", fmt.Errorf("%s: GitHubMCPSourceCommit not found", sourcePath)
	}
	return string(match[1]), nil
}

func githubCatalogNames(catalogPath string) (map[string]bool, error) {
	content, err := os.ReadFile(catalogPath)
	if err != nil {
		return nil, err
	}
	var catalog struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(content, &catalog); err != nil {
		return nil, fmt.Errorf("%s: %w", catalogPath, err)
	}
	names := map[string]bool{}
	for _, item := range catalog.Tools {
		names[item.Name] = true
	}
	return names, nil
}

// sparseClone fetches only the tool snapshots: a blobless clone limited to
// the __toolsnaps__ directory. It returns upstream HEAD.
func sparseClone(dir string) (string, error) {
	steps := [][]string{
		{"clone", "--quiet", "--filter=blob:none", "--no-checkout", githubMCPRepository, dir},
		{"-C", dir, "sparse-checkout", "set", "--no-cone", githubToolsnaps},
	}
	for _, args := range steps {
		if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(string(output)))
		}
	}
	output, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// readToolsnaps checks out the snapshots at commit and fingerprints each
// tool's definition: description, input schema and annotations. UI metadata
// (_meta) is left out; it does not change what a call does.
func readToolsnaps(dir, commit string) (map[string]githubUpstreamTool, error) {
	if output, err := exec.Command("git", "-C", dir, "checkout", "--quiet", commit).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("git checkout %s: %v: %s", commit[:12], err, strings.TrimSpace(string(output)))
	}
	paths, err := filepath.Glob(filepath.Join(dir, githubToolsnaps, "*.snap"))
	if err != nil {
		return nil, err
	}
	// A tool can have several snapshots (input variants); each one counts, so
	// a change to any of them is a change to the tool.
	definitions := map[string][]string{}
	hints := map[string]string{}
	for _, snapPath := range paths {
		content, err := os.ReadFile(snapPath)
		if err != nil {
			return nil, err
		}
		var snap map[string]any
		if err := json.Unmarshal(content, &snap); err != nil {
			return nil, fmt.Errorf("%s: %w", path.Base(snapPath), err)
		}
		delete(snap, "_meta")
		name, _ := snap["name"].(string)
		if name == "" {
			continue
		}
		canonical, err := json.Marshal(snap)
		if err != nil {
			return nil, err
		}
		annotations, err := json.Marshal(snap["annotations"])
		if err != nil {
			return nil, err
		}
		definitions[name] = append(definitions[name], string(canonical))
		if hint := hintAccess(string(annotations)); hintRank[hint] > hintRank[hints[name]] {
			hints[name] = hint
		}
	}
	tools := map[string]githubUpstreamTool{}
	for name, variants := range definitions {
		sort.Strings(variants)
		tools[name] = githubUpstreamTool{Name: name, Hint: hints[name], Definition: fingerprint([]byte(strings.Join(variants, "\n")))}
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("no tool snapshots at %s", commit[:12])
	}
	return tools, nil
}

// hintRank orders upstream hints from loosest to strictest; a tool takes
// the strictest hint any of its variants carries.
var hintRank = map[string]int{"": 0, "read": 1, "write": 2, "delete": 3}

func writeGitHubUpstream(upstreamPath string, upstream *githubUpstream) error {
	content, err := json.MarshalIndent(upstream, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(upstreamPath, append(content, '\n'), 0o644)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
