// Command toolcatalog-refresh checks the provider MCP catalogs in
// internal/toolcatalog/providers against their upstream sources and, with
// -write, adds what changed.
//
// A tool that appears upstream is added with the tier its MCP annotations
// suggest, and with write when there are none, so a new tool is never
// silently treated as a read. Tools that disappear upstream are kept (older
// servers and v1 connections still expose them) and only reported. Every
// change is listed in the report so a reviewer can correct a tier before the
// refresh PR merges; the copy in kontext-cloud is then synced from this one.
//
// Sources: the @hubspot/mcp-server npm package, sooperset/mcp-atlassian on
// GitHub, and, when credentials are set, a live tools/list against the
// hosted Atlassian (ATLASSIAN_MCP_AUTHORIZATION, the full Authorization header
// value) and HubSpot (HUBSPOT_MCP_TOKEN) servers. The pinned GitHub MCP
// commit is compared with upstream HEAD and reported only; re-pinning it
// changes input schemas and stays a manual change.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type catalog struct {
	Provider        string       `json:"provider"`
	ToolIDPrefix    string       `json:"toolIdPrefix"`
	Version         string       `json:"version"`
	ServerNameHints []string     `json:"serverNameHints"`
	Sources         []string     `json:"sources"`
	Dispatchers     []dispatcher `json:"dispatchers"`
	Tools           []tool       `json:"tools"`
}

type dispatcher struct {
	Name           string `json:"name"`
	OperationField string `json:"operationField"`
	Distinctive    bool   `json:"distinctive,omitempty"`
}

type tool struct {
	Name        string `json:"name"`
	Product     string `json:"product"`
	Access      string `json:"access"`
	Distinctive bool   `json:"distinctive,omitempty"`
}

// upstreamTool is one tool as a source reports it.
type upstreamTool struct {
	name   string
	access string // read, write or delete, from annotations or tags
}

type refresher struct {
	client  *http.Client
	report  []string
	changed bool
}

var (
	atlassianDistinctive = regexp.MustCompile(`^jira_|^confluence_|Jira|Jsm|Confluence|Bitbucket|bitbucket|Compass|Loom|Atlassian|TeamworkGraph|CapacityPlan|Talent|FocusArea`)
	hubspotDistinctive   = regexp.MustCompile(`^manage_|hubspot|crm|campaign|aeo|marketing_email|landing_page|website_page|blog_post|intent_signals|conversation_channel|content_analytics`)
	atlassianProducts    = []struct {
		pattern *regexp.Regexp
		product string
	}{
		{regexp.MustCompile(`Jsm`), "jsm"},
		{regexp.MustCompile(`^jira_|Jira`), "jira"},
		{regexp.MustCompile(`^confluence_|Confluence`), "confluence"},
		{regexp.MustCompile(`(?i)bitbucket`), "bitbucket"},
		{regexp.MustCompile(`Loom`), "loom"},
		{regexp.MustCompile(`Compass`), "compass"},
		{regexp.MustCompile(`Goal`), "goals"},
		{regexp.MustCompile(`Talent`), "talent"},
	}
)

func main() {
	dir := flag.String("dir", "internal/toolcatalog/providers", "provider catalog directory")
	write := flag.Bool("write", false, "write additions to the catalogs")
	reportPath := flag.String("report", "", "also write the markdown report to this file")
	flag.Parse()

	r := &refresher{client: &http.Client{Timeout: 60 * time.Second}}
	if err := r.run(*dir, *write); err != nil {
		fmt.Fprintln(os.Stderr, "toolcatalog-refresh:", err)
		os.Exit(1)
	}
	body := strings.Join(r.report, "\n") + "\n"
	fmt.Print(body)
	if *reportPath != "" {
		if err := os.WriteFile(*reportPath, []byte(body), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "toolcatalog-refresh:", err)
			os.Exit(1)
		}
	}
}

func (r *refresher) run(dir string, write bool) error {
	atlassianPath := filepath.Join(dir, "atlassian-mcp.json")
	hubspotPath := filepath.Join(dir, "hubspot-mcp.json")
	atlassian, err := readCatalog(atlassianPath)
	if err != nil {
		return err
	}
	hubspot, err := readCatalog(hubspotPath)
	if err != nil {
		return err
	}
	r.note("# Tool catalog refresh")

	if err := r.refreshHubSpotNPM(hubspot); err != nil {
		r.note("- @hubspot/mcp-server: check failed: %v", err)
	}
	if err := r.refreshSooperset(atlassian); err != nil {
		r.note("- sooperset/mcp-atlassian: check failed: %v", err)
	}
	if auth := os.Getenv("ATLASSIAN_MCP_AUTHORIZATION"); auth != "" {
		r.refreshLive(atlassian, "Atlassian Rovo MCP", "https://mcp.atlassian.com/v2/mcp?tools=all", auth)
	} else {
		r.note("- Atlassian Rovo MCP: skipped (ATLASSIAN_MCP_AUTHORIZATION not set)")
	}
	if token := os.Getenv("HUBSPOT_MCP_TOKEN"); token != "" {
		r.refreshLive(hubspot, "HubSpot remote MCP", "https://mcp.hubspot.com/", "Bearer "+token)
	} else {
		r.note("- HubSpot remote MCP: skipped (HUBSPOT_MCP_TOKEN not set)")
	}
	r.reportGitHubDrift()

	if !r.changed {
		r.note("\nNo catalog changes.")
		return nil
	}
	if !write {
		r.note("\nRun with -write to apply.")
		return nil
	}
	today := time.Now().UTC().Format("2006-01-02")
	for _, item := range []struct {
		path    string
		catalog *catalog
	}{{atlassianPath, atlassian}, {hubspotPath, hubspot}} {
		item.catalog.Version = today
		sort.Slice(item.catalog.Tools, func(i, j int) bool { return item.catalog.Tools[i].Name < item.catalog.Tools[j].Name })
		if err := writeCatalog(item.path, item.catalog); err != nil {
			return err
		}
	}
	r.note("\nCatalog version set to %s. Review every added tier above, then sync kontext-cloud.", today)
	return nil
}

func (r *refresher) note(format string, args ...any) {
	r.report = append(r.report, fmt.Sprintf(format, args...))
}

// merge adds upstream tools the catalog does not list and reports those it
// lists that upstream no longer has (filtered to the prefix the source owns).
func (r *refresher) merge(c *catalog, source string, upstream []upstreamTool, owns func(string) bool) {
	known := map[string]bool{}
	for _, t := range c.Tools {
		known[t.Name] = true
	}
	for _, d := range c.Dispatchers {
		known[d.Name] = true
	}
	seen := map[string]bool{}
	var added []string
	for _, u := range upstream {
		seen[u.name] = true
		if known[u.name] {
			continue
		}
		access := u.access
		if access == "" {
			access = "write"
		}
		entry := tool{Name: u.name, Product: productFor(c.Provider, u.name), Access: access}
		if c.Provider == "atlassian" {
			entry.Distinctive = atlassianDistinctive.MatchString(u.name)
		} else {
			entry.Distinctive = hubspotDistinctive.MatchString(u.name)
		}
		c.Tools = append(c.Tools, entry)
		known[u.name] = true
		added = append(added, fmt.Sprintf("`%s` (%s, %s)", u.name, entry.Product, access))
	}
	var gone []string
	for _, t := range c.Tools {
		if owns(t.Name) && !seen[t.Name] {
			gone = append(gone, "`"+t.Name+"`")
		}
	}
	if len(added) == 0 && len(gone) == 0 {
		r.note("- %s: %d tools, no change", source, len(upstream))
		return
	}
	if len(added) > 0 {
		r.changed = true
		r.note("- %s: **added %d** — review the tier of each: %s", source, len(added), strings.Join(added, ", "))
	}
	if len(gone) > 0 {
		r.note("- %s: no longer listed upstream (kept): %s", source, strings.Join(gone, ", "))
	}
}

func productFor(provider, name string) string {
	if provider == "hubspot" {
		return "crm"
	}
	for _, candidate := range atlassianProducts {
		if candidate.pattern.MatchString(name) {
			return candidate.product
		}
	}
	return "platform"
}

var (
	npmPinned   = regexp.MustCompile(`@hubspot/mcp-server@([0-9][^ ]*)`)
	npmToolName = regexp.MustCompile(`name: '(hubspot-[a-z-]+)'`)
)

func (r *refresher) refreshHubSpotNPM(c *catalog) error {
	var meta struct {
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := r.getJSON("https://registry.npmjs.org/@hubspot/mcp-server", &meta); err != nil {
		return err
	}
	latest := meta.DistTags["latest"]
	pinned := ""
	sourceIndex := -1
	for i, source := range c.Sources {
		if match := npmPinned.FindStringSubmatch(source); match != nil {
			pinned, sourceIndex = match[1], i
		}
	}
	tarball, err := r.get(meta.Versions[latest].Dist.Tarball)
	if err != nil {
		return err
	}
	upstream, err := npmTools(tarball)
	if err != nil {
		return err
	}
	label := "@hubspot/mcp-server@" + latest
	if latest != pinned {
		label += " (was " + pinned + ")"
		if sourceIndex >= 0 {
			c.Sources[sourceIndex] = npmPinned.ReplaceAllString(c.Sources[sourceIndex], "@hubspot/mcp-server@"+latest)
			r.changed = true
		}
	}
	r.merge(c, label, upstream, func(name string) bool { return strings.HasPrefix(name, "hubspot-") })
	return nil
}

func npmTools(tarball []byte) ([]upstreamTool, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	archive := tar.NewReader(gz)
	var tools []upstreamTool
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if !strings.Contains(header.Name, "/dist/tools/") || !strings.HasSuffix(header.Name, "Tool.js") {
			continue
		}
		source, err := io.ReadAll(io.LimitReader(archive, 1<<20))
		if err != nil {
			return nil, err
		}
		match := npmToolName.FindSubmatch(source)
		if match == nil {
			continue
		}
		tools = append(tools, upstreamTool{name: string(match[1]), access: hintAccess(string(source))})
	}
	if len(tools) == 0 {
		return nil, errors.New("no tool definitions found in the package")
	}
	return tools, nil
}

// hintAccess reads MCP tool annotations in source text or JSON.
func hintAccess(text string) string {
	compact := strings.ReplaceAll(strings.ReplaceAll(text, " ", ""), "\"", "")
	switch {
	case strings.Contains(compact, "destructiveHint:true"):
		return "delete"
	case strings.Contains(compact, "readOnlyHint:true"):
		return "read"
	default:
		return "write"
	}
}

var (
	soopersetPinned = regexp.MustCompile(`sooperset/mcp-atlassian@([0-9a-f]{40})`)
	soopersetTool   = regexp.MustCompile(`(?s)@\w+\.tool\((.*?)\)\s*(?:@[^\n]*\n\s*)*async def (\w+)`)
	soopersetTags   = regexp.MustCompile(`tags=\{([^}]*)\}`)
)

func (r *refresher) refreshSooperset(c *catalog) error {
	head, err := lsRemoteHead("https://github.com/sooperset/mcp-atlassian")
	if err != nil {
		return err
	}
	var upstream []upstreamTool
	for _, product := range []string{"jira", "confluence"} {
		source, err := r.get("https://raw.githubusercontent.com/sooperset/mcp-atlassian/" + head + "/src/mcp_atlassian/servers/" + product + ".py")
		if err != nil {
			return err
		}
		for _, match := range soopersetTool.FindAllStringSubmatch(string(source), -1) {
			access := "write"
			if tags := soopersetTags.FindStringSubmatch(match[1]); tags != nil && strings.Contains(tags[1], `"read"`) {
				access = "read"
			}
			if strings.Contains(match[2], "delete") {
				access = "delete"
			}
			upstream = append(upstream, upstreamTool{name: product + "_" + match[2], access: access})
		}
	}
	if len(upstream) == 0 {
		return errors.New("no tools found; the server layout may have changed")
	}
	for i, source := range c.Sources {
		if match := soopersetPinned.FindStringSubmatch(source); match != nil && match[1] != head {
			c.Sources[i] = soopersetPinned.ReplaceAllString(source, "sooperset/mcp-atlassian@"+head)
			r.changed = true
		}
	}
	r.merge(c, "sooperset/mcp-atlassian@"+head[:12], upstream, func(name string) bool {
		return strings.HasPrefix(name, "jira_") || strings.HasPrefix(name, "confluence_")
	})
	return nil
}

// refreshLive lists a hosted server's tools over MCP streamable HTTP. A
// failure is reported, not fatal: the other sources still refresh.
func (r *refresher) refreshLive(c *catalog, label, endpoint, authorization string) {
	tools, err := r.listTools(endpoint, authorization)
	if err != nil {
		r.note("- %s: check failed: %v", label, err)
		return
	}
	r.merge(c, label, tools, func(name string) bool {
		if c.Provider == "hubspot" {
			return !strings.HasPrefix(name, "hubspot-")
		}
		// v1 names and community tools are not on the hosted v2 list.
		return false
	})
}

func (r *refresher) listTools(endpoint, authorization string) ([]upstreamTool, error) {
	session := ""
	call := func(id int, method string, params any) (json.RawMessage, error) {
		payload := map[string]any{"jsonrpc": "2.0", "method": method}
		if id > 0 {
			payload["id"] = id
		}
		if params != nil {
			payload["params"] = params
		}
		body, _ := json.Marshal(payload)
		request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", authorization)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", "2025-06-18")
		if session != "" {
			request.Header.Set("Mcp-Session-Id", session)
		}
		response, err := r.client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if value := response.Header.Get("Mcp-Session-Id"); value != "" {
			session = value
		}
		if response.StatusCode >= 300 {
			return nil, fmt.Errorf("%s: HTTP %d", method, response.StatusCode)
		}
		if id == 0 {
			return nil, nil
		}
		return rpcResult(response)
	}
	if _, err := call(1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "kontext-toolcatalog-refresh", "version": "1"},
	}); err != nil {
		return nil, err
	}
	if _, err := call(0, "notifications/initialized", nil); err != nil {
		return nil, err
	}
	var tools []upstreamTool
	cursor := ""
	for page := 2; page < 100; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := call(page, "tools/list", params)
		if err != nil {
			return nil, err
		}
		var result struct {
			Tools []struct {
				Name        string          `json:"name"`
				Annotations json.RawMessage `json:"annotations"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, err
		}
		for _, t := range result.Tools {
			tools = append(tools, upstreamTool{name: t.Name, access: hintAccess(string(t.Annotations))})
		}
		if result.NextCursor == "" {
			return tools, nil
		}
		cursor = result.NextCursor
	}
	return nil, errors.New("tools/list did not finish paginating")
}

// rpcResult reads a JSON-RPC result from a JSON or an SSE response body.
func rpcResult(response *http.Response) (json.RawMessage, error) {
	var payloads [][]byte
	if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 0, 1<<20), 16<<20)
		for scanner.Scan() {
			if data, ok := strings.CutPrefix(scanner.Text(), "data:"); ok {
				payloads = append(payloads, []byte(strings.TrimSpace(data)))
			}
		}
	} else {
		body, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, body)
	}
	for _, payload := range payloads {
		var message struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(payload, &message) != nil {
			continue
		}
		if message.Error != nil {
			return nil, errors.New(message.Error.Message)
		}
		if message.Result != nil {
			return message.Result, nil
		}
	}
	return nil, errors.New("no JSON-RPC result in response")
}

func (r *refresher) reportGitHubDrift() {
	source, err := os.ReadFile("internal/toolcatalog/github.go")
	if err != nil {
		return
	}
	match := regexp.MustCompile(`GitHubMCPSourceCommit\s*=\s*"([0-9a-f]{40})"`).FindSubmatch(source)
	if match == nil {
		return
	}
	head, err := lsRemoteHead("https://github.com/github/github-mcp-server")
	if err != nil {
		r.note("- github/github-mcp-server: check failed: %v", err)
		return
	}
	if head == string(match[1]) {
		r.note("- github/github-mcp-server: pinned commit is HEAD")
		return
	}
	r.note("- github/github-mcp-server: pinned %s, upstream HEAD %s. Re-pinning is manual (input schemas change).", match[1][:12], head[:12])
}

func lsRemoteHead(repository string) (string, error) {
	output, err := exec.Command("git", "ls-remote", repository, "HEAD").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 || len(fields[0]) != 40 {
		return "", fmt.Errorf("unexpected ls-remote output %q", output)
	}
	return fields[0], nil
}

func (r *refresher) get(url string) ([]byte, error) {
	response, err := r.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 64<<20))
}

func (r *refresher) getJSON(url string, value any) error {
	body, err := r.get(url)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, value)
}

func readCatalog(path string) (*catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c catalog
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func writeCatalog(path string, c *catalog) error {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(c); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}
