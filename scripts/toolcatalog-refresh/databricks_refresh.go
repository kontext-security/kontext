package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// The weekly refresh keeps both Databricks sources current.
//
// The route table follows the latest databricks/cli release. A regenerated
// table keeps every operation upstream dropped (older CLIs still call it)
// and every command upstream dropped, and reports what moved: added
// operations, changed methods or paths, tiers and products, and new
// hand-written subcommands, which stay unclassified until a reviewer adds
// them to databricksHandCommands.
//
// The managed MCP servers are listed live on the test workspace with an
// OAuth M2M token (DATABRICKS_HOST, DATABRICKS_CLIENT_ID,
// DATABRICKS_CLIENT_SECRET). DATABRICKS_MCP_ENDPOINTS holds the server paths
// to list, separated by spaces, commas or newlines. Their tools go through
// merge(), so annotations only ever raise a tier. The gateway's GitHub and
// Atlassian servers are checked against those catalogs, and servers whose
// tool names are per workspace (Unity Catalog functions, AI Search indexes)
// are only reported, since their urlKinds entry classifies them by URL.

// databricksLatestRelease redirects to the latest release's tag page. The
// redirect has no API rate limit.
var databricksLatestRelease = "https://github.com/databricks/cli/releases/latest"

// databricksMCPProducts places each managed MCP server's new tools, keyed by
// the server's last path segment. A server in DATABRICKS_MCP_ENDPOINTS that
// is not listed here fails its check until a reviewer places it.
var databricksMCPProducts = map[string]string{
	"sql":                     "sql",
	"system.ai.dbsql":         "sql",
	"system.ai.genie_one_mcp": "ai",
	"system.ai.sandbox":       "execution",
	"system.ai.web_search":    "ai",
}

// databricksPerWorkspace are the catalog's synthetic tool ids for servers
// whose tool names are per workspace (a Unity Catalog function's name, an
// AI Search index's), so they are only reported. The sandbox's urlKinds
// entry names its real tool, run_code, and is listed like any server.
var databricksPerWorkspace = map[string]bool{"uc-function": true, "ai-search": true}

var (
	databricksDistinctive = regexp.MustCompile(`^genie_|databricks`)
	cobraUseLiteral       = regexp.MustCompile(`Use:\s*"([^"\s]+)|\.Use\s*=\s*"([^"\s]+)`)
)

// refreshDatabricksRoutes moves the route table to the latest databricks/cli
// release; run() writes it.
func (r *refresher) refreshDatabricksRoutes(outputPath string) error {
	old, err := readDatabricksTable(outputPath)
	if err != nil {
		return err
	}
	latest, err := r.latestDatabricksCLI()
	if err != nil {
		return err
	}
	if latest == old.CLI {
		r.note("- Databricks route table: databricks/cli %s is the latest release, no change", latest)
		return nil
	}
	table, err := r.regenerateDatabricks(old, latest)
	if err != nil {
		return err
	}
	r.routes, r.routesPath = table, outputPath
	return nil
}

func (r *refresher) latestDatabricksCLI() (string, error) {
	client := *r.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(databricksLatestRelease)
	if err != nil {
		return "", err
	}
	response.Body.Close()
	tag := path.Base(response.Header.Get("Location"))
	if response.StatusCode/100 != 3 || !goModVersion.MatchString(tag) {
		return "", fmt.Errorf("latest databricks/cli release: HTTP %d, tag %q", response.StatusCode, tag)
	}
	return tag, nil
}

// regenerateDatabricks builds the table at a databricks/cli release and
// carries over what the old table has that the new one dropped.
func (r *refresher) regenerateDatabricks(old *databricksTable, version string) (*databricksTable, error) {
	cli, hand, err := r.databricksCLISource(version)
	if err != nil {
		return nil, err
	}
	sdk, sdkVersion, err := r.databricksSDKSource(cli)
	if err != nil {
		return nil, err
	}
	table, report, err := buildDatabricksTable(cli, sdk, version, sdkVersion)
	if err != nil {
		return nil, err
	}
	r.report = append(r.report, report...)
	r.note("\n## Changes since databricks/cli %s, databricks-sdk-go %s\n", old.CLI, old.SDK)
	r.keepDatabricksRoutes(old, table)
	if version != old.CLI {
		_, oldHand, err := r.databricksCLISource(old.CLI)
		if err != nil {
			return nil, err
		}
		var added []string
		for command := range hand {
			if !oldHand[command] {
				added = append(added, "`"+command+"`")
			}
		}
		r.noteList("new hand-written subcommands, unclassified until added to databricksHandCommands", added)
		if len(added) > 0 {
			// Merging on its own would bury the notice.
			r.needsReview("databricks/cli adds hand-written subcommands")
		}
	}
	return table, nil
}

// keepDatabricksRoutes compares the regenerated table with the old one. It
// keeps operations and commands upstream dropped, reports every change and
// asks for review when one could loosen a classification.
func (r *refresher) keepDatabricksRoutes(old, fresh *databricksTable) {
	byOperation, byRoute, byCommand := map[string]*databricksEntry{}, map[string]*databricksEntry{}, map[string]*databricksEntry{}
	for i := range fresh.Routes {
		entry := &fresh.Routes[i]
		byOperation[entry.Operation] = entry
		if entry.Path != "" {
			byRoute[entry.Method+" "+entry.Path] = entry
		}
		for _, command := range entry.Commands {
			byCommand[command] = entry
		}
	}
	var added, removed, moved, lowered, raised, products, commandsMoved, commandsKept []string
	compare := func(label string, before databricksEntry, after *databricksEntry) {
		switch {
		case looserAccess(before.Access, after.Access):
			lowered = append(lowered, fmt.Sprintf("%s (%s to %s)", label, before.Access, after.Access))
		case after.Access != before.Access:
			raised = append(raised, fmt.Sprintf("%s (%s to %s)", label, before.Access, after.Access))
		}
		if after.Product != before.Product {
			products = append(products, fmt.Sprintf("%s (%s to %s)", label, before.Product, after.Product))
		}
	}
	oldOperations := map[string]*databricksEntry{}
	var kept []databricksEntry
	for i, before := range old.Routes {
		oldOperations[before.Operation] = &old.Routes[i]
		after := byOperation[before.Operation]
		switch {
		case after != nil:
			if after.Method != before.Method || after.Path != before.Path {
				moved = append(moved, fmt.Sprintf("`%s` (`%s %s` to `%s %s`)", before.Operation, before.Method, before.Path, after.Method, after.Path))
				// Older clients and `databricks api` calls still use the old
				// route, so it stays classified under its own name.
				if before.Path != "" && byRoute[before.Method+" "+before.Path] == nil {
					route := before
					route.Operation, route.Commands = before.Operation+"@"+old.CLI, nil
					kept = append(kept, route)
				}
			}
		case before.Path != "" && byRoute[before.Method+" "+before.Path] != nil:
			after = byRoute[before.Method+" "+before.Path]
			moved = append(moved, fmt.Sprintf("`%s %s` (`%s` renamed `%s`)", before.Method, before.Path, before.Operation, after.Operation))
		default:
			entry := before
			entry.Commands = nil
			for _, command := range before.Commands {
				if now := byCommand[command]; now == nil {
					entry.Commands = append(entry.Commands, command)
					commandsKept = append(commandsKept, fmt.Sprintf("`%s` (on `%s`)", command, before.Operation))
				} else {
					commandsMoved = append(commandsMoved, fmt.Sprintf("`%s` (`%s` to `%s`)", command, before.Operation, now.Operation))
					compare("`"+command+"`", before, now)
				}
			}
			kept = append(kept, entry)
			removed = append(removed, fmt.Sprintf("`%s` (%s)", before.Operation, before.Access))
			continue
		}
		compare("`"+before.Operation+"`", before, after)
		for _, command := range before.Commands {
			if now := byCommand[command]; now == nil {
				after.Commands = append(after.Commands, command)
				sort.Strings(after.Commands)
				byCommand[command] = after
				commandsKept = append(commandsKept, fmt.Sprintf("`%s` (on `%s`)", command, after.Operation))
			} else if now.Operation != after.Operation {
				commandsMoved = append(commandsMoved, fmt.Sprintf("`%s` (`%s` to `%s`)", command, before.Operation, now.Operation))
				compare("`"+command+"`", before, now)
			}
		}
	}
	var reads, shadows []string
	for _, entry := range fresh.Routes {
		was := oldOperations[entry.Operation]
		if was == nil {
			added = append(added, fmt.Sprintf("`%s %s` %s (%s, %s)", entry.Method, entry.Path, entry.Operation, entry.Product, entry.Access))
			if entry.Access == "read" {
				reads = append(reads, entry.Operation)
			}
		} else if was.Method == entry.Method && was.Path == entry.Path && was.Access == entry.Access && was.Product == entry.Product {
			continue
		}
		// A new or changed route can take over requests an old route
		// matched (it is more literal, names the exact API version, or
		// ties), so it must not be looser than, or differ in product from,
		// any other old route whose template some request matches along
		// with its own.
		for _, before := range old.Routes {
			if before.Operation == entry.Operation || before.Method != entry.Method || before.Path == "" || entry.Path == "" || !routesOverlap(before.Path, entry.Path) {
				continue
			}
			if looserAccess(before.Access, entry.Access) || entry.Product != before.Product {
				shadows = append(shadows, fmt.Sprintf("`%s %s` %s (%s, %s) over `%s` %s (%s, %s)", entry.Method, entry.Path, entry.Operation, entry.Product, entry.Access, before.Path, before.Operation, before.Product, before.Access))
			}
		}
	}
	fresh.Routes = append(fresh.Routes, kept...)
	sortDatabricksRoutes(fresh.Routes)

	if len(added)+len(removed)+len(commandsKept)+len(moved)+len(commandsMoved)+len(lowered)+len(raised)+len(products) == 0 {
		r.note("- no operation or command changes")
	}
	r.noteList("added (a POST, PUT, PATCH or DELETE is never read unless a reviewed rule says so)", added)
	r.noteList("removed upstream (kept for older CLIs)", removed)
	r.noteList("commands removed upstream (kept)", commandsKept)
	r.noteList("method, path or operation name changed", moved)
	r.noteList("commands moved to another operation", commandsMoved)
	r.noteList("**tier lowered**", lowered)
	r.noteList("tier raised", raised)
	r.noteList("**product changed**", products)
	r.noteList("**new route over an old template with a different tier or product**", shadows)
	if len(reads) > 0 {
		r.needsReview(fmt.Sprintf("the route table adds %d read operations", len(reads)))
	}
	if len(lowered) > 0 {
		r.needsReview("the route table lowers a tier")
	}
	if len(products) > 0 {
		r.needsReview("the route table changes a product")
	}
	if len(shadows) > 0 {
		r.needsReview("a new route takes over an old route's requests with a looser tier or another product")
	}
	if len(commandsKept) > 0 {
		// The command may still exist but call something the generator
		// cannot place, which its old mapping would hide.
		r.needsReview("the route table keeps commands upstream no longer maps")
	}
	if len(moved)+len(commandsMoved) > 0 {
		r.needsReview("the route table moves an operation or a command")
	}
}

var (
	routeVersion  = regexp.MustCompile(`^/api/\d+\.\d+/`)
	routeCatchAll = regexp.MustCompile(`^(/api/\d+\.\d+)?/\{`)
)

// routesOverlap says whether some request path matches both route
// templates, under any API version, as internal/toolcatalog matches them:
// {param} spans one segment, {param+} one or more. A segment that mixes a
// parameter with literal text counts as a parameter, so an overlap is never
// missed. Templates that start with a parameter are never matched by path
// at runtime (databricksCatchAll) and overlap nothing.
func routesOverlap(a, b string) bool {
	segments := func(template string) []string {
		return strings.Split(strings.TrimPrefix(routeVersion.ReplaceAllString(template, "/api/{v}/"), "/"), "/")
	}
	if routeCatchAll.MatchString(a) || routeCatchAll.MatchString(b) {
		return false
	}
	return segmentsOverlap(segments(a), segments(b))
}

func segmentsOverlap(a, b []string) bool {
	multi := func(segment string) bool { return strings.Contains(segment, "+}") }
	param := func(segment string) bool { return strings.Contains(segment, "{") }
	switch {
	case len(a) == 0 || len(b) == 0:
		return len(a) == 0 && len(b) == 0
	case multi(a[0]):
		// It takes b[0] and stops, or takes b[0] and goes on; when b[0]
		// spans several too, b's goes on instead.
		return segmentsOverlap(a[1:], b[1:]) || segmentsOverlap(a, b[1:]) || multi(b[0]) && segmentsOverlap(a[1:], b)
	case multi(b[0]):
		return segmentsOverlap(b, a)
	case param(a[0]) || param(b[0]) || a[0] == b[0]:
		return segmentsOverlap(a[1:], b[1:])
	}
	return false
}

// looserAccess says whether moving an operation from one tier to another
// drops a fact a preset matches on. A delete emits databricks/delete and an
// admin operation databricks/admin, and neither implies the other, so
// delete to admin loosens the deletion presets even though admin ranks
// higher.
func looserAccess(before, after string) bool {
	return accessRankDatabricks[after] < accessRankDatabricks[before] || before == "delete" && after == "admin"
}

// handWrittenCommands lists `<group> <verb>` for every cobra command outside
// the generated cmd/workspace and cmd/account packages. Nested groups are
// filed under their top-level group, which is enough to spot a new one.
func handWrittenCommands(cli sourceTree) map[string]bool {
	commands := map[string]bool{}
	for name, source := range cli {
		group, _, nested := strings.Cut(strings.TrimPrefix(name, "cmd/"), "/")
		if !nested || group == "workspace" || group == "account" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, match := range cobraUseLiteral.FindAllSubmatch(source, -1) {
			if verb := string(match[1]) + string(match[2]); verb != group {
				commands[group+" "+verb] = true
			}
		}
	}
	return commands
}

func (r *refresher) noteList(label string, items []string) {
	if len(items) == 0 {
		return
	}
	sort.Strings(items)
	r.note("- %s (%d): %s", label, len(items), strings.Join(items, ", "))
}

// refreshDatabricksMCP lists the managed MCP servers in
// DATABRICKS_MCP_ENDPOINTS on the test workspace.
func (r *refresher) refreshDatabricksMCP(databricks, atlassian *catalog, githubCatalogPath string) {
	host := strings.TrimSuffix(strings.TrimPrefix(os.Getenv("DATABRICKS_HOST"), "https://"), "/")
	clientID, clientSecret := os.Getenv("DATABRICKS_CLIENT_ID"), os.Getenv("DATABRICKS_CLIENT_SECRET")
	endpoints := strings.FieldsFunc(os.Getenv("DATABRICKS_MCP_ENDPOINTS"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' })
	switch {
	case host == "" || clientID == "" || clientSecret == "":
		r.note("- Databricks managed MCP: skipped (DATABRICKS_HOST, DATABRICKS_CLIENT_ID and DATABRICKS_CLIENT_SECRET not set)")
		return
	case len(endpoints) == 0:
		r.note("- Databricks managed MCP: skipped (DATABRICKS_MCP_ENDPOINTS not set)")
		return
	}
	parsedHost, err := url.Parse("https://" + host)
	if err != nil || parsedHost.Host != host || parsedHost.User != nil || parsedHost.Hostname() == "" {
		r.databricksFailed("- Databricks managed MCP: check failed: DATABRICKS_HOST is not a host name")
		return
	}
	// A transport error names the URL; the host is a secret and the report
	// lands in a PR body. Every line this check adds is scrubbed again on
	// the way out.
	// A DNS error names the bare host name, without the port.
	redact := strings.NewReplacer(host, "$DATABRICKS_HOST", parsedHost.Hostname(), "$DATABRICKS_HOST")
	scrub := func(err error) string { return redact.Replace(err.Error()) }
	start := len(r.report)
	defer func() {
		for i := start; i < len(r.report); i++ {
			r.report[i] = redact.Replace(r.report[i])
		}
	}()
	token, err := r.databricksToken("https://"+host, clientID, clientSecret)
	if err != nil {
		r.databricksFailed("- Databricks managed MCP: check failed: %s", scrub(err))
		return
	}

	type served struct {
		tool        upstreamTool
		definitions map[string]bool
		servers     []string
	}
	byName := map[string]*served{}
	add := func(t upstreamTool, server string) {
		entry := byName[t.name]
		if entry == nil {
			entry = &served{tool: t, definitions: map[string]bool{}}
			byName[t.name] = entry
		}
		entry.definitions[t.definition] = true
		entry.servers = append(entry.servers, server)
		if accessRank[t.hint] > accessRank[entry.tool.hint] {
			entry.tool.hint = t.hint
		}
		if entry.tool.product != t.product {
			r.note("- Databricks managed MCP: `%s` is served by %s with different products; a new entry takes %s", t.name, strings.Join(entry.servers, ", "), entry.tool.product)
		}
	}
	complete := true
	for _, endpoint := range endpoints {
		label := "Databricks MCP " + endpoint
		parsed, err := url.Parse("https://" + host + endpoint)
		if err != nil || !strings.HasPrefix(endpoint, "/") || parsed.Host != host {
			// The entry may be a full URL, which names the host.
			r.databricksFailed("- Databricks MCP: check failed: a DATABRICKS_MCP_ENDPOINTS entry is not a server path")
			complete = false
			continue
		}
		tools, err := r.listTools(parsed.String(), "Bearer "+token)
		if err != nil {
			r.databricksFailed("- %s: check failed: %s", label, scrub(err))
			complete = false
			continue
		}
		server := path.Base(endpoint)
		switch server {
		case "system.ai.github":
			r.noteGitHubGateway(label, githubCatalogPath, tools)
			continue
		case "system.ai.atlassian":
			r.merge(atlassian, label, tools, func(string) bool { return false })
			continue
		}
		// Every tool on a urlKinds server resolves by URL to the kind's
		// tool, so that entry takes the strictest hint any of them carries
		// and a fingerprint over all their definitions.
		if kind := urlKindFor(databricks, endpoint); kind != nil {
			name := strings.TrimPrefix(kind.ToolID, databricks.ToolIDPrefix)
			effective := upstreamTool{name: name}
			parts := make([]string, len(tools))
			names := make([]string, len(tools))
			for i, t := range tools {
				parts[i], names[i] = t.name+"\t"+t.definition, "`"+t.name+"`"
				if accessRank[t.hint] > accessRank[effective.hint] {
					effective.hint = t.hint
				}
			}
			sort.Strings(parts)
			effective.definition = fingerprint([]byte(strings.Join(parts, "\n")))
			for _, t := range databricks.Tools {
				if t.Name == name {
					effective.product = t.Product
				}
			}
			add(effective, server)
			if databricksPerWorkspace[name] {
				r.noteList(fmt.Sprintf("%s: per-workspace tool names, classified by URL as %s", label, kind.ToolID), names)
				continue
			}
		}
		product := databricksMCPProducts[server]
		if product == "" {
			r.databricksFailed("- %s: check failed: no product for server %q; add it to databricksMCPProducts", label, server)
			complete = false
			continue
		}
		for _, t := range tools {
			t.product = product
			add(t, server)
		}
	}
	if len(byName) == 0 {
		return
	}
	// A tool served by several servers is fingerprinted over all of its
	// definitions, so the servers' order never reads as a change.
	var upstream []upstreamTool
	for _, name := range sortedKeys(byName) {
		entry := byName[name]
		if len(entry.definitions) > 1 {
			entry.tool.definition = fingerprint([]byte(strings.Join(sortedKeys(entry.definitions), "\n")))
		}
		upstream = append(upstream, entry.tool)
	}
	r.merge(databricks, "Databricks managed MCP", upstream, func(name string) bool {
		// Only a full listing can say a tool is gone.
		return complete && !databricksPerWorkspace[name]
	})
}

// databricksToken mints a workspace OAuth token for the service principal
// (OAuth M2M). Neither the secret nor the token is ever reported.
func (r *refresher) databricksToken(workspace, clientID, clientSecret string) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"all-apis"}}
	request, err := http.NewRequest(http.MethodPost, workspace+"/oidc/v1/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.SetBasicAuth(clientID, clientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := r.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body); err != nil || response.StatusCode != http.StatusOK || body.AccessToken == "" {
		return "", fmt.Errorf("token: HTTP %d %s", response.StatusCode, body.Error)
	}
	return body.AccessToken, nil
}

func urlKindFor(c *catalog, endpoint string) *urlKind {
	for i, kind := range c.URLKinds {
		if strings.HasPrefix(endpoint, kind.PathPrefix) {
			return &c.URLKinds[i]
		}
	}
	return nil
}

// databricksFailed reports a failed Databricks check. A human looks at the
// refresh, so it never merges on its own, and the workflow fails the run.
func (r *refresher) databricksFailed(format string, args ...any) {
	r.note(format, args...)
	r.needsReview("a Databricks check failed")
}

// noteGitHubGateway reports gateway GitHub tools the GitHub catalog does not
// list. That catalog is pinned to github/github-mcp-server, which adds them.
func (r *refresher) noteGitHubGateway(label, githubCatalogPath string, tools []upstreamTool) {
	raw, err := os.ReadFile(githubCatalogPath)
	var catalog githubCatalog
	if err == nil {
		err = json.Unmarshal(raw, &catalog)
	}
	if err != nil {
		r.databricksFailed("- %s: check failed: %v", label, err)
		return
	}
	known := map[string]bool{}
	for _, t := range catalog.Tools {
		known[t.Name] = true
	}
	var unknown []string
	for _, t := range tools {
		if !known[t.name] {
			unknown = append(unknown, "`"+t.name+"`")
		}
	}
	if len(unknown) == 0 {
		r.note("- %s: %d tools, all in the GitHub catalog", label, len(tools))
		return
	}
	r.noteList(fmt.Sprintf("%s: not in the GitHub catalog (unrecognized until github/github-mcp-server serves them)", label), unknown)
}
