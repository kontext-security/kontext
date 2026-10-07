package shellprojection

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// Jira, Confluence and HubSpot facts mirror the MCP catalog tiers so one
// Cedar preset can forbid a tier on both surfaces. A shell call that reaches
// a provider carries its route fact, and every remote write also carries
// <product>/write=true; deletes and administration add a narrower fact on
// top. The values are shared with the cloud presets; renaming one is a
// contract change.
const (
	FactAtlassianRouteCatalogued   = "atlassian/route=catalogued"
	FactAtlassianRouteUnrecognized = "atlassian/route=unrecognized"
	FactHubSpotRouteCatalogued     = "hubspot/route=catalogued"
	FactHubSpotRouteUnrecognized   = "hubspot/route=unrecognized"

	productJira       = "jira"
	productConfluence = "confluence"
	productHubSpot    = "hubspot"
)

func writeFact(product string) string  { return product + "/write=true" }
func deleteFact(product string) string { return product + "/delete=true" }
func adminFact(product string) string  { return product + "/admin=true" }

// tierFacts renders a classified call. Delete and admin imply write, so a
// read-only preset needs only the write fact.
func tierFacts(product string, write, del, admin bool) []string {
	var facts []string
	if write || del || admin {
		facts = append(facts, writeFact(product))
	}
	if del {
		facts = append(facts, deleteFact(product))
	}
	if admin {
		facts = append(facts, adminFact(product))
	}
	return facts
}

func isAtlassianHost(host string) bool {
	return strings.HasSuffix(host, ".atlassian.net") || host == "api.atlassian.com" || strings.HasSuffix(host, ".jira.com")
}

func isHubSpotHost(host string) bool {
	return host == "hubapi.com" || strings.HasSuffix(host, ".hubapi.com") || host == "api.hubspot.com"
}

// Jira and Confluence answer some reads over POST (JQL search, bulk fetch);
// they stay reads. Every other non-GET method is a write.
var (
	jiraReadPost = regexp.MustCompile(`^/rest/api/(?:2|3|latest)/(?:search(?:/jql|/approximate-count)?|jql/(?:parse|match|autocompletedata/suggestions)|expression/(?:eval|evaluate|analyse)|issue/bulkfetch|changelog/bulkfetch|comment/list|worklog/list|permissions/(?:check|project)|issue/picker|field/search)/?$`)
	// Administration: project, scheme, workflow, field and user
	// configuration, plus site-wide settings.
	jiraAdminSegments = map[string]bool{
		"project": true, "projectCategory": true, "projectvalidate": true, "workflow": true, "workflows": true,
		"workflowscheme": true, "screens": true, "screenscheme": true, "issuetypescreenscheme": true,
		"issuetype": true, "issuetypescheme": true, "field": true, "fieldconfiguration": true,
		"fieldconfigurationscheme": true, "permissionscheme": true, "notificationscheme": true,
		"issuesecurityschemes": true, "securitylevel": true, "role": true, "priority": true,
		"priorityscheme": true, "resolution": true, "status": true, "statuses": true, "group": true,
		"user": true, "webhook": true, "application-properties": true, "configuration": true,
		"auditing": true, "permissions": true, "projects": true,
	}
	confluenceAdminSegments = map[string]bool{
		"space": true, "spaces": true, "restriction": true, "permissions": true, "permission": true,
		"settings": true, "group": true, "user": true, "admin-key": true, "classification-levels": true,
	}
	confluenceReadPost = regexp.MustCompile(`/(?:search|cql|convert|contentbody/convert/[^/]+)/?$`)
	cloudIDPrefix      = regexp.MustCompile(`^/ex/(jira|confluence)/[^/]+`)
)

// classifyAtlassianCurl classifies a literal request to an Atlassian Cloud
// site (`<site>.atlassian.net`) or the OAuth gateway (`api.atlassian.com/ex/
// jira|confluence/<cloudId>`). An incomplete parse, such as a body read from
// a file, is unrecognized.
func classifyAtlassianCurl(host string, parsed *url.URL, method string, complete bool) cedareval.ShellProjectionV2 {
	path := parsed.Path
	product := productJira
	if match := cloudIDPrefix.FindStringSubmatch(path); match != nil {
		product = match[1]
		path = strings.TrimPrefix(path, match[0])
	} else if host == "api.atlassian.com" {
		// Other gateway APIs (admin, graphql, teams) are not catalogued.
		return projection("curl", []string{"curl/host=" + host, "http/method=" + method, FactAtlassianRouteUnrecognized}, nil, false)
	}
	if strings.HasPrefix(path, "/wiki/") || path == "/wiki" {
		product = productConfluence
		path = strings.TrimPrefix(path, "/wiki")
	}
	facts := []string{"curl/host=" + host, "http/method=" + method, "http/path=" + parsed.EscapedPath()}
	if complete {
		facts = append(facts, FactAtlassianRouteCatalogued)
	} else {
		facts = append(facts, FactAtlassianRouteUnrecognized)
	}
	if isWriteMethod(method) {
		read := method == "POST" && (product == productJira && jiraReadPost.MatchString(path) ||
			product == productConfluence && confluenceReadPost.MatchString(path))
		if !read {
			admin := false
			if product == productJira {
				for _, segment := range apiResourceSegments(path) {
					admin = admin || jiraAdminSegments[segment]
				}
			} else {
				// Confluence nests restrictions and permissions under content.
				for _, segment := range strings.Split(path, "/") {
					admin = admin || confluenceAdminSegments[segment]
				}
			}
			facts = append(facts, tierFacts(product, true, method == "DELETE", admin)...)
		}
	}
	return projection("curl", facts, nil, complete)
}

// apiResourceSegments returns the path's first resource segment after the
// API prefix (/rest/api/3/, /rest/agile/1.0/, /api/v2/, /rest/api/), and
// for project-scoped routes the nested admin segment too, so
// /rest/api/3/project/ENG/role/10002 counts as administration.
func apiResourceSegments(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	start := 0
	for i, part := range parts {
		if part == "api" || part == "agile" || part == "servicedeskapi" {
			start = i + 1
			if start < len(parts) && (parts[start] == "2" || parts[start] == "3" || parts[start] == "latest" || parts[start] == "1.0" || parts[start] == "v2") {
				start++
			}
			break
		}
	}
	if start >= len(parts) {
		return nil
	}
	segments := []string{parts[start]}
	if parts[start] == "project" || parts[start] == "projects" || parts[start] == "space" || parts[start] == "spaces" {
		for _, nested := range parts[start+1:] {
			segments = append(segments, nested)
		}
	}
	return segments
}

var (
	hubspotAdminPrefixes = []string{
		"/crm/v3/properties", "/crm/v3/pipelines", "/crm/v3/schemas", "/crm-object-schemas",
		"/crm/v4/associations/definitions", "/properties/", "/crm-pipelines", "/settings/",
		"/webhooks/", "/automation/", "/account-info/", "/oauth/", "/integrations/",
	}
	hubspotAssociationLabels = regexp.MustCompile(`^/crm/v4/associations/[^/]+/[^/]+/labels`)
	hubspotDeleteSuffixes    = []string{"/batch/archive", "/gdpr-delete", "/purge"}
)

// classifyHubSpotCurl classifies a literal request to the HubSpot API. Search
// and batch-read endpoints are POST reads; archive and GDPR-delete endpoints
// are deletes whatever their method.
func classifyHubSpotCurl(host string, parsed *url.URL, method string, complete bool) cedareval.ShellProjectionV2 {
	path := strings.TrimSuffix(parsed.Path, "/")
	facts := []string{"curl/host=" + host, "http/method=" + method, "http/path=" + parsed.EscapedPath()}
	if complete {
		facts = append(facts, FactHubSpotRouteCatalogued)
	} else {
		facts = append(facts, FactHubSpotRouteUnrecognized)
	}
	if isWriteMethod(method) {
		read := method == "POST" && (strings.HasSuffix(path, "/search") || strings.HasSuffix(path, "/batch/read"))
		if !read {
			del := method == "DELETE" || hasSuffix(path, hubspotDeleteSuffixes...)
			admin := hasPrefix(path, hubspotAdminPrefixes...) || hubspotAssociationLabels.MatchString(path)
			facts = append(facts, tierFacts(productHubSpot, true, del, admin)...)
		}
	}
	return projection("curl", facts, nil, complete)
}

func hasSuffix(value string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

// verbCLI describes a `<program> [product] <noun...> <verb>` command line.
// The verb is the first positional word that is not a known noun. Only
// listed read verbs are reads; a listed write or delete verb is a catalogued
// write; anything else is an unrecognized write, so a new subcommand fails
// closed.
type verbCLI struct {
	program    string
	products   map[string]string // first word -> product; "" when the CLI has one product
	product    string            // the product when products is nil or the word is absent
	nouns      map[string]bool
	reads      map[string]bool
	writes     map[string]bool
	deletes    map[string]bool
	adminNouns map[string]bool
	catalogued string
	unknown    string
}

func words(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

// acli is Atlassian's official CLI (`acli jira workitem create`).
var acliCLI = verbCLI{
	program:  "acli",
	products: map[string]string{"jira": productJira, "confluence": productConfluence, "admin": productJira},
	product:  productJira,
	nouns: words("jira", "confluence", "admin", "workitem", "workitems", "comment", "comments", "attachment", "link", "watcher",
		"worklog", "project", "board", "sprint", "filter", "dashboard", "field", "space", "page", "blog", "user", "auth",
		"version", "component", "issue"),
	reads:      words("view", "list", "search", "get", "show", "help", "--help", "-h", "login", "logout", "status", "switch", "version", "--version"),
	writes:     words("create", "create-bulk", "edit", "update", "assign", "transition", "clone", "archive", "unarchive", "move", "add", "remove", "link", "unlink", "watch", "unwatch", "release", "start", "complete", "close", "activate", "deactivate"),
	deletes:    words("delete", "purge"),
	adminNouns: words("admin", "project", "field", "user", "space"),
	catalogued: FactAtlassianRouteCatalogued,
	unknown:    FactAtlassianRouteUnrecognized,
}

// jiraCLI covers the community `jira` binaries (ankitpokhrel/jira-cli,
// go-jira), which share the verb layout `jira [noun] <verb>`.
var jiraCLI = verbCLI{
	program:    "jira",
	product:    productJira,
	nouns:      words("issue", "issues", "epic", "epics", "sprint", "sprints", "project", "projects", "board", "boards", "release", "releases", "comment", "worklog"),
	reads:      words("list", "ls", "view", "show", "open", "browse", "me", "serverinfo", "init", "completion", "version", "help", "--help", "-h", "man", "fields", "issuetypes", "createmeta", "editmeta", "transmeta", "transitions", "components", "login", "logout"),
	writes:     words("create", "edit", "assign", "unassign", "move", "transition", "trans", "link", "unlink", "clone", "add", "remove", "watch", "vote", "unvote", "rank", "close", "resolve", "reopen", "start", "stop", "done", "todo", "backlog", "comment", "label", "labels", "worklog", "subtask", "dup", "block", "take", "give"),
	deletes:    words("delete", "del", "rm"),
	catalogued: FactAtlassianRouteCatalogued,
	unknown:    FactAtlassianRouteUnrecognized,
}

// hsCLI is the HubSpot developer CLI (`hs project deploy`). Local scaffolding
// and config commands (init, auth, lint) do not reach HubSpot and stay reads.
var hsCLI = verbCLI{
	program:    "hs",
	product:    productHubSpot,
	nouns:      words("accounts", "account", "project", "sandbox", "sandboxes", "secret", "secrets", "custom-object", "custom-objects", "schema", "hubdb", "filemanager", "function", "functions", "cms", "theme", "module", "app", "test-account", "config"),
	reads:      words("list", "ls", "info", "fetch", "fetch-all", "logs", "open", "help", "--help", "-h", "--version", "init", "auth", "use", "lint", "doctor", "completion", "list-builds", "validate", "get", "set", "migrate-config", "preview", "install-deps"),
	writes:     words("create", "upload", "watch", "deploy", "dev", "add", "update", "sync", "mv", "clear", "feedback", "cleanup", "rename", "migrate", "clone-app", "publish"),
	deletes:    words("delete", "remove", "clean"),
	adminNouns: words("secret", "secrets", "custom-object", "custom-objects", "schema", "sandbox", "sandboxes", "app", "test-account", "accounts", "account"),
	catalogued: FactHubSpotRouteCatalogued,
	unknown:    FactHubSpotRouteUnrecognized,
}

func (cli verbCLI) classify(args []string, complete bool) cedareval.ShellProjectionV2 {
	product := cli.product
	var nounsSeen []string
	verb := ""
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && !cli.reads[arg] {
			continue
		}
		if p, ok := cli.products[arg]; ok && len(nounsSeen) == 0 {
			product = p
			nounsSeen = append(nounsSeen, arg)
			continue
		}
		if cli.nouns[arg] && verb == "" && !(len(nounsSeen) > 0 && (cli.reads[arg] || cli.writes[arg] || cli.deletes[arg])) {
			nounsSeen = append(nounsSeen, arg)
			continue
		}
		verb = arg
		break
	}
	facts := []string{cli.program + "/command=" + strings.Join(append(nounsSeen, verb), "/")}
	admin := false
	for _, noun := range nounsSeen {
		admin = admin || cli.adminNouns[noun]
	}
	switch {
	case verb == "" && len(nounsSeen) == 0:
		// Bare program or flags only (help, version): no remote effect.
		facts = append(facts, cli.catalogued)
	case cli.reads[verb]:
		facts = append(facts, cli.catalogued)
	case cli.deletes[verb]:
		facts = append(facts, cli.catalogued)
		facts = append(facts, tierFacts(product, true, true, admin)...)
	case cli.writes[verb]:
		facts = append(facts, cli.catalogued)
		facts = append(facts, tierFacts(product, true, false, admin)...)
	default:
		facts = append(facts, cli.unknown)
		facts = append(facts, tierFacts(product, true, false, admin)...)
		complete = false
	}
	if !complete {
		facts = replaceFact(facts, cli.catalogued, cli.unknown)
	}
	return projection(cli.program, facts, nil, complete)
}
