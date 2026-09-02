package shellprojection

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// GitHub operation facts name the verb-object effect a shell call has on
// GitHub so a Cedar preset can forbid one effect with a single
// facts.contains. A call can carry several (`gh pr merge --delete-branch`
// merges and deletes a ref). The values are shared with the cloud templates;
// renaming one is a contract change.
const (
	factOperationPrefix = "github/operation="

	OperationForcePush            = "force-push"
	OperationForcePushWithLease   = "force-push-with-lease"
	OperationDeleteRef            = "delete-ref"
	OperationMoveTag              = "move-tag"
	OperationUpdateRef            = "update-ref"
	OperationMergePullRequest     = "merge-pull-request"
	OperationEnableAutoMerge      = "enable-auto-merge"
	OperationDisableAutoMerge     = "disable-auto-merge"
	OperationMergeBranch          = "merge-branch"
	OperationApprovePullRequest   = "approve-pull-request"
	OperationCreateRelease        = "create-release"
	OperationEditRelease          = "edit-release"
	OperationDeleteRelease        = "delete-release"
	OperationUploadReleaseAsset   = "upload-release-asset"
	OperationRunWorkflow          = "run-workflow"
	OperationRerunWorkflowRun     = "rerun-workflow-run"
	OperationCancelWorkflowRun    = "cancel-workflow-run"
	OperationApproveWorkflowRun   = "approve-workflow-run"
	OperationDeleteWorkflowRun    = "delete-workflow-run"
	OperationEnableWorkflow       = "enable-workflow"
	OperationDisableWorkflow      = "disable-workflow"
	OperationEditRepository       = "edit-repository"
	OperationDeleteRepository     = "delete-repository"
	OperationTransferRepository   = "transfer-repository"
	OperationEditBranchProtection = "edit-branch-protection"
	OperationEditEnvironment      = "edit-environment"
	OperationEditCollaborators    = "edit-collaborators"
	OperationEditWebhooks         = "edit-webhooks"
	OperationEditDeployKeys       = "edit-deploy-keys"
	OperationEditSecrets          = "edit-secrets"
	// OperationOtherWrite marks a catalogued GitHub write no row above
	// names, so a strict custom policy can deny "every other write" without
	// the read-only preset.
	OperationOtherWrite = "other-write"

	// FeatureOperationFromRoute marks operations derived from a REST
	// method and path; FeatureOperationFromGraphQL from a literal GraphQL
	// mutation; FeatureGraphQLNotLiteral a GraphQL call whose query text
	// could not be read (file, variable, --input).
	FeatureOperationFromRoute   = "github-operation-from-route"
	FeatureOperationFromGraphQL = "github-operation-from-graphql"
	FeatureGraphQLNotLiteral    = "graphql-query-not-literal"

	hostGitHubAPI     = "api.github.com"
	hostGitHubUploads = "uploads.github.com"
)

// OperationFact renders an operation as the fact string Cedar matches.
func OperationFact(operation string) string {
	return factOperationPrefix + operation
}

func operationFacts(operations []string) []string {
	facts := make([]string, 0, len(operations))
	for _, operation := range operations {
		facts = append(facts, OperationFact(operation))
	}
	return facts
}

// ghCommandOperations maps a gh command key (see classifyGH) to the
// operations it always performs. Flag-sensitive commands are refined by
// ghOperations. A write key absent here is other-write.
var ghCommandOperations = map[string][]string{
	"pr/merge":               {OperationMergePullRequest},
	"release/create":         {OperationCreateRelease},
	"release/edit":           {OperationEditRelease},
	"release/delete":         {OperationDeleteRelease},
	"release/delete-asset":   {OperationDeleteRelease},
	"release/upload":         {OperationUploadReleaseAsset},
	"workflow/run":           {OperationRunWorkflow},
	"workflow/enable":        {OperationEnableWorkflow},
	"workflow/disable":       {OperationDisableWorkflow},
	"run/rerun":              {OperationRerunWorkflowRun},
	"run/cancel":             {OperationCancelWorkflowRun},
	"run/delete":             {OperationDeleteWorkflowRun},
	"repo/edit":              {OperationEditRepository},
	"repo/rename":            {OperationEditRepository},
	"repo/archive":           {OperationEditRepository},
	"repo/unarchive":         {OperationEditRepository},
	"repo/autolink/create":   {OperationEditRepository},
	"repo/autolink/delete":   {OperationEditRepository},
	"repo/delete":            {OperationDeleteRepository},
	"repo/deploy-key/add":    {OperationEditDeployKeys},
	"repo/deploy-key/delete": {OperationEditDeployKeys},
	"secret/set":             {OperationEditSecrets},
	"secret/delete":          {OperationEditSecrets},
	"variable/set":           {OperationEditSecrets},
	"variable/delete":        {OperationEditSecrets},
}

// ghOperations classifies a non-api gh write command from its key and the
// literal arguments after the key words.
func ghOperations(key string, rest []string) []string {
	flags := ghFlags(rest)
	var operations []string
	switch key {
	case "pr/merge":
		switch {
		case flags["--auto"]:
			operations = append(operations, OperationEnableAutoMerge)
		case flags["--disable-auto"]:
			operations = append(operations, OperationDisableAutoMerge)
		default:
			operations = append(operations, OperationMergePullRequest)
		}
		if flags["-d"] || flags["--delete-branch"] {
			operations = append(operations, OperationDeleteRef)
		}
	case "pr/review":
		if flags["-a"] || flags["--approve"] {
			operations = append(operations, OperationApprovePullRequest)
		}
	case "release/delete":
		operations = append(operations, OperationDeleteRelease)
		if flags["--cleanup-tag"] {
			operations = append(operations, OperationDeleteRef)
		}
	case "repo/sync":
		if flags["--force"] {
			operations = append(operations, OperationForcePush)
		}
	default:
		operations = append(operations, ghCommandOperations[key]...)
	}
	if len(operations) == 0 {
		operations = append(operations, OperationOtherWrite)
	}
	return operations
}

// ghFlags collects the option words of a gh command, expanding clustered
// short flags (`-ds` is `-d -s`) and dropping `--option=value` values, so
// flag-sensitive operations can test presence. Option values that happen
// to look like flags are counted too; the projection prefers to over-report
// an effect rather than miss one.
func ghFlags(args []string) map[string]bool {
	flags := make(map[string]bool, len(args))
	for _, arg := range args {
		if arg == "--" {
			break
		}
		switch {
		case strings.HasPrefix(arg, "--"):
			name, _, _ := strings.Cut(arg, "=")
			flags[name] = true
		case shortFlagCluster.MatchString(arg):
			for _, flag := range arg[1:] {
				flags["-"+string(flag)] = true
			}
		case strings.HasPrefix(arg, "-") && arg != "-":
			flags[arg] = true
		}
	}
	return flags
}

// hasDeleteRefspec reports a push refspec with an empty source (`:branch`,
// `+:refs/tags/v1`): git deletes the destination. A bare `:` pushes matching
// branches and is not a deletion.
func hasDeleteRefspec(refspecs []string) bool {
	for _, refspec := range refspecs {
		trimmed := strings.TrimPrefix(refspec, "+")
		if strings.HasPrefix(trimmed, ":") && len(trimmed) > 1 {
			return true
		}
	}
	return false
}

func hasForceWithLease(options []string) bool {
	return hasArg(options, "--force-with-lease", "--force-if-includes") || hasPrefixArg(options, "--force-with-lease=")
}

func hasPrefixArg(args []string, prefix string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	return false
}

// githubRoute is one row of the REST route table. `*` matches exactly one
// non-empty path segment, `**` one or more trailing segments; every other
// segment must match literally, so `pulls/x/merge-ish` never matches
// `pulls/*/merge`. Host "" is api.github.com.
type githubRoute struct {
	host      string
	methods   []string
	pattern   []string
	operation string
}

func route(methods, pattern, operation string) githubRoute {
	return githubRoute{methods: strings.Fields(methods), pattern: strings.Split(pattern, "/"), operation: operation}
}

func uploadsRoute(methods, pattern, operation string) githubRoute {
	r := route(methods, pattern, operation)
	r.host = hostGitHubUploads
	return r
}

var githubRoutes = []githubRoute{
	// Git refs. PATCH is handled in githubRouteOperations because force and
	// tag detection decide between several operations.
	route("DELETE", "repos/*/*/git/refs/**", OperationDeleteRef),

	// Merging.
	route("PUT", "repos/*/*/pulls/*/merge", OperationMergePullRequest),
	route("POST", "repos/*/*/merges", OperationMergeBranch),
	route("POST", "repos/*/*/merge-upstream", OperationMergeBranch),

	// Releases. `curl -T` sends PUT to the uploads host, so both verbs count.
	route("POST", "repos/*/*/releases", OperationCreateRelease),
	route("PATCH", "repos/*/*/releases/*", OperationEditRelease),
	route("PATCH", "repos/*/*/releases/assets/*", OperationEditRelease),
	route("DELETE", "repos/*/*/releases/*", OperationDeleteRelease),
	route("DELETE", "repos/*/*/releases/assets/*", OperationDeleteRelease),
	uploadsRoute("POST PUT", "repos/*/*/releases/*/assets", OperationUploadReleaseAsset),

	// Actions.
	route("POST", "repos/*/*/actions/workflows/*/dispatches", OperationRunWorkflow),
	route("POST", "repos/*/*/dispatches", OperationRunWorkflow),
	route("POST", "repos/*/*/actions/runs/*/rerun", OperationRerunWorkflowRun),
	route("POST", "repos/*/*/actions/runs/*/rerun-failed-jobs", OperationRerunWorkflowRun),
	route("POST", "repos/*/*/actions/jobs/*/rerun", OperationRerunWorkflowRun),
	route("POST", "repos/*/*/actions/runs/*/cancel", OperationCancelWorkflowRun),
	route("POST", "repos/*/*/actions/runs/*/force-cancel", OperationCancelWorkflowRun),
	route("POST", "repos/*/*/actions/runs/*/approve", OperationApproveWorkflowRun),
	route("POST", "repos/*/*/actions/runs/*/pending_deployments", OperationApproveWorkflowRun),
	route("POST", "repos/*/*/actions/runs/*/deployment_protection_rule", OperationApproveWorkflowRun),
	route("DELETE", "repos/*/*/actions/runs/*", OperationDeleteWorkflowRun),
	route("DELETE", "repos/*/*/actions/runs/*/logs", OperationDeleteWorkflowRun),
	route("DELETE", "repos/*/*/actions/artifacts/*", OperationDeleteWorkflowRun),
	route("PUT", "repos/*/*/actions/workflows/*/enable", OperationEnableWorkflow),
	route("PUT", "repos/*/*/actions/workflows/*/disable", OperationDisableWorkflow),

	// Repository settings.
	route("PATCH", "repos/*/*", OperationEditRepository),
	route("PUT", "repos/*/*/topics", OperationEditRepository),
	route("PUT DELETE", "repos/*/*/automated-security-fixes", OperationEditRepository),
	route("PUT DELETE", "repos/*/*/vulnerability-alerts", OperationEditRepository),
	route("PUT DELETE", "repos/*/*/private-vulnerability-reporting", OperationEditRepository),
	route("PUT", "repos/*/*/actions/permissions", OperationEditRepository),
	route("PUT", "repos/*/*/actions/permissions/**", OperationEditRepository),
	route("PUT DELETE", "repos/*/*/interaction-limits", OperationEditRepository),
	route("POST PUT DELETE", "repos/*/*/pages", OperationEditRepository),
	route("POST PUT DELETE", "repos/*/*/pages/**", OperationEditRepository),
	route("PUT", "repos/*/*/actions/oidc/**", OperationEditRepository),
	route("POST PATCH DELETE", "repos/*/*/autolinks", OperationEditRepository),
	route("POST PATCH DELETE", "repos/*/*/autolinks/**", OperationEditRepository),
	route("PATCH", "repos/*/*/code-scanning/default-setup", OperationEditRepository),
	route("DELETE", "repos/*/*", OperationDeleteRepository),
	route("POST", "repos/*/*/transfer", OperationTransferRepository),

	// Branch protection and rulesets.
	route("PUT PATCH POST DELETE", "repos/*/*/branches/*/protection", OperationEditBranchProtection),
	route("PUT PATCH POST DELETE", "repos/*/*/branches/*/protection/**", OperationEditBranchProtection),
	route("POST PUT DELETE", "repos/*/*/rulesets", OperationEditBranchProtection),
	route("POST PUT DELETE", "repos/*/*/rulesets/**", OperationEditBranchProtection),
	route("POST", "repos/*/*/branches/*/rename", OperationEditBranchProtection),

	// Environments.
	route("PUT DELETE", "repos/*/*/environments/*", OperationEditEnvironment),
	route("POST PUT DELETE", "repos/*/*/environments/*/deployment-branch-policies", OperationEditEnvironment),
	route("POST PUT DELETE", "repos/*/*/environments/*/deployment-branch-policies/**", OperationEditEnvironment),
	route("POST DELETE", "repos/*/*/environments/*/deployment_protection_rules", OperationEditEnvironment),
	route("POST DELETE", "repos/*/*/environments/*/deployment_protection_rules/**", OperationEditEnvironment),

	// Access.
	route("PUT DELETE", "repos/*/*/collaborators/*", OperationEditCollaborators),
	route("PATCH DELETE", "repos/*/*/invitations/*", OperationEditCollaborators),
	route("PUT DELETE", "orgs/*/teams/*/repos/*/*", OperationEditCollaborators),
	route("PUT DELETE", "user/installations/*/repositories/*", OperationEditCollaborators),

	// Integrations.
	route("POST PATCH DELETE", "repos/*/*/hooks", OperationEditWebhooks),
	route("POST PATCH DELETE", "repos/*/*/hooks/**", OperationEditWebhooks),
	route("POST DELETE", "repos/*/*/keys", OperationEditDeployKeys),
	route("POST DELETE", "repos/*/*/keys/**", OperationEditDeployKeys),

	// Secrets and variables.
	route("PUT DELETE", "repos/*/*/actions/secrets/**", OperationEditSecrets),
	route("POST PATCH DELETE", "repos/*/*/actions/variables", OperationEditSecrets),
	route("POST PATCH DELETE", "repos/*/*/actions/variables/**", OperationEditSecrets),
	route("PUT DELETE", "repos/*/*/dependabot/secrets/**", OperationEditSecrets),
	route("PUT DELETE", "repos/*/*/codespaces/secrets/**", OperationEditSecrets),
	route("PUT DELETE", "repos/*/*/environments/*/secrets/**", OperationEditSecrets),
	route("POST PATCH DELETE", "repos/*/*/environments/*/variables", OperationEditSecrets),
	route("POST PATCH DELETE", "repos/*/*/environments/*/variables/**", OperationEditSecrets),
	route("PUT DELETE", "orgs/*/actions/secrets/**", OperationEditSecrets),
	route("POST PATCH DELETE", "orgs/*/actions/variables", OperationEditSecrets),
	route("POST PATCH DELETE", "orgs/*/actions/variables/**", OperationEditSecrets),
	route("PUT DELETE", "orgs/*/dependabot/secrets/**", OperationEditSecrets),
	route("PUT DELETE", "orgs/*/codespaces/secrets/**", OperationEditSecrets),
	route("PUT DELETE", "user/codespaces/secrets/**", OperationEditSecrets),
}

func (r githubRoute) matches(host, method string, segments []string) bool {
	routeHost := r.host
	if routeHost == "" {
		routeHost = hostGitHubAPI
	}
	if routeHost != host || !hasArg(r.methods, method) {
		return false
	}
	return matchSegments(r.pattern, segments)
}

func matchSegments(pattern, segments []string) bool {
	for i, part := range pattern {
		if part == "**" {
			return len(segments) > i
		}
		if i >= len(segments) || segments[i] == "" {
			return false
		}
		if part != "*" && part != segments[i] {
			return false
		}
	}
	return len(segments) == len(pattern)
}

var gitRefsPattern = []string{"repos", "*", "*", "git", "refs", "**"}
var pullReviewPatterns = [][]string{
	{"repos", "*", "*", "pulls", "*", "reviews"},
	{"repos", "*", "*", "pulls", "*", "reviews", "*", "events"},
}

// githubRouteOperations classifies a REST call to api.github.com or
// uploads.github.com. force is the caller's existing force-push detection;
// approve reports a literal event=APPROVE in the request body.
func githubRouteOperations(host, method string, segments []string, force, approve bool) []string {
	var operations []string
	matched := false
	if force {
		operations = append(operations, OperationForcePush)
		matched = true
	}
	if host == hostGitHubAPI && method == "PATCH" && matchSegments(gitRefsPattern, segments) {
		switch segments[5] {
		case "tags":
			operations = append(operations, OperationMoveTag)
			matched = true
		case "heads":
			if !force {
				operations = append(operations, OperationUpdateRef)
			}
			matched = true
		}
	}
	if host == hostGitHubAPI && method == "POST" && approve {
		for _, pattern := range pullReviewPatterns {
			if matchSegments(pattern, segments) {
				operations = append(operations, OperationApprovePullRequest)
				matched = true
			}
		}
	}
	for _, r := range githubRoutes {
		if r.matches(host, method, segments) {
			operations = append(operations, r.operation)
			matched = true
		}
	}
	if !matched && isWriteMethod(method) {
		operations = append(operations, OperationOtherWrite)
	}
	return operations
}

// githubAPISegments normalises a `gh api` path or a full GitHub URL into
// host and path segments. A full URL on another host is not a GitHub API
// call the route table can classify.
func githubAPISegments(path string) (host string, segments []string, ok bool) {
	host = hostGitHubAPI
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		parsed, err := url.Parse(path)
		if err != nil {
			return "", nil, false
		}
		host = strings.ToLower(parsed.Hostname())
		if host != hostGitHubAPI && host != hostGitHubUploads {
			return "", nil, false
		}
		path = parsed.EscapedPath()
	}
	path, _, _ = strings.Cut(path, "?")
	path, _, _ = strings.Cut(path, "#")
	return host, pathSegments(path), true
}

func pathSegments(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

// graphqlMutationOperations maps GraphQL mutation names to operations. Names
// that need the query body (updateRef, review submissions) are handled in
// graphqlOperations.
var graphqlMutationOperations = map[string]string{
	"deleteRef":                   OperationDeleteRef,
	"mergePullRequest":            OperationMergePullRequest,
	"enqueuePullRequest":          OperationMergePullRequest,
	"enablePullRequestAutoMerge":  OperationEnableAutoMerge,
	"disablePullRequestAutoMerge": OperationDisableAutoMerge,
	"createRelease":               OperationCreateRelease,
	"updateRepository":            OperationEditRepository,
	"archiveRepository":           OperationEditRepository,
	"unarchiveRepository":         OperationEditRepository,
	"transferRepository":          OperationTransferRepository,
	"createBranchProtectionRule":  OperationEditBranchProtection,
	"updateBranchProtectionRule":  OperationEditBranchProtection,
	"deleteBranchProtectionRule":  OperationEditBranchProtection,
	"createRepositoryRuleset":     OperationEditBranchProtection,
	"updateRepositoryRuleset":     OperationEditBranchProtection,
	"deleteRepositoryRuleset":     OperationEditBranchProtection,
}

var (
	graphqlMutationKeyword = regexp.MustCompile(`\bmutation\b`)
	graphqlFieldCall       = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	graphqlForceLiteral    = regexp.MustCompile(`\bforce\s*:\s*true\b`)
	graphqlApproveLiteral  = regexp.MustCompile(`\bevent\s*:\s*APPROVE\b`)
)

// graphqlOperations classifies a literal GraphQL document. Only the
// top-level fields of each `mutation { … }` body count; a document without
// a mutation is a read and yields nothing.
func graphqlOperations(query string) []string {
	names := graphqlMutationFields(query)
	if len(names) == 0 {
		return nil
	}
	force := graphqlForceLiteral.MatchString(query)
	approve := graphqlApproveLiteral.MatchString(query)
	tag := strings.Contains(query, "refs/tags/")
	var operations []string
	for _, name := range names {
		switch name {
		case "updateRef":
			switch {
			case force:
				operations = append(operations, OperationForcePush)
				if tag {
					operations = append(operations, OperationMoveTag)
				}
			case tag:
				operations = append(operations, OperationMoveTag)
			default:
				operations = append(operations, OperationUpdateRef)
			}
		case "addPullRequestReview", "submitPullRequestReview":
			if approve {
				operations = append(operations, OperationApprovePullRequest)
			} else {
				operations = append(operations, OperationOtherWrite)
			}
		default:
			if operation, ok := graphqlMutationOperations[name]; ok {
				operations = append(operations, operation)
			} else {
				operations = append(operations, OperationOtherWrite)
			}
		}
	}
	return operations
}

// graphqlMutationFields returns the field names called at the top level of
// every mutation body in the document, in order.
func graphqlMutationFields(query string) []string {
	var names []string
	rest := blankGraphqlNoise(query)
	for {
		loc := graphqlMutationKeyword.FindStringIndex(rest)
		if loc == nil {
			return names
		}
		rest = rest[loc[1]:]
		open := strings.Index(rest, "{")
		if open < 0 {
			return names
		}
		body, end := topLevelBody(rest[open:])
		for _, match := range graphqlFieldCall.FindAllStringSubmatch(body, -1) {
			names = append(names, match[1])
		}
		rest = rest[open+end:]
	}
}

// blankGraphqlNoise replaces comments (# to end of line), string literals and
// block strings with spaces, so neither a `# mutation {` comment nor a string
// argument can pose as an operation or open a brace the parser then follows.
func blankGraphqlNoise(query string) string {
	out := []byte(query)
	for i := 0; i < len(out); {
		switch {
		case out[i] == '#':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case strings.HasPrefix(string(out[i:]), `"""`):
			end := strings.Index(string(out[i+3:]), `"""`)
			stop := len(out)
			if end >= 0 {
				stop = i + 3 + end + 3
			}
			for ; i < stop; i++ {
				out[i] = ' '
			}
		case out[i] == '"':
			out[i] = ' '
			i++
			for i < len(out) && out[i] != '"' {
				if out[i] == '\\' && i+1 < len(out) {
					out[i] = ' '
					i++
				}
				out[i] = ' '
				i++
			}
			if i < len(out) {
				out[i] = ' '
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}

// topLevelBody returns the text at brace depth one of the block that starts
// at text[0] == '{', with nested blocks and string literals blanked out, and
// the offset just past the closing brace.
func topLevelBody(text string) (string, int) {
	var out strings.Builder
	depth := 0
	inString := false
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if inString {
			if ch == '\\' && i+1 < len(text) {
				i++
			} else if ch == '"' {
				inString = false
			}
			out.WriteByte(' ')
			continue
		}
		switch ch {
		case '"':
			inString = true
			out.WriteByte(' ')
		case '{':
			depth++
			out.WriteByte(' ')
		case '}':
			depth--
			out.WriteByte(' ')
			if depth == 0 {
				return out.String(), i + 1
			}
		default:
			if depth == 1 {
				out.WriteByte(ch)
			} else {
				out.WriteByte(' ')
			}
		}
	}
	return out.String(), len(text)
}

// graphqlQueryText finds the literal query in gh api fields (`query=…`) or
// curl bodies (`{"query": "…"}`, `query=…`). ok is false when no literal
// query is present: a file reference, a variable, or an --input body.
func graphqlQueryText(values []string) (string, bool) {
	for _, value := range values {
		if query, found := strings.CutPrefix(value, "query="); found {
			if query == "" || strings.HasPrefix(query, "@") {
				return "", false
			}
			return query, true
		}
		var body map[string]any
		if json.Unmarshal([]byte(value), &body) == nil {
			if query, isString := body["query"].(string); isString && query != "" {
				return query, true
			}
		}
	}
	return "", false
}

// bodyHasField reports a request field with a literal string value, in gh
// `key=value` form or inside a JSON body.
func bodyHasField(values []string, key, want string) bool {
	for _, value := range values {
		if value == key+"="+want {
			return true
		}
		var body map[string]any
		if json.Unmarshal([]byte(value), &body) == nil {
			if got, isString := body[key].(string); isString && got == want {
				return true
			}
		}
	}
	return false
}
