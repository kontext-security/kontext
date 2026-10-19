package shellprojection

import (
	"encoding/json"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/toolcatalog"
)

// Databricks facts. A classified call carries the catalogued route, its
// product (reads too, so the secrets preset can block reading a secret) and
// the tier facts; an unknown command or route carries only the unrecognized
// route, so it fails open unless the opt-in guard preset is on. The values
// are shared with the cloud presets; renaming one is a contract change.
const (
	FactDatabricksRouteCatalogued   = "databricks/route=catalogued"
	FactDatabricksRouteUnrecognized = "databricks/route=unrecognized"

	productDatabricks       = "databricks"
	databricksProductPrefix = "databricks/product="
	databricksSQLProduct    = "sql"
	databricksSQLRoute      = "/api/2.0/sql/statements"
)

func databricksProductFact(product string) string { return databricksProductPrefix + product }

// databricksOperation is a classified call: its product and tier. del and
// admin can both hold (bundle destroy, or SQL that drops and grants).
type databricksOperation struct {
	product           string
	write, del, admin bool
	// sql marks a command whose positional arguments and stdin are SQL.
	sql bool
}

// raise adds what a flag makes a command do: its tiers, and its product when
// it names one.
func (op databricksOperation) raise(by databricksOperation) databricksOperation {
	if by.product != "" {
		op.product = by.product
	}
	op.write, op.del, op.admin = op.write || by.write, op.del || by.del, op.admin || by.admin
	return op
}

func databricksAccess(product, access string) databricksOperation {
	return databricksOperation{
		product: product,
		write:   access != toolcatalog.AccessRead,
		del:     access == toolcatalog.AccessDelete,
		admin:   access == toolcatalog.AccessAdmin,
	}
}

func (op databricksOperation) facts() []string {
	facts := []string{FactDatabricksRouteCatalogued}
	if op.product != "" {
		facts = append(facts, databricksProductFact(op.product))
	}
	return append(facts, tierFacts(productDatabricks, op.write, op.del, op.admin)...)
}

// raiseSQL applies the SQL check to each text; the strictest result wins.
// SQL that calls secret() is a secrets call, so the secrets preset blocks it
// and read-only-except-sql no longer exempts it.
func (op databricksOperation) raiseSQL(texts []string) databricksOperation {
	for _, text := range texts {
		deletes, admin, secrets, _ := toolcatalog.ClassifyDatabricksSQL(text)
		op.del, op.admin = op.del || deletes, op.admin || admin
		if secrets {
			op.product = "secrets"
		}
	}
	return op
}

const (
	dbRead  = toolcatalog.AccessRead
	dbWrite = toolcatalog.AccessWrite
	dbDel   = toolcatalog.AccessDelete
	dbAdmin = toolcatalog.AccessAdmin
)

// databricksCommands are the hand-written CLI commands the generated route
// table does not list, and the ones whose tier it states too loosely for a
// preset (bundle destroy deletes as well as administers). They take
// precedence over a generated command of the same path. Commands that only
// touch the local machine have no product. Running or deploying code is the
// execution product at write tier or above.
var databricksCommands = func() map[string]databricksOperation {
	table := map[string]databricksOperation{}
	for _, group := range []struct {
		op       databricksOperation
		commands []string
	}{
		{databricksOperation{}, []string{
			"help", "configure", "version", "cache clear",
			"auth login", "auth logout", "auth profiles", "auth switch", "auth describe",
			"auth docker host", "auth docker configure", "auth docker profile",
			"completion bash", "completion zsh", "completion fish", "completion powershell",
			"completion install", "completion uninstall", "completion status",
			"aitools install", "aitools update", "aitools uninstall", "aitools list", "aitools version",
			"aitools skills list", "aitools skills install",
			"experimental aitools install", "experimental aitools update", "experimental aitools uninstall",
			"experimental aitools list", "experimental aitools version",
			"experimental aitools skills list", "experimental aitools skills install", "experimental workspace open",
			"bundle init", "bundle schema", "bundle open", "bundle debug refschema", "bundle debug states",
			"bundle debug render-template-schema", "bundle debug list-targets", "bundle debug fetch-repository-info",
			"apps init", "apps manifest", "apps validate", "apps run-local", "pipelines init",
			"sandbox default", "sandbox set-default", "ssh setup", "air convert-to-dabs",
			"labs list", "labs show", "labs installed", "labs clear-cache",
		}},
		// They print credentials.
		{databricksAccess("secrets", dbRead), []string{"auth token", "auth env", "auth docker token"}},

		{databricksAccess("workloads", dbRead), []string{
			"bundle validate", "bundle summary", "bundle plan", "bundle config-remote-sync",
			"bundle generate job", "bundle generate pipeline", "bundle generate dashboard",
			"bundle generate alert", "bundle generate app", "bundle generate genie-space",
			"pipelines open", "pipelines logs", "pipelines history", "pipelines show", "pipelines generate", "apps logs",
		}},
		{databricksAccess("workloads", dbWrite), []string{
			"bundle deployment bind", "bundle deployment unbind", "bundle deployment migrate",
			"pipelines stop", "air images push",
		}},
		{databricksOperation{product: "workloads", write: true, del: true, admin: true}, []string{
			"bundle destroy", "pipelines destroy", "apps delete",
		}},

		{databricksAccess("execution", dbRead), []string{
			"sandbox list", "sandbox status", "sandbox ssh-key list", "air get", "air list", "air logs",
		}},
		{databricksAccess("execution", dbWrite), []string{
			"bundle run", "pipelines run", "pipelines dry-run", "apps dev-remote",
			"psql", "experimental postgres query",
			"sandbox create", "sandbox start", "sandbox stop", "sandbox register", "sandbox ssh", "sandbox config",
			"air run", "air cancel", "ssh connect", "ssh server", "ssh agent-shim",
			"labs install", "labs upgrade", "labs uninstall",
		}},
		{databricksAccess("execution", dbDel), []string{"sandbox delete", "sandbox ssh-key delete"}},
		// Deploys can set permissions.
		// apps import deploys the imported bundle and starts the app.
		{databricksAccess("execution", dbAdmin), []string{"bundle deploy", "pipelines deploy", "apps deploy", "apps import"}},

		{databricksAccess("data", dbRead), []string{"fs ls", "fs cat"}},
		{databricksAccess("data", dbWrite), []string{"fs mkdir", "fs mkdirs"}},
		{databricksAccess("data", dbDel), []string{"fs rm"}},
		{databricksAccess("data", dbWrite), []string{"fs cp"}},
		{databricksAccess("workspace", dbRead), []string{"workspace export-dir"}},
		{databricksAccess("workspace", dbWrite), []string{"workspace import-dir"}},
		// Sync mirrors local deletions to the workspace.
		{databricksAccess("workspace", dbDel), []string{"sync", "bundle sync"}},
		{databricksAccess("compute", dbRead), []string{
			"air pools list", "air pools get", "experimental aitools tools get-default-warehouse",
		}},

		{databricksOperation{product: databricksSQLProduct, write: true, sql: true}, []string{
			"experimental aitools tools query", "experimental aitools tools statement submit",
		}},
		{databricksAccess(databricksSQLProduct, dbRead), []string{
			"experimental aitools tools statement get", "experimental aitools tools statement status",
			"experimental aitools tools discover-schema",
		}},
		// genie ask starts a conversation that runs SQL, as genie
		// start-conversation does.
		{databricksAccess(databricksSQLProduct, dbWrite), []string{
			"experimental aitools tools statement cancel", "genie ask", "experimental genie ask",
		}},
	} {
		for _, command := range group.commands {
			if _, ok := table[command]; ok {
				panic("databricksCommands lists " + command + " twice")
			}
			table[command] = group.op
		}
	}
	return table
}()

// databricksFlagRaises are what a flag adds to a command: overwriting deletes
// the old content, apps import --cleanup deletes the old source folder, apps
// init can deploy and run the new app, auth describe --sensitive prints
// credentials, and bundle generate --bind binds the live resource.
var databricksFlagRaises = map[string]map[string]databricksOperation{
	"fs cp":                {"--overwrite": {del: true, write: true}},
	"workspace import-dir": {"--overwrite": {del: true, write: true}},
	"apps import":          {"--cleanup": {del: true, write: true}},
	"apps init": {
		"--deploy": databricksAccess("execution", dbAdmin),
		"--run":    databricksAccess("execution", dbWrite),
	},
	"auth describe": {"--sensitive": {product: "secrets"}},
	// --bind binds the generated config to the live resource, as bundle
	// deployment bind does.
	"bundle generate job":         {"--bind": databricksAccess("workloads", dbWrite), "-b": databricksAccess("workloads", dbWrite)},
	"bundle generate pipeline":    {"--bind": databricksAccess("workloads", dbWrite), "-b": databricksAccess("workloads", dbWrite)},
	"bundle generate dashboard":   {"--bind": databricksAccess("workloads", dbWrite), "-b": databricksAccess("workloads", dbWrite)},
	"bundle generate app":         {"--bind": databricksAccess("workloads", dbWrite), "-b": databricksAccess("workloads", dbWrite)},
	"bundle generate genie-space": {"--bind": databricksAccess("workloads", dbWrite), "-b": databricksAccess("workloads", dbWrite)},
}

// flagSet reports whether a flag is given with a value other than false or
// none.
func flagSet(args []string, flag string) bool {
	// "--" is not a terminator here: it may be an earlier option's value
	// (--log-file --), and reading a later word as a flag only raises.
	for _, arg := range args {
		if arg == flag {
			return true
		}
		if value, ok := strings.CutPrefix(arg, flag+"="); ok && flagValueTrue(value) {
			return true
		}
		// A short flag inside a cluster: -fb is -f -b, and -fb=v gives the
		// last letter the value. A letter after one that takes a value is
		// that value, but reading it as a flag only raises.
		if len(flag) == 2 && len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
			letters, value, hasValue := strings.Cut(arg[1:], "=")
			if at := strings.IndexByte(letters, flag[1]); at >= 0 && (!hasValue || at < len(letters)-1 || flagValueTrue(value)) {
				return true
			}
		}
	}
	return false
}

func flagValueTrue(value string) bool {
	switch strings.ToLower(value) {
	case "false", "f", "0", "none", "":
		return false
	}
	return true
}

// databricksValueFlags are the global flags that take a value. Cobra treats
// every other flag it does not know, while it looks for the command, as
// taking one too; only these booleans do not.
var (
	databricksValueFlags = words("-p", "--profile", "-o", "--output", "-t", "--target", "-e", "--environment",
		"--log-file", "--log-level", "--log-format", "--progress-format", "--var")
	databricksBoolFlags = words("--debug", "-h", "--help", "--version")
)

const databricksMaxCommandWords = 5

// classifyDatabricks classifies the Databricks CLI. It finds the command the
// way cobra does: flags are skipped wherever they appear, and a flag it does
// not know takes the next word as its value. The command is then looked up in
// databricksCommands and the generated route table; `databricks api` goes
// through the route table by method and path.
func classifyDatabricks(args []string, complete bool) cedareval.ShellProjectionV2 {
	var path []string
	var pathIndexes []int
	dynamic := false
	for i := 0; i < len(args) && len(path) < databricksMaxCommandWords; i++ {
		arg := args[i]
		switch {
		case arg == "--":
			i = len(args)
		case arg == "":
			// Cobra skips an empty word. A dynamic one (already incomplete)
			// may be a flag, so the command around it still counts.
			dynamic = true
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			if !strings.Contains(arg, "=") && !databricksBoolFlags[arg] && (strings.HasPrefix(arg, "--") || len(arg) == 2) {
				i++
			}
		default:
			path = append(path, arg)
			pathIndexes = append(pathIndexes, i)
		}
	}
	if len(path) == 0 && !dynamic {
		// Flags only (help, version): no Databricks request.
		return projection(productDatabricks, []string{FactDatabricksRouteCatalogued}, nil, complete)
	}
	if len(path) >= 2 && path[0] == "api" {
		return classifyDatabricksAPI(path[1], withoutIndexes(args, pathIndexes[:2]), complete)
	}
	// The longest hand-written command wins over a generated one of the
	// same or a shorter path, otherwise the first generated command found.
	var op databricksOperation
	length := 0
	for n := 1; n <= len(path); n++ {
		if entry, ok := databricksCommands[strings.Join(path[:n], " ")]; ok {
			op, length = entry, n
		}
	}
	for n := 1; n <= len(path); n++ {
		if generated, ok := toolcatalog.DatabricksCommand(strings.Join(path[:n-1], " "), path[n-1]); ok {
			if n > length {
				op, length = databricksAccess(generated.Product, generated.Access), n
			}
			break
		}
	}
	if length == 0 && len(path) > 0 && path[0] == "labs" {
		// labs <project> <command> runs the installed project's code.
		op, length = databricksAccess("execution", dbWrite), 1
	}
	if length == 0 {
		facts := []string{FactDatabricksRouteUnrecognized}
		if len(path) > 0 {
			facts = append(facts, productDatabricks+"/command="+strings.Join(path, "/"))
		}
		return projection(productDatabricks, facts, nil, false)
	}
	rest := withoutIndexes(args, pathIndexes[:length])
	command := strings.Join(path[:length], " ")
	if op.sql {
		op = op.raiseSQL(databricksSQLArgs(rest))
	}
	for flag, by := range databricksFlagRaises[command] {
		if flagSet(rest, flag) {
			op = op.raise(by)
		}
	}
	facts := append(op.facts(), productDatabricks+"/command="+strings.Join(path[:length], "/"))
	if !complete {
		facts = replaceFact(facts, FactDatabricksRouteCatalogued, FactDatabricksRouteUnrecognized)
	}
	return projection(productDatabricks, facts, nil, complete)
}

// withoutIndexes returns args minus the command words, as cobra passes them
// to the command's own flag parser.
func withoutIndexes(args []string, indexes []int) []string {
	out := make([]string, 0, len(args))
	next := 0
	for i, arg := range args {
		if next < len(indexes) && indexes[next] == i {
			next++
			continue
		}
		out = append(out, arg)
	}
	return out
}

// databricksSQLValueFlags are the flags of the SQL commands that take a value
// other than SQL. --file reads SQL the projection cannot see, so the call
// keeps its base tier.
var databricksSQLValueFlags = words("-w", "--warehouse", "-f", "--file", "--concurrency", "--param",
	"-p", "--profile", "-o", "--output", "-t", "--target", "-e", "--environment",
	"--log-file", "--log-level", "--log-format", "--progress-format")

// databricksSQLArgs returns every word of a SQL command that could be SQL:
// each positional argument, including one after a flag the projection does
// not know, since that flag may not take a value. A positional ending in .sql
// is read as a file when one exists and as SQL otherwise, so it is checked
// as SQL too; a real file name raises nothing.
func databricksSQLArgs(args []string) []string {
	var texts []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return withCleanedSQL(append(texts, args[i+1:]...))
		case databricksSQLValueFlags[arg]:
			i++
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
		default:
			texts = append(texts, arg)
		}
	}
	return withCleanedSQL(texts)
}

// withCleanedSQL adds each text as the CLI's cleanSQL sends it: trimmed, one
// pair of enclosing quotes removed, and lines starting with -- dropped. Both
// readings are checked, so quoting cannot hide a statement.
func withCleanedSQL(texts []string) []string {
	out := slices.Clone(texts)
	for _, text := range texts {
		text = strings.TrimSpace(text)
		if len(text) >= 2 && (text[0] == '"' && text[len(text)-1] == '"' || text[0] == '\'' && text[len(text)-1] == '\'') {
			text = text[1 : len(text)-1]
		}
		var lines []string
		for line := range strings.SplitSeq(text, "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "--") {
				lines = append(lines, line)
			}
		}
		out = append(out, strings.Join(lines, "\n"))
	}
	return out
}

// classifyDatabricksAPI classifies `databricks api <method> <path>`. The path
// may be a full URL; --json carries the body.
func classifyDatabricksAPI(method string, args []string, complete bool) cedareval.ShellProjectionV2 {
	method = strings.ToUpper(method)
	var target string
	var bodies []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value, isJSON := "", false
		switch {
		case arg == "--json" && i+1 < len(args):
			i++
			value, isJSON = args[i], true
		case strings.HasPrefix(arg, "--json="):
			value, isJSON = strings.TrimPrefix(arg, "--json="), true
		case databricksValueFlags[arg] || arg == "--workspace-id":
			i++
		case strings.HasPrefix(arg, "-"):
		case target == "":
			target = arg
		}
		if isJSON {
			bodies = append(bodies, value)
		}
	}
	parsed, err := url.Parse(target)
	if err != nil || target == "" || !strings.HasPrefix(parsed.Path, "/") {
		facts := []string{"databricks/command=api/" + strings.ToLower(method), FactDatabricksRouteUnrecognized}
		return projection(productDatabricks, facts, nil, false)
	}
	facts := []string{"databricks/command=api/" + strings.ToLower(method), "http/method=" + method, "http/path=" + parsed.EscapedPath()}
	routeFacts, known := databricksRouteFacts(method, parsed.Path, bodies)
	complete = complete && known
	facts = append(facts, routeFacts...)
	if !complete {
		facts = replaceFact(facts, FactDatabricksRouteCatalogued, FactDatabricksRouteUnrecognized)
	}
	return projection(productDatabricks, facts, nil, complete)
}

// classifyDatabricksCurl classifies a literal curl request to a Databricks
// workspace or account host.
func classifyDatabricksCurl(host string, parsed *url.URL, method string, bodies []string, complete bool) cedareval.ShellProjectionV2 {
	facts := []string{"curl/host=" + host, "http/method=" + method, "http/path=" + parsed.EscapedPath()}
	routeFacts, known := databricksRouteFacts(method, parsed.Path, bodies)
	complete = complete && known
	facts = append(facts, routeFacts...)
	if !complete {
		facts = replaceFact(facts, FactDatabricksRouteCatalogued, FactDatabricksRouteUnrecognized)
	}
	return projection("curl", facts, nil, complete)
}

// databricksRouteFacts looks a request up in the route table. Curl and the
// server resolve dot segments and repeated slashes, so the path is cleaned
// first. MCP endpoints
// carry their operation in a JSON-RPC body the projection does not read, so
// they are unrecognized. A POST to the SQL statements route raises its tier
// by the statements in its literal body pieces; a piece read from a file
// adds nothing, so SQL only in a file keeps the base tier.
func databricksRouteFacts(method, requestPath string, bodies []string) ([]string, bool) {
	if requestPath != "" {
		requestPath = path.Clean(requestPath)
	}
	if strings.HasPrefix(requestPath, "/api/2.0/mcp/") || strings.HasPrefix(requestPath, "/ai-gateway/mcp-services/") {
		return []string{FactDatabricksRouteUnrecognized}, false
	}
	route, ok := toolcatalog.DatabricksRoute(method, requestPath)
	if !ok {
		return []string{FactDatabricksRouteUnrecognized}, false
	}
	op := databricksAccess(route.Product, route.Access)
	if route.Method == "POST" && route.Path == databricksSQLRoute {
		statements, ok := databricksStatements(bodies)
		op = op.raiseSQL(statements)
		if !ok {
			// Too many pieces to join every way: assume the worst.
			op = op.raise(databricksOperation{product: "secrets", write: true, del: true, admin: true})
		}
	}
	return op.facts(), true
}

// databricksMaxBodyPieces bounds the joins databricksStatements tries.
const databricksMaxBodyPieces = 8

// databricksStatements returns every top-level "statement" string in the
// request body, matched case-insensitively and duplicates included, so a
// server that reads a different copy than Go would still has its copy
// checked. The body is assembled from its literal pieces: curl joins -d
// pieces with & and --json pieces with nothing, and the CLI keeps the last
// --json, so each piece alone and every join of the pieces is read. A piece
// read from a file (@name) is unknown and read as empty. Past
// databricksMaxBodyPieces only each piece and the two uniform joins are
// read, and ok is false.
func databricksStatements(bodies []string) (statements []string, ok bool) {
	var pieces []string
	for _, body := range bodies {
		if !strings.HasPrefix(body, "@") {
			pieces = append(pieces, body)
		}
	}
	candidates := append(slices.Clone(pieces), strings.Join(pieces, ""), strings.Join(pieces, "&"))
	ok = len(pieces) <= databricksMaxBodyPieces
	for mask := 0; ok && len(pieces) > 1 && mask < 1<<(len(pieces)-1); mask++ {
		var joined strings.Builder
		for i, piece := range pieces {
			if i > 0 && mask&(1<<(i-1)) != 0 {
				joined.WriteByte('&')
			}
			joined.WriteString(piece)
		}
		candidates = append(candidates, joined.String())
	}
	for _, body := range candidates {
		statements = append(statements, jsonStatements(body)...)
	}
	return statements, ok
}

func jsonStatements(body string) []string {
	var statements []string
	decoder := json.NewDecoder(strings.NewReader(body))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			break
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			break
		}
		var statement string
		if name, ok := key.(string); ok && strings.EqualFold(name, "statement") && json.Unmarshal(value, &statement) == nil {
			statements = append(statements, statement)
		}
	}
	return statements
}

// mergeDatabricksProducts keeps a curl command that requests several URLs from
// borrowing the SQL exemption: once the merged facts name another product
// too, the SQL product fact is dropped, so read-only-except-sql judges the
// other requests' writes.
func mergeDatabricksProducts(facts []string) []string {
	sql := databricksProductFact(databricksSQLProduct)
	other := slices.ContainsFunc(facts, func(fact string) bool {
		return strings.HasPrefix(fact, databricksProductPrefix) && fact != sql
	})
	if !other {
		return facts
	}
	return slices.DeleteFunc(facts, func(fact string) bool { return fact == sql })
}

// databricksDomains are the domains in a URL that may name a Databricks host.
var databricksDomains = []string{"databricks.com", "azuredatabricks.net", "databricks.us", "databricks.mil", "databricks.azure.us", "databricks.azure.cn"}

// databricksUnreadableURLFacts are the facts of a curl URL the projection
// cannot read (it does not parse, or a glob is too large to expand) that
// names a Databricks domain: it could reach any route, so it carries every
// tier and the products the presets single out.
func databricksUnreadableURLFacts(urlText string) []string {
	text := strings.ToLower(urlText)
	if decoded, err := url.PathUnescape(text); err == nil {
		text = decoded
	}
	if !slices.ContainsFunc(databricksDomains, func(domain string) bool { return strings.Contains(text, domain) }) {
		return nil
	}
	return []string{FactDatabricksRouteUnrecognized, databricksProductFact("secrets"), databricksProductFact("execution"),
		writeFact(productDatabricks), deleteFact(productDatabricks), adminFact(productDatabricks)}
}
