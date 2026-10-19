package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// The Databricks route table (internal/toolcatalog/databricks-routes.json)
// maps every Databricks REST operation to a product and an access tier, and
// every generated CLI command to the operation it calls. The Databricks CLI,
// `databricks api` and curl are classified from the same table.
//
// The generator reads two pinned upstream sources as Go source and never
// executes them: the databricks/cli release in databricksCLIVersion and the
// databricks-sdk-go version that release's go.mod requires.
//
//   - SDK service/*/impl.go gives each operation's HTTP method and path.
//   - SDK workspace_client.go and account_client.go map a client field
//     (w.Clusters) to the service that implements it.
//   - CLI cmd/workspace and cmd/account give each `<group> <verb>` command
//     and the SDK call it makes.
//
// Tiers: a GET or HEAD is read unless databricksConsumingGets lists it; a
// POST is read only when databricksPostReads lists it, so a new route is a
// write until someone reviews it. Anything that acts on permissions,
// grants, identities, settings or account provisioning (product admin),
// whose request body can carry an owner, permissions, an access control
// list or grants (one generic rule, computed fields aside), or that
// databricksAdminOperations lists, is admin; a delete (by method, name or
// databricksDeleteOperations) is delete; everything else is write. Products
// are assigned per operation from databricksServiceProducts and
// databricksOperationProducts, and a service neither lists fails
// generation so a reviewer has to place it.

const (
	databricksCLIVersion = "v1.21.0"
	databricksCLIModule  = "github.com/databricks/cli"
	databricksSDKModule  = "github.com/databricks/databricks-sdk-go"
)

type databricksTable struct {
	CLI string `json:"cli"`
	SDK string `json:"sdk"`
	// Rules fingerprints the reviewed rules below, so a test catches a rule
	// change that was not regenerated into the table.
	Rules  string            `json:"rules"`
	Routes []databricksEntry `json:"routes"`
}

// databricksRulesFingerprint hashes every reviewed rule the table is built
// from. encoding/json sorts map keys, so the hash is stable.
func databricksRulesFingerprint() string {
	rules, err := json.Marshal(map[string]any{
		"adminField":        databricksAdminField.String(),
		"adminOperations":   databricksAdminOperations,
		"aliases":           databricksCommandAliases,
		"consumingGets":     databricksConsumingGets,
		"delete":            databricksDelete.String(),
		"deleteOperations":  databricksDeleteOperations,
		"handCommands":      databricksHandCommands,
		"operationProducts": databricksOperationProducts,
		"outputField":       databricksOutputField.String(),
		"permission":        databricksPermission.String(),
		"postReads":         databricksPostReads,
		"serviceProducts":   databricksServiceProducts,
	})
	if err != nil {
		panic(err)
	}
	return fingerprint(rules)
}

// databricksEntry is one operation. Hand-kept CLI commands that call no
// single route (bundle deploy) have no method or path.
type databricksEntry struct {
	Operation string   `json:"operation"`
	Client    string   `json:"client,omitempty"`
	Method    string   `json:"method,omitempty"`
	Path      string   `json:"path,omitempty"`
	Commands  []string `json:"commands,omitempty"`
	Product   string   `json:"product"`
	Access    string   `json:"access"`
	// AdminFields are the request body fields (dotted JSON paths) that can
	// change an owner or permissions; they made the operation admin.
	AdminFields []string `json:"adminFields,omitempty"`
}

// sourceTree holds an upstream repository's Go files by repository path.
type sourceTree map[string][]byte

type sdkOperation struct {
	id         string // compute.Clusters.Delete
	service    string // compute.Clusters
	name       string // Delete
	method     string
	path       string
	account    bool
	bodyFields []string
}

var (
	databricksAdminField = regexp.MustCompile(`^(owner|owner_[a-z_]+|[a-z_]+_owner|permissions|[a-z_]+_permissions|access_control_list|grants)$`)
	// databricksOutputField matches fields the server computes and ignores
	// on write: effective_* values and an AIP resource's status block.
	databricksOutputField = regexp.MustCompile(`(^|\.)effective_[a-z_]+$|(^|\.)status\.`)
	databricksReadSuffix  = regexp.MustCompile(`(?i)[/:](batch)?(get|list|search|query|export|scan)([-_][a-z0-9_-]*)?$`)
	databricksDelete      = regexp.MustCompile(`^(Delete|PermanentDelete|Destroy|Purge|Remove|Clear|Trash|Truncate|Drop|Pop)`)
	databricksPermission  = regexp.MustCompile(`^(Get|Set|Update|Share)Permissions$|^GetPermissionLevels$`)
	sprintfVerb           = regexp.MustCompile(`%[^v]`)
	accessRankDatabricks  = map[string]int{"read": 0, "write": 1, "delete": 2, "admin": 3}
)

func (r *refresher) refreshDatabricks(outputPath string, write bool) error {
	cliTarball, err := r.get("https://codeload.github.com/databricks/cli/tar.gz/refs/tags/" + databricksCLIVersion)
	if err != nil {
		return err
	}
	cli, err := readGoTarball(cliTarball, func(name string) bool {
		return name == "go.mod" || strings.HasPrefix(name, "cmd/workspace/") || strings.HasPrefix(name, "cmd/account/")
	})
	if err != nil {
		return fmt.Errorf("databricks/cli: %w", err)
	}
	sdkVersion, err := goModRequire(cli["go.mod"], databricksSDKModule)
	if err != nil {
		return err
	}
	sdkTarball, err := r.get("https://codeload.github.com/databricks/databricks-sdk-go/tar.gz/refs/tags/" + sdkVersion)
	if err != nil {
		return err
	}
	sdk, err := readGoTarball(sdkTarball, func(name string) bool {
		return strings.HasPrefix(name, "service/") || name == "workspace_client.go" || name == "account_client.go"
	})
	if err != nil {
		return fmt.Errorf("databricks-sdk-go: %w", err)
	}
	table, report, err := buildDatabricksTable(cli, sdk, databricksCLIVersion, sdkVersion)
	if err != nil {
		return err
	}
	encoded, err := encodeDatabricksTable(table)
	if err != nil {
		return err
	}
	r.report = append(r.report, report...)
	current, _ := os.ReadFile(outputPath)
	switch {
	case bytes.Equal(current, encoded):
		r.note("\nNo route table changes.")
	case write:
		if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
			return err
		}
		r.note("\nRoute table written to %s. Review the tiers above before it merges.", outputPath)
	default:
		r.changed = true
		r.note("\nThe route table is out of date. Run with -write to apply.")
	}
	return nil
}

func encodeDatabricksTable(table *databricksTable) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(table); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// readGoTarball returns the files keep selects from a GitHub source tarball,
// with the top-level directory stripped. Only regular .go files and go.mod
// are kept, and only in memory.
func readGoTarball(tarball []byte, keep func(string) bool) (sourceTree, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	archive := tar.NewReader(gz)
	files := sourceTree{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		_, name, ok := strings.Cut(header.Name, "/")
		if !ok || header.Typeflag != tar.TypeReg || path.Clean(name) != name || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if !(strings.HasSuffix(name, ".go") || name == "go.mod") || !keep(name) {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(archive, 16<<20))
		if err != nil {
			return nil, err
		}
		files[name] = content
	}
	if len(files) == 0 {
		return nil, errors.New("tarball holds no Go source")
	}
	return files, nil
}

var goModVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

func goModRequire(goMod []byte, module string) (string, error) {
	for _, line := range strings.Split(string(goMod), "\n") {
		fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
		if len(fields) >= 2 && fields[0] == module {
			if !goModVersion.MatchString(fields[1]) {
				return "", fmt.Errorf("go.mod requires %s at unexpected version %q", module, fields[1])
			}
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("go.mod does not require %s", module)
}

func buildDatabricksTable(cli, sdk sourceTree, cliVersion, sdkVersion string) (*databricksTable, []string, error) {
	index, err := parseSDK(sdk)
	if err != nil {
		return nil, nil, err
	}
	commands, unresolved, err := parseCLI(cli, index)
	if err != nil {
		return nil, nil, err
	}
	// A restrictive entry (an admin, delete or consuming-GET tier, or an
	// operation's product) that matches nothing fails generation: upstream
	// may have renamed the operation, which would lose the restriction.
	// Stale permissive or cosmetic entries (POST reads, aliases, services)
	// are only reported. A service nobody has placed fails too.
	var stale, missing, unmapped []string
	for key := range databricksOperationProducts {
		if index.operations[key] == nil {
			missing = append(missing, "databricksOperationProducts "+key)
		}
	}
	for key := range databricksAdminOperations {
		if index.operations[key] == nil {
			missing = append(missing, "databricksAdminOperations "+key)
		}
	}
	for key := range databricksDeleteOperations {
		if index.operations[key] == nil {
			missing = append(missing, "databricksDeleteOperations "+key)
		}
	}
	for key := range databricksConsumingGets {
		if op := index.operations[key]; op == nil || op.method != "GET" {
			missing = append(missing, "databricksConsumingGets "+key)
		}
	}
	for key := range databricksPostReads {
		if op := index.operations[key]; op == nil || op.method != "POST" {
			stale = append(stale, "POST read "+key)
		}
	}
	for key, target := range databricksCommandAliases {
		if index.operations[target] == nil {
			stale = append(stale, "command alias "+key)
		}
	}
	services := map[string]bool{}
	for _, op := range index.operations {
		services[op.service] = true
	}
	for service := range services {
		if databricksServiceProducts[service] == "" {
			unmapped = append(unmapped, service)
		}
	}
	for service := range databricksServiceProducts {
		if !services[service] {
			stale = append(stale, "service "+service)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, nil, fmt.Errorf("databricks route table: these reviewed restrictions match no upstream operation; find where each went and move it:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		return nil, nil, fmt.Errorf("databricks route table: give these services a product in databricksServiceProducts:\n  %s", strings.Join(unmapped, "\n  "))
	}

	entries := map[string]*databricksEntry{}
	for _, op := range index.operations {
		entry := &databricksEntry{Operation: op.id, Method: op.method, Path: op.path, Product: databricksProduct(op)}
		if op.method == "POST" || op.method == "PUT" || op.method == "PATCH" {
			for _, field := range op.bodyFields {
				if databricksAdminField.MatchString(field[strings.LastIndex(field, ".")+1:]) && !databricksOutputField.MatchString(field) {
					entry.AdminFields = append(entry.AdminFields, field)
				}
			}
		}
		entry.Access = databricksAccess(op, entry.Product, len(entry.AdminFields) > 0)
		entries[op.id] = entry
	}

	// A command takes the strictest operation it calls, so a mutation
	// followed by a status read stays a mutation. Hand-kept commands take
	// over generated ones of the same name.
	handCommands := map[string]bool{}
	for _, hand := range databricksHandCommands {
		for _, command := range hand.Commands {
			handCommands[command] = true
		}
	}
	var multiple []string
	for _, command := range sortedKeys(commands) {
		if handCommands[command] {
			continue
		}
		ops := commands[command]
		chosen := ops[0]
		for _, op := range ops[1:] {
			if accessRankDatabricks[entries[op].Access] >= accessRankDatabricks[entries[chosen].Access] {
				chosen = op
			}
		}
		if len(ops) > 1 {
			multiple = append(multiple, fmt.Sprintf("`%s` calls %s; kept %s", command, strings.Join(ops, ", "), chosen))
		}
		entries[chosen].Commands = append(entries[chosen].Commands, command)
	}

	table := &databricksTable{CLI: cliVersion, SDK: sdkVersion, Rules: databricksRulesFingerprint()}
	var postReads, adminByPayload, suggestedReads []string
	for _, op := range index.operations {
		entry := entries[op.id]
		entry.Client = databricksClient(op, index, entry.Commands)
		line := fmt.Sprintf("`%s %s` %s (%s)", op.method, op.path, op.id, strings.Join(entry.Commands, ", "))
		switch {
		case entry.Access == "read" && op.method == "POST":
			postReads = append(postReads, line)
		case entry.Access == "admin" && entry.Product != "admin" && len(entry.AdminFields) > 0:
			adminByPayload = append(adminByPayload, fmt.Sprintf("%s: %s", line, strings.Join(entry.AdminFields, ", ")))
		}
		if entry.Access != "read" && op.method == "POST" && databricksReadSuffix.MatchString(op.path) {
			suggestedReads = append(suggestedReads, line)
		}
		table.Routes = append(table.Routes, *entry)
	}
	table.Routes = append(table.Routes, databricksHandCommands...)
	sort.Slice(table.Routes, func(i, j int) bool {
		a, b := table.Routes[i], table.Routes[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.Operation < b.Operation
	})

	tiers, products := map[string]int{}, map[string]int{}
	for _, entry := range table.Routes {
		tiers[entry.Access]++
		products[entry.Product]++
	}
	report := []string{fmt.Sprintf("# Databricks route table\n\ndatabricks/cli %s, databricks-sdk-go %s: %d routes, %d CLI commands.", cliVersion, sdkVersion, len(table.Routes), countCommands(table)), "", "| Tier | Routes |", "|---|---|"}
	for _, key := range sortedKeys(tiers) {
		report = append(report, fmt.Sprintf("| %s | %d |", key, tiers[key]))
	}
	report = append(report, "", "| Product | Routes |", "|---|---|")
	for _, key := range sortedKeys(products) {
		report = append(report, fmt.Sprintf("| %s | %d |", key, products[key]))
	}
	for _, section := range []struct {
		title string
		lines []string
	}{
		{"POST reads (reviewed allowlist)", postReads},
		{"Admin because the body can carry an owner or permissions", adminByPayload},
		{"POST routes whose path suggests a read (still write until reviewed)", suggestedReads},
		{"CLI commands whose SDK call is not a route (unclassified)", unresolved},
		{"CLI commands that call several operations", multiple},
		{"Reviewed entries that match nothing upstream", stale},
	} {
		sort.Strings(section.lines)
		report = append(report, "", fmt.Sprintf("## %s (%d)", section.title, len(section.lines)), "")
		for _, line := range section.lines {
			report = append(report, "- "+line)
		}
	}
	return table, report, nil
}

// databricksClient says whether an operation runs against the account or a
// workspace: by its account-ID path, else by the SDK client that owns its
// service, else by where the CLI files its commands.
func databricksClient(op *sdkOperation, index *sdkIndex, commands []string) string {
	owners := map[string]bool{}
	for client, fields := range index.clients {
		for _, service := range fields {
			if service == op.service {
				owners[client] = true
			}
		}
	}
	accountCommands := len(commands) > 0
	for _, command := range commands {
		accountCommands = accountCommands && strings.HasPrefix(command, "account ")
	}
	if op.account || (owners["account"] && !owners["workspace"]) || (len(owners) != 1 && accountCommands) {
		return "account"
	}
	return "workspace"
}

func countCommands(table *databricksTable) int {
	count := 0
	for _, entry := range table.Routes {
		count += len(entry.Commands)
	}
	return count
}

func databricksProduct(op *sdkOperation) string {
	if product := databricksOperationProducts[op.id]; product != "" {
		return product
	}
	if databricksPermission.MatchString(op.name) {
		return "admin"
	}
	return databricksServiceProducts[op.service]
}

func databricksAccess(op *sdkOperation, product string, adminBody bool) string {
	switch {
	case databricksConsumingGets[op.id]:
		return "write"
	case op.method == "GET" || op.method == "HEAD":
		return "read"
	case product == "admin" || adminBody || databricksAdminOperations[op.id]:
		// Admin evidence beats the POST-read allowlist.
		return "admin"
	case op.method == "POST" && databricksPostReads[op.id]:
		return "read"
	case op.method == "DELETE" || databricksDelete.MatchString(op.name) || databricksDeleteOperations[op.id]:
		return "delete"
	default:
		return "write"
	}
}

// sdkIndex is what the SDK source says about its operations and clients.
type sdkIndex struct {
	operations map[string]*sdkOperation
	// structs maps pkg.Type to its declaration and the file's imports;
	// types holds every declared pkg.Type, structs or not (enums).
	structs map[string]sdkStruct
	types   map[string]bool
	// aliases maps pkg.Type to the type it names (type A = B, type A B).
	aliases map[string]sdkAlias
	// clients maps "workspace"/"account" and a client field to pkg.Service.
	clients map[string]map[string]string
}

type sdkAlias struct {
	pkg     string
	target  ast.Expr
	imports map[string]string
}

type sdkStruct struct {
	pkg     string
	fields  *ast.StructType
	imports map[string]string
}

func parseSDK(sdk sourceTree) (*sdkIndex, error) {
	index := &sdkIndex{operations: map[string]*sdkOperation{}, structs: map[string]sdkStruct{}, types: map[string]bool{}, aliases: map[string]sdkAlias{}, clients: map[string]map[string]string{}}
	type implMethod struct {
		pkg     string
		imports map[string]string
		decl    *ast.FuncDecl
	}
	var methods []implMethod
	fileSet := token.NewFileSet()
	for _, name := range sortedKeys(sdk) {
		pkg, file, ok := strings.Cut(strings.TrimPrefix(name, "service/"), "/")
		if !strings.HasPrefix(name, "service/") || !ok || strings.Contains(file, "/") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, name, sdk[name], parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		imports := fileImports(parsed)
		for _, decl := range parsed.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					if spec, ok := spec.(*ast.TypeSpec); ok {
						key := pkg + "." + spec.Name.Name
						index.types[key] = true
						switch target := spec.Type.(type) {
						case *ast.StructType:
							index.structs[key] = sdkStruct{pkg: pkg, fields: target, imports: imports}
						default:
							// Named types and aliases, collections included
							// (type Items []Item), resolve to what they name.
							index.aliases[key] = sdkAlias{pkg: pkg, target: target, imports: imports}
						}
					}
				}
			case *ast.FuncDecl:
				if strings.HasSuffix(file, "impl.go") && implReceiver(decl) != "" && operationName(decl) != "" {
					methods = append(methods, implMethod{pkg, imports, decl})
				}
			}
		}
	}
	for _, m := range methods {
		op, err := index.parseOperation(m.pkg, m.imports, m.decl)
		if err != nil {
			return nil, fmt.Errorf("service/%s: %s.%s: %w", m.pkg, implReceiver(m.decl), m.decl.Name.Name, err)
		}
		if op != nil {
			if index.operations[op.id] != nil {
				return nil, fmt.Errorf("databricks-sdk-go: operation %s is implemented twice", op.id)
			}
			index.operations[op.id] = op
		}
	}
	if len(index.operations) == 0 {
		return nil, errors.New("databricks-sdk-go: no operations found in service/*/impl.go")
	}
	for client, file := range map[string]string{"workspace": "workspace_client.go", "account": "account_client.go"} {
		fields, err := parseClient(fileSet, file, sdk[file])
		if err != nil {
			return nil, err
		}
		index.clients[client] = fields
	}
	return index, nil
}

func fileImports(file *ast.File) map[string]string {
	imports := map[string]string{}
	for _, spec := range file.Imports {
		importPath, _ := strconv.Unquote(spec.Path.Value)
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[name] = importPath
	}
	return imports
}

// implReceiver returns the service implementation type a method belongs to
// (clustersImpl), or "".
func implReceiver(decl *ast.FuncDecl) string {
	if decl.Recv == nil || len(decl.Recv.List) != 1 {
		return ""
	}
	star, ok := decl.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	ident, ok := star.X.(*ast.Ident)
	if !ok || !strings.HasSuffix(ident.Name, "Impl") {
		return ""
	}
	return ident.Name
}

// operationName names the operation an impl method performs. A paginated
// List wraps internalList, which makes the request.
func operationName(decl *ast.FuncDecl) string {
	name := decl.Name.Name
	if inner, ok := strings.CutPrefix(name, "internal"); ok && inner != "" && unicode.IsUpper(rune(inner[0])) {
		return inner
	}
	if decl.Name.IsExported() {
		return name
	}
	return ""
}

func serviceName(pkg, impl string) string {
	name := strings.TrimSuffix(impl, "Impl")
	return pkg + "." + strings.ToUpper(name[:1]) + name[1:]
}

// parseOperation reads one impl method: `path := ...` and the
// a.client.Do(ctx, http.MethodX, path, headers, queryParams, body, out) call.
// A method that calls something else (a data-plane URL) has no fixed route
// and is skipped.
func (index *sdkIndex) parseOperation(pkg string, imports map[string]string, decl *ast.FuncDecl) (*sdkOperation, error) {
	var pathExpr ast.Expr
	var calls []*ast.CallExpr
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == 1 && len(node.Rhs) == 1 && isIdent(node.Lhs[0], "path") {
				pathExpr = node.Rhs[0]
			}
		case *ast.CallExpr:
			if selectorPath(node.Fun) == "a.client.Do" {
				calls = append(calls, node)
			}
		}
		return true
	})
	if len(calls) == 0 {
		return nil, nil
	}
	if len(calls) > 1 || pathExpr == nil {
		return nil, errors.New("expected one path assignment and one client.Do call")
	}
	call := calls[0]
	if len(call.Args) != 7 || !isIdent(call.Args[2], "path") {
		return nil, errors.New("unexpected client.Do arguments")
	}
	method, ok := strings.CutPrefix(selectorPath(call.Args[1]), "http.Method")
	if !ok || method == "" {
		return nil, errors.New("HTTP method is not an http.MethodX constant")
	}
	template, account, err := pathTemplate(pathExpr)
	if err != nil {
		return nil, err
	}
	service := serviceName(pkg, implReceiver(decl))
	name := operationName(decl)
	op := &sdkOperation{id: service + "." + name, service: service, name: name, method: strings.ToUpper(method), path: template, account: account}

	var requestType ast.Expr
	if params := decl.Type.Params.List; len(params) == 2 && len(params[1].Names) == 1 && params[1].Names[0].Name == "request" {
		requestType = params[1].Type
	}
	body := call.Args[5]
	switch {
	case isIdent(body, "nil"):
		return op, nil
	case isIdent(body, "request") && requestType != nil:
	case requestType != nil:
		selector, ok := body.(*ast.SelectorExpr)
		if !ok || !isIdent(selector.X, "request") {
			return nil, errors.New("request body is neither request nor one of its fields")
		}
		key, err := index.resolveType(pkg, imports, requestType)
		if err != nil || key == "" {
			return nil, fmt.Errorf("request type is not a known struct: %v", err)
		}
		requestType = nil
		// The field's type is spelled in the request struct's file.
		pkg, imports = index.structs[key].pkg, index.structs[key].imports
		for _, field := range index.structs[key].fields.Fields.List {
			for _, name := range field.Names {
				if name.Name == selector.Sel.Name {
					requestType = field.Type
				}
			}
		}
		if requestType == nil {
			return nil, fmt.Errorf("request has no field %s", selector.Sel.Name)
		}
	default:
		return nil, errors.New("request body without a request parameter")
	}
	key, err := index.resolveType(pkg, imports, requestType)
	if err != nil {
		return nil, err
	}
	if key != "" {
		if err := index.collectFields(key, "", map[string]bool{}, &op.bodyFields); err != nil {
			return nil, err
		}
	}
	return op, nil
}

var goBuiltinTypes = map[string]bool{"any": true, "bool": true, "byte": true, "float32": true, "float64": true, "int": true, "int32": true, "int64": true, "rune": true, "string": true, "uint": true, "uint32": true, "uint64": true}

// resolveType returns the pkg.Type of the SDK struct a type holds, looking
// through pointers, slices and maps; "" when it holds no SDK struct (a
// builtin, an enum, io.ReadCloser). A type the SDK source does not declare
// is an error: its fields, possibly an owner or an ACL, would go unseen.
func (index *sdkIndex) resolveType(pkg string, imports map[string]string, expr ast.Expr) (string, error) {
	switch expr := expr.(type) {
	case *ast.StarExpr:
		return index.resolveType(pkg, imports, expr.X)
	case *ast.ArrayType:
		return index.resolveType(pkg, imports, expr.Elt)
	case *ast.MapType:
		return index.resolveType(pkg, imports, expr.Value)
	case *ast.InterfaceType, *ast.FuncType, *ast.ChanType:
		// Not serialized into a body.
		return "", nil
	case *ast.Ident:
		if goBuiltinTypes[expr.Name] {
			return "", nil
		}
		return index.declaredType(pkg + "." + expr.Name)
	case *ast.SelectorExpr:
		alias, ok := expr.X.(*ast.Ident)
		if !ok {
			break
		}
		importPath, ok := imports[alias.Name]
		if !ok {
			return "", fmt.Errorf("type %s.%s has no import", alias.Name, expr.Sel.Name)
		}
		if !strings.HasPrefix(importPath, databricksSDKModule+"/service/") {
			return "", nil
		}
		return index.declaredType(path.Base(importPath) + "." + expr.Sel.Name)
	}
	return "", fmt.Errorf("unsupported type expression %T", expr)
}

func (index *sdkIndex) declaredType(key string) (string, error) {
	switch alias, isAlias := index.aliases[key]; {
	case index.structs[key].fields != nil:
		return key, nil
	case isAlias:
		// Upstream types never alias in a cycle; a cycle would not compile.
		return index.resolveType(alias.pkg, alias.imports, alias.target)
	case index.types[key]:
		return "", nil
	}
	return "", fmt.Errorf("type %s is not declared in the SDK source", key)
}

// collectFields appends the dotted JSON path of every field a request body
// can carry, nested and embedded structs included. visiting stops recursive
// types.
func (index *sdkIndex) collectFields(key, prefix string, visiting map[string]bool, out *[]string) error {
	if visiting[key] {
		return nil
	}
	visiting[key] = true
	defer delete(visiting, key)
	declaration := index.structs[key]
	for _, field := range declaration.fields.Fields.List {
		name := ""
		if field.Tag != nil {
			tag, _ := strconv.Unquote(field.Tag.Value)
			name, _, _ = strings.Cut(reflect.StructTag(tag).Get("json"), ",")
		}
		embedded := len(field.Names) == 0 && name == ""
		if name == "" && !embedded {
			// encoding/json falls back to the Go name of an exported field.
			if !field.Names[0].IsExported() {
				continue
			}
			name = field.Names[0].Name
		}
		if name == "-" {
			continue
		}
		nested, err := index.resolveType(declaration.pkg, declaration.imports, field.Type)
		if err != nil {
			return fmt.Errorf("%s field %s: %w", key, prefix+name, err)
		}
		fieldPrefix := prefix
		if !embedded {
			*out = append(*out, prefix+name)
			fieldPrefix = prefix + name + "."
		}
		if nested != "" {
			if err := index.collectFields(nested, fieldPrefix, visiting, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// pathTemplate turns a path literal or fmt.Sprintf call into a template with
// {param} placeholders; {param+} spans several segments.
func pathTemplate(expr ast.Expr) (string, bool, error) {
	if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.STRING {
		value, err := strconv.Unquote(literal.Value)
		return value, false, err
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || selectorPath(call.Fun) != "fmt.Sprintf" || len(call.Args) < 2 {
		return "", false, errors.New("path is neither a literal nor fmt.Sprintf")
	}
	literal, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return "", false, errors.New("path format is not a literal")
	}
	format, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false, err
	}
	parts := strings.Split(format, "%v")
	if sprintfVerb.MatchString(strings.ReplaceAll(format, "%v", "")) || len(parts) != len(call.Args) {
		return "", false, fmt.Errorf("path format %q does not match its arguments", format)
	}
	var out strings.Builder
	account := false
	for i, arg := range call.Args[1:] {
		out.WriteString(parts[i])
		switch {
		case selectorPath(arg) == "a.client.ConfiguredAccountID":
			out.WriteString("{account_id}")
			account = true
		case strings.HasPrefix(selectorPath(arg), "request."):
			out.WriteString("{" + snakeCase(strings.TrimPrefix(selectorPath(arg), "request.")) + "}")
		case selectorPath(arg) == "httpclient.EncodeMultiSegmentPathParameter" && len(arg.(*ast.CallExpr).Args) == 1 && strings.HasPrefix(selectorPath(arg.(*ast.CallExpr).Args[0]), "request."):
			out.WriteString("{" + snakeCase(strings.TrimPrefix(selectorPath(arg.(*ast.CallExpr).Args[0]), "request.")) + "+}")
		default:
			return "", false, fmt.Errorf("unexpected path argument in %q", format)
		}
	}
	out.WriteString(parts[len(parts)-1])
	return out.String(), account, nil
}

// selectorPath renders a.b.c, and a.b.c() as a.b.c, or "" for anything else.
func selectorPath(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		if inner := selectorPath(expr.X); inner != "" {
			return inner + "." + expr.Sel.Name
		}
	case *ast.CallExpr:
		return selectorPath(expr.Fun)
	}
	return ""
}

func isIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

func snakeCase(name string) string {
	name = strings.ReplaceAll(name, ".", "_")
	var out strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		if unicode.IsUpper(r) && i > 0 && runes[i-1] != '_' && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
			out.WriteByte('_')
		}
		out.WriteRune(unicode.ToLower(r))
	}
	return out.String()
}

// parseClient maps each client field (Clusters) to the service its
// constructor builds (compute.NewClusters → compute.Clusters).
func parseClient(fileSet *token.FileSet, name string, source []byte) (map[string]string, error) {
	if source == nil {
		return nil, fmt.Errorf("databricks-sdk-go: %s missing", name)
	}
	parsed, err := parser.ParseFile(fileSet, name, source, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	imports := fileImports(parsed)
	// constructed resolves pkg.NewX(...) to pkg.X, also through a local
	// variable assigned from one.
	locals := map[string]string{}
	constructed := func(expr ast.Expr) string {
		if ident, ok := expr.(*ast.Ident); ok {
			return locals[ident.Name]
		}
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return ""
		}
		constructor, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.HasPrefix(constructor.Sel.Name, "New") {
			return ""
		}
		alias, ok := constructor.X.(*ast.Ident)
		if importPath := imports[alias.Name]; ok && strings.HasPrefix(importPath, databricksSDKModule+"/service/") {
			return path.Base(importPath) + "." + strings.TrimPrefix(constructor.Sel.Name, "New")
		}
		return ""
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		if assign, ok := node.(*ast.AssignStmt); ok && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 {
			if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
				if service := constructed(assign.Rhs[0]); service != "" {
					locals[ident.Name] = service
				}
			}
		}
		return true
	})
	fields := map[string]string{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		if pair, ok := node.(*ast.KeyValueExpr); ok {
			if key, ok := pair.Key.(*ast.Ident); ok {
				if service := constructed(pair.Value); service != "" {
					fields[key.Name] = service
				}
			}
		}
		return true
	})
	if len(fields) == 0 {
		return nil, fmt.Errorf("databricks-sdk-go: no client fields in %s", name)
	}
	return fields, nil
}

// cliPackage is one cmd/workspace/<dir> or cmd/account/<dir> package.
type cliPackage struct {
	group    string
	children []string
	// commands maps a verb to the SDK calls its function makes, in order.
	commands map[string][]sdkCall
}

type sdkCall struct {
	client  string // workspace or account
	field   string // Clusters, or Settings
	sub     string // DisableLegacyDbfs for w.Settings.DisableLegacyDbfs().Get
	method  string
	display string
}

// parseCLI returns, per operation, the CLI commands that call it, plus the
// commands whose call it could not place.
func parseCLI(cli sourceTree, index *sdkIndex) (map[string][]string, []string, error) {
	// commands maps each `<group> <verb>` to the operations it calls.
	fileSet := token.NewFileSet()
	packages := map[string]*cliPackage{}
	roots := map[string][]string{}
	for _, name := range sortedKeys(cli) {
		dir := path.Dir(name)
		root, pkgDir, nested := strings.Cut(dir, "/")
		if root != "cmd" {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, name, cli[name], parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, err
		}
		imports := fileImports(parsed)
		children := func(node ast.Node) []string {
			var out []string
			ast.Inspect(node, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) != 0 {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "New" {
					return true
				}
				if alias, ok := selector.X.(*ast.Ident); ok {
					if importPath := imports[alias.Name]; strings.HasPrefix(importPath, databricksCLIModule+"/cmd/") {
						out = append(out, strings.TrimPrefix(importPath, databricksCLIModule+"/"))
					}
				}
				return true
			})
			return out
		}
		if !nested || !strings.Contains(pkgDir, "/") {
			// cmd/workspace/*.go or cmd/account/*.go: the root command files.
			if path.Base(name) == "cmd.go" {
				roots[dir] = append(roots[dir], children(parsed)...)
			}
			continue
		}
		if strings.Count(pkgDir, "/") != 1 {
			continue
		}
		pkg := packages[dir]
		if pkg == nil {
			pkg = &cliPackage{commands: map[string][]sdkCall{}}
			packages[dir] = pkg
		}
		for _, decl := range parsed.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || function.Recv != nil || function.Body == nil {
				continue
			}
			if function.Name.Name == "New" {
				pkg.group = cobraUse(function.Body)
				pkg.children = append(pkg.children, children(function.Body)...)
				continue
			}
			verb := commandUse(function.Body)
			if verb == "" {
				continue
			}
			pkg.commands[verb] = append(pkg.commands[verb], sdkCalls(function.Body)...)
		}
	}

	commands := map[string][]string{}
	var unresolved []string
	var walk func(dir, prefix string, depth int) error
	walk = func(dir, prefix string, depth int) error {
		pkg := packages[dir]
		if pkg == nil || pkg.group == "" {
			return fmt.Errorf("databricks/cli: %s has no New command", dir)
		}
		if depth > 4 {
			return fmt.Errorf("databricks/cli: %s nests too deep", dir)
		}
		group := strings.TrimSpace(prefix + " " + pkg.group)
		for _, verb := range sortedKeys(pkg.commands) {
			command := group + " " + verb
			ops, display := resolveCommand(pkg.commands[verb], index)
			if len(ops) == 0 {
				unresolved = append(unresolved, fmt.Sprintf("`%s` (%s)", command, display))
				continue
			}
			for _, op := range ops {
				if !slices.Contains(commands[command], op) {
					commands[command] = append(commands[command], op)
				}
			}
		}
		for _, child := range pkg.children {
			if err := walk(child, group, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for root, prefix := range map[string]string{"cmd/workspace": "", "cmd/account": "account"} {
		if len(roots[root]) == 0 {
			return nil, nil, fmt.Errorf("databricks/cli: %s/cmd.go registers no commands", root)
		}
		for _, dir := range roots[root] {
			if err := walk(dir, prefix, 0); err != nil {
				return nil, nil, err
			}
		}
	}
	return commands, unresolved, nil
}

// resolveCommand lists the operations a command calls, skipping name-to-id
// lookups. Any other SDK call that is not an operation leaves the command
// unresolved; display names it.
func resolveCommand(calls []sdkCall, index *sdkIndex) ([]string, string) {
	var ops []string
	display := "no SDK call"
	for _, call := range calls {
		if strings.HasSuffix(call.method, "Map") {
			continue
		}
		service := index.clients[call.client][call.field]
		if service == "" {
			// A client field the SDK clients do not build could be the
			// mutation; leave the command unclassified.
			return nil, call.display
		}
		if call.sub != "" {
			pkg, _, _ := strings.Cut(service, ".")
			service = pkg + "." + call.sub
		}
		display = call.display
		op := service + "." + call.method
		if alias := databricksCommandAliases[op]; alias != "" {
			op = alias
		}
		if index.operations[op] == nil {
			// An SDK call that is no route could be the mutation; leave the
			// command unclassified rather than judge it by the calls left.
			return nil, display
		}
		if !slices.Contains(ops, op) {
			ops = append(ops, op)
		}
	}
	return ops, display
}

// cobraUse reads the first word of Use in New's &cobra.Command{...}.
func cobraUse(body *ast.BlockStmt) string {
	use := ""
	ast.Inspect(body, func(node ast.Node) bool {
		pair, ok := node.(*ast.KeyValueExpr)
		if ok && use == "" && isIdent(pair.Key, "Use") {
			use = stringLiteral(pair.Value)
		}
		return use == ""
	})
	return firstWord(use)
}

// commandUse reads the first word of `cmd.Use = "verb ARGS"`.
func commandUse(body *ast.BlockStmt) string {
	use := ""
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if ok && use == "" && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 && selectorPath(assign.Lhs[0]) == "cmd.Use" {
			use = stringLiteral(assign.Rhs[0])
		}
		return use == ""
	})
	return firstWord(use)
}

func stringLiteral(expr ast.Expr) string {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return ""
	}
	value, _ := strconv.Unquote(literal.Value)
	return value
}

func firstWord(text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// sdkCalls lists w.Field.Method(...), a.Field.Method(...) and
// w.Field.Sub().Method(...) calls in source order. A variable holding a
// client (c := cmdctx.WorkspaceClient(ctx), c := w) or a service
// (svc := w.Clusters) counts as what it holds, so a call through it is
// not missed.
func sdkCalls(body *ast.BlockStmt) []sdkCall {
	clients := map[string]string{"w": "workspace", "a": "account"}
	services := map[string]sdkCall{}
	client := func(expr ast.Expr) string {
		if ident, ok := expr.(*ast.Ident); ok {
			return clients[ident.Name]
		}
		switch selectorPath(expr) {
		case "cmdctx.WorkspaceClient":
			return "workspace"
		case "cmdctx.AccountClient":
			return "account"
		}
		return ""
	}
	var calls []sdkCall
	// accessors are the X() in w.Field.X().Method(...); Inspect reaches the
	// outer call first.
	accessors := map[*ast.CallExpr]bool{}
	bind := func(name string, value ast.Expr) {
		if name == "_" {
			return
		}
		if kind := client(value); kind != "" {
			clients[name] = kind
		} else if field, ok := value.(*ast.SelectorExpr); ok && client(field.X) != "" {
			services[name] = sdkCall{client: client(field.X), field: field.Sel.Name}
		}
	}
	ast.Inspect(body, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						bind(ident.Name, node.Rhs[i])
					}
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == len(node.Values) {
				for i, name := range node.Names {
					bind(name.Name, node.Values[i])
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || accessors[call] {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		var found sdkCall
		switch receiver := method.X.(type) {
		case *ast.Ident:
			found = services[receiver.Name]
		case *ast.SelectorExpr:
			found.field = receiver.Sel.Name
			found.client = client(receiver.X)
		case *ast.CallExpr:
			sub, ok := receiver.Fun.(*ast.SelectorExpr)
			if !ok || len(receiver.Args) != 0 {
				return true
			}
			accessors[receiver] = true
			field, ok := sub.X.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			found.field, found.sub, found.client = field.Sel.Name, sub.Sel.Name, client(field.X)
		}
		if found.client == "" {
			return true
		}
		found.method = method.Sel.Name
		found.display = selectorPath(call.Fun)
		calls = append(calls, found)
		return true
	})
	return calls
}

// databricksServiceProducts is each SDK service's default product, which a
// reviewer confirms when a service first appears. sql is only for running
// SQL; warehouses are compute and saved queries, alerts and dashboards are
// workspace objects. Permissions methods on any service are admin (see
// databricksPermission), and databricksOperationProducts overrides single
// operations.
var databricksServiceProducts = map[string]string{
	// sql
	"sql.StatementExecution": "sql",
	// data
	"catalog.Catalogs":                                "data",
	"catalog.Connections":                             "data",
	"catalog.Credentials":                             "data",
	"catalog.EntityTagAssignments":                    "data",
	"catalog.ExternalLineage":                         "data",
	"catalog.ExternalLocations":                       "data",
	"catalog.ExternalMetadata":                        "data",
	"catalog.Functions":                               "data",
	"catalog.OnlineTables":                            "data",
	"catalog.QualityMonitors":                         "data",
	"catalog.ResourceQuotas":                          "data",
	"catalog.Schemas":                                 "data",
	"catalog.StorageCredentials":                      "data",
	"catalog.TableConstraints":                        "data",
	"catalog.Tables":                                  "data",
	"catalog.Volumes":                                 "data",
	"cleanrooms.CleanRoomAssetRevisions":              "data",
	"cleanrooms.CleanRoomAssets":                      "data",
	"cleanrooms.CleanRoomAutoApprovalRules":           "data",
	"cleanrooms.CleanRoomTaskRuns":                    "data",
	"cleanrooms.CleanRooms":                           "data",
	"database.Database":                               "data",
	"dataclassification.DataClassification":           "data",
	"dataquality.DataQuality":                         "data",
	"domains.Domains":                                 "data",
	"files.Dbfs":                                      "data",
	"files.Files":                                     "data",
	"marketplace.ConsumerFulfillments":                "data",
	"marketplace.ConsumerListings":                    "data",
	"marketplace.ConsumerPersonalizationRequests":     "data",
	"marketplace.ConsumerProviders":                   "data",
	"marketplace.ProviderExchangeFilters":             "data",
	"marketplace.ProviderExchanges":                   "data",
	"marketplace.ProviderFiles":                       "data",
	"marketplace.ProviderListings":                    "data",
	"marketplace.ProviderPersonalizationRequests":     "data",
	"marketplace.ProviderProviderAnalyticsDashboards": "data",
	"marketplace.ProviderProviders":                   "data",
	"postgres.Postgres":                               "data",
	"qualitymonitorv2.QualityMonitorV2":               "data",
	"sharing.Providers":                               "data",
	"sharing.Recipients":                              "data",
	"sharing.Shares":                                  "data",
	// compute
	"compute.ClusterPolicies":             "compute",
	"compute.Clusters":                    "compute",
	"compute.InstancePools":               "compute",
	"compute.Libraries":                   "compute",
	"compute.PolicyComplianceForClusters": "compute",
	"compute.PolicyFamilies":              "compute",
	"sql.DataSources":                     "compute",
	"sql.QueryHistory":                    "compute",
	"sql.Warehouses":                      "compute",
	// workloads
	"apps.Apps":                           "workloads",
	"apps.AppsSettings":                   "workloads",
	"bundle.Bundle":                       "workloads",
	"bundledeployments.BundleDeployments": "workloads",
	"jobs.Jobs":                           "workloads",
	"jobs.PolicyComplianceForJobs":        "workloads",
	"pipelines.Pipelines":                 "workloads",
	// ai
	"agentbricks.AgentBricks":                 "ai",
	"agentkit.AgentKit":                       "ai",
	"aifunctions.AiFunctions":                 "ai",
	"aisearch.AiSearch":                       "ai",
	"catalog.AiGateway":                       "ai",
	"catalog.ModelVersions":                   "ai",
	"catalog.RegisteredModels":                "ai",
	"dashboards.Genie":                        "ai",
	"knowledgeassistants.KnowledgeAssistants": "ai",
	"mason.Mason":                             "ai",
	"ml.Experiments":                          "ai",
	"ml.FeatureEngineering":                   "ai",
	"ml.FeatureStore":                         "ai",
	"ml.Forecasting":                          "ai",
	"ml.MaterializedFeatures":                 "ai",
	"ml.ModelRegistry":                        "ai",
	"serving.ServingEndpoints":                "ai",
	"supervisoragents.SupervisorAgents":       "ai",
	"vectorsearch.VectorSearchEndpoints":      "ai",
	"vectorsearch.VectorSearchIndexes":        "ai",
	// workspace
	"dashboards.Lakeview":                "workspace",
	"sql.Alerts":                         "workspace",
	"sql.AlertsLegacy":                   "workspace",
	"sql.AlertsV2":                       "workspace",
	"sql.DashboardWidgets":               "workspace",
	"sql.Dashboards":                     "workspace",
	"sql.Queries":                        "workspace",
	"sql.QueriesLegacy":                  "workspace",
	"sql.QueryVisualizations":            "workspace",
	"sql.QueryVisualizationsLegacy":      "workspace",
	"sql.RedashConfig":                   "workspace",
	"tags.WorkspaceEntityTagAssignments": "workspace",
	"workspace.Repos":                    "workspace",
	"workspace.Workspace":                "workspace",
	// secrets
	"marketplace.ConsumerInstallations":   "secrets", // responses carry bearer tokens
	"catalog.SecretsUc":                   "secrets",
	"catalog.TemporaryPathCredentials":    "secrets",
	"catalog.TemporaryTableCredentials":   "secrets",
	"catalog.TemporaryVolumeCredentials":  "secrets",
	"dashboards.LakeviewEmbedded":         "secrets",
	"oauth2.ServicePrincipalSecrets":      "secrets",
	"oauth2.ServicePrincipalSecretsProxy": "secrets",
	"settings.CredentialsManager":         "secrets",
	"settings.TokenManagement":            "secrets",
	"settings.Tokens":                     "secrets",
	"sharing.RecipientActivation":         "secrets",
	"workspace.GitCredentials":            "secrets",
	"workspace.Secrets":                   "secrets",
	// admin
	"catalog.SystemSchemas":                          "admin", // metastore-wide audit and billing schemas
	"environments.Environments":                      "admin", // workspace-wide base environments
	"billing.BillableUsage":                          "admin",
	"billing.BudgetPolicy":                           "admin",
	"billing.Budgets":                                "admin",
	"billing.LogDelivery":                            "admin",
	"billing.UsageDashboards":                        "admin",
	"catalog.AccountMetastoreAssignments":            "admin",
	"catalog.AccountMetastores":                      "admin",
	"catalog.AccountStorageCredentials":              "admin",
	"catalog.ArtifactAllowlists":                     "admin",
	"catalog.Grants":                                 "admin",
	"catalog.Metastores":                             "admin",
	"catalog.Policies":                               "admin",
	"catalog.Rfa":                                    "admin",
	"catalog.WorkspaceBindings":                      "admin",
	"compute.GlobalInitScripts":                      "admin",
	"compute.InstanceProfiles":                       "admin",
	"disasterrecovery.DisasterRecovery":              "admin",
	"iam.AccessControl":                              "admin",
	"iam.AccountAccessControl":                       "admin",
	"iam.AccountAccessControlProxy":                  "admin",
	"iam.AccountGroups":                              "admin",
	"iam.AccountGroupsV2":                            "admin",
	"iam.AccountServicePrincipals":                   "admin",
	"iam.AccountServicePrincipalsV2":                 "admin",
	"iam.AccountUsers":                               "admin",
	"iam.AccountUsersV2":                             "admin",
	"iam.CurrentUser":                                "admin",
	"iam.Groups":                                     "admin",
	"iam.GroupsV2":                                   "admin",
	"iam.PermissionMigration":                        "admin",
	"iam.Permissions":                                "admin",
	"iam.ServicePrincipals":                          "admin",
	"iam.ServicePrincipalsV2":                        "admin",
	"iam.Users":                                      "admin",
	"iam.UsersV2":                                    "admin",
	"iam.WorkspaceAssignment":                        "admin",
	"iamv2.AccountIamV2":                             "admin",
	"iamv2.WorkspaceIamV2":                           "admin",
	"networking.Endpoints":                           "admin",
	"networking.PrivateNetworkGateways":              "admin",
	"oauth2.AccountFederationPolicy":                 "admin",
	"oauth2.CustomAppIntegration":                    "admin",
	"oauth2.OAuthPublishedApps":                      "admin",
	"oauth2.PublishedAppIntegration":                 "admin",
	"oauth2.ServicePrincipalFederationPolicy":        "admin",
	"provisioning.Credentials":                       "admin",
	"provisioning.EncryptionKeys":                    "admin",
	"provisioning.Networks":                          "admin",
	"provisioning.PrivateAccess":                     "admin",
	"provisioning.Storage":                           "admin",
	"provisioning.VpcEndpoints":                      "admin",
	"provisioning.Workspaces":                        "admin",
	"settings.AccountIpAccessLists":                  "admin",
	"settings.AibiDashboardEmbeddingAccessPolicy":    "admin",
	"settings.AibiDashboardEmbeddingApprovedDomains": "admin",
	"settings.AutomaticClusterUpdate":                "admin",
	"settings.ComplianceSecurityProfile":             "admin",
	"settings.CspEnablementAccount":                  "admin",
	"settings.DashboardEmailSubscriptions":           "admin",
	"settings.DefaultNamespace":                      "admin",
	"settings.DefaultWarehouseId":                    "admin",
	"settings.DisableLegacyAccess":                   "admin",
	"settings.DisableLegacyDbfs":                     "admin",
	"settings.DisableLegacyFeatures":                 "admin",
	"settings.EnableExportNotebook":                  "admin",
	"settings.EnableIpAccessLists":                   "admin",
	"settings.EnableNotebookTableClipboard":          "admin",
	"settings.EnableResultsDownloading":              "admin",
	"settings.EnhancedSecurityMonitoring":            "admin",
	"settings.EsmEnablementAccount":                  "admin",
	"settings.IpAccessLists":                         "admin",
	"settings.LlmProxyPartnerPoweredAccount":         "admin",
	"settings.LlmProxyPartnerPoweredEnforce":         "admin",
	"settings.LlmProxyPartnerPoweredWorkspace":       "admin",
	"settings.NetworkConnectivity":                   "admin",
	"settings.NetworkPolicies":                       "admin",
	"settings.NotificationDestinations":              "admin",
	"settings.PersonalCompute":                       "admin",
	"settings.RestrictWorkspaceAdmins":               "admin",
	"settings.SqlResultsDownload":                    "admin",
	"settings.WorkspaceConf":                         "admin",
	"settings.WorkspaceNetworkConfiguration":         "admin",
	"settingsv2.AccountSettingsV2":                   "admin",
	"settingsv2.WorkspaceSettingsV2":                 "admin",
	"sharing.RecipientFederationPolicies":            "admin",
	"sql.DbsqlPermissions":                           "admin",
	"tags.TagPolicies":                               "admin",
	// execution
	"compute.CommandExecution": "execution",
	"sandbox.Sandbox":          "execution",
}

// databricksOperationProducts places operations their service's default does
// not fit: running code now or deploying it (execution; testing a job
// webhook runs the job, installing a library runs its install code, cloning
// a pipeline starts an update), running SQL (sql; a Genie message generates and runs
// it) and minting or returning credentials (secrets; a recipient carries
// its activation URL, a provider its recipient profile's bearer token,
// which Create and Update import, a connection the database credentials in
// its options, a model provider service the provider's API keys).
var databricksOperationProducts = map[string]string{
	"apps.Apps.Deploy":                                       "execution",
	"apps.Apps.Start":                                        "execution",
	"compute.Libraries.Install":                              "execution",
	"jobs.Jobs.RepairRun":                                    "execution",
	"jobs.Jobs.RunNow":                                       "execution",
	"jobs.Jobs.Submit":                                       "execution",
	"ml.ModelRegistry.TestRegistryWebhook":                   "execution",
	"serving.ServingEndpoints.HttpRequest":                   "execution",
	"pipelines.Pipelines.Clone":                              "execution",
	"pipelines.Pipelines.StartUpdate":                        "execution",
	"dashboards.Genie.CreateMessage":                         "sql",
	"dashboards.Genie.ExecuteMessageAttachmentQuery":         "sql",
	"dashboards.Genie.ExecuteMessageQuery":                   "sql",
	"dashboards.Genie.GenerateDownloadFullQueryResult":       "sql",
	"dashboards.Genie.GenieCreateEvalRun":                    "sql",
	"dashboards.Genie.StartConversation":                     "sql",
	"catalog.AiGateway.CreateMcpServiceUserMappedCredential": "secrets",
	"catalog.AiGateway.DeleteMcpServiceUserMappedCredential": "secrets",
	"catalog.AiGateway.GetMcpServiceUserMappedCredential":    "secrets",
	"catalog.AiGateway.CreateModelProviderService":           "secrets",
	"catalog.AiGateway.UpdateModelProviderService":           "secrets",
	"catalog.Connections.Create":                             "secrets",
	"catalog.Connections.Update":                             "secrets",
	"catalog.Credentials.GenerateTemporaryServiceCredential": "secrets",
	"sharing.Providers.Create":                               "secrets",
	"sharing.Providers.Get":                                  "secrets",
	"sharing.Providers.List":                                 "secrets",
	"sharing.Providers.Update":                               "secrets",
	"sharing.Recipients.Create":                              "secrets",
	"sharing.Recipients.Get":                                 "secrets",
	"sharing.Recipients.List":                                "secrets",
	"database.Database.GenerateDatabaseCredential":           "secrets",
	"postgres.Postgres.GenerateDatabaseCredential":           "secrets",
	"sharing.Recipients.RotateToken":                         "secrets",
}

// databricksAdminOperations are the operations a reviewer placed at admin
// because of what they do, beyond the generic rules (admin product, and a
// request body that can carry an owner, permissions, an access control list
// or grants):
//   - identities and authentication: database roles and owners, native
//     Postgres login, the data API's JWT role claim, branch protection,
//     credentials minted, changed or revoked for another identity (service
//     principal secrets, OBO tokens, git credentials, recipient tokens), UC
//     storage and service credentials, model provider services
//   - delegated identity: run_as on jobs, pipelines, queries, alerts and
//     legacy dashboards, a dashboard published with embedded credentials, a
//     registry webhook holding an access token, an app granting its service
//     principal access to resources, a secret scope's initial MANAGE
//     principal, secret ACLs
//   - security controls: cluster policies and their pending enforcement, the
//     workspace warehouse config and default-warehouse overrides, AI Gateway
//     and serving guardrails, rate limits, payload logging and telemetry,
//     Kafka and stream TLS settings, the external HTTP proxy
//   - data access: governed tags and data classification (ABAC), external
//     location creation (fallback mode), marketplace exchanges, listings,
//     filters and fulfilled requests, clean-room approvals
var databricksAdminOperations = map[string]bool{
	"apps.Apps.Create":                                                    true,
	"apps.Apps.CreateSpace":                                               true,
	"apps.Apps.CreateUpdate":                                              true,
	"apps.Apps.Update":                                                    true,
	"apps.Apps.UpdateSpace":                                               true,
	"catalog.AiGateway.CreateMcpService":                                  true,
	"catalog.AiGateway.CreateModelProviderService":                        true,
	"catalog.AiGateway.CreateModelService":                                true,
	"catalog.AiGateway.UpdateMcpService":                                  true,
	"catalog.AiGateway.UpdateModelProviderService":                        true,
	"catalog.AiGateway.UpdateModelService":                                true,
	"catalog.Credentials.CreateCredential":                                true,
	"catalog.Credentials.DeleteCredential":                                true,
	"catalog.EntityTagAssignments.Create":                                 true,
	"catalog.EntityTagAssignments.Delete":                                 true,
	"catalog.EntityTagAssignments.Update":                                 true,
	"catalog.ExternalLocations.Create":                                    true,
	"catalog.StorageCredentials.Create":                                   true,
	"catalog.StorageCredentials.Delete":                                   true,
	"cleanrooms.CleanRoomAssets.CreateCleanRoomAssetReview":               true,
	"cleanrooms.CleanRoomAutoApprovalRules.Create":                        true,
	"cleanrooms.CleanRoomAutoApprovalRules.Delete":                        true,
	"cleanrooms.CleanRoomAutoApprovalRules.Update":                        true,
	"compute.ClusterPolicies.Create":                                      true,
	"compute.ClusterPolicies.Delete":                                      true,
	"compute.ClusterPolicies.Edit":                                        true,
	"compute.PolicyComplianceForClusters.CancelPendingClusterEnforcement": true,
	"dashboards.Lakeview.Publish":                                         true,
	"database.Database.CreateDatabaseInstance":                            true,
	"database.Database.CreateDatabaseInstanceRole":                        true,
	"database.Database.DeleteDatabaseInstanceRole":                        true,
	"database.Database.UpdateDatabaseInstance":                            true,
	"dataclassification.DataClassification.CreateCatalogConfig":           true,
	"dataclassification.DataClassification.DeleteCatalogConfig":           true,
	"dataclassification.DataClassification.UpdateCatalogConfig":           true,
	"jobs.Jobs.Reset":                                                     true,
	"jobs.Jobs.Update":                                                    true,
	"marketplace.ProviderExchangeFilters.Create":                          true,
	"marketplace.ProviderExchangeFilters.Delete":                          true,
	"marketplace.ProviderExchangeFilters.Update":                          true,
	"marketplace.ProviderExchanges.AddListingToExchange":                  true,
	"marketplace.ProviderExchanges.Create":                                true,
	"marketplace.ProviderExchanges.DeleteListingFromExchange":             true,
	"marketplace.ProviderExchanges.Update":                                true,
	"marketplace.ProviderListings.Create":                                 true,
	"marketplace.ProviderListings.Update":                                 true,
	"marketplace.ProviderPersonalizationRequests.Update":                  true,
	"ml.FeatureEngineering.CreateKafkaConfig":                             true,
	"ml.FeatureEngineering.CreateStream":                                  true,
	"ml.FeatureEngineering.UpdateKafkaConfig":                             true,
	"ml.FeatureEngineering.UpdateStream":                                  true,
	"ml.ModelRegistry.CreateWebhook":                                      true,
	"ml.ModelRegistry.UpdateWebhook":                                      true,
	"oauth2.ServicePrincipalSecrets.Create":                               true,
	"oauth2.ServicePrincipalSecrets.Delete":                               true,
	"oauth2.ServicePrincipalSecretsProxy.Create":                          true,
	"oauth2.ServicePrincipalSecretsProxy.Delete":                          true,
	"pipelines.Pipelines.Create":                                          true,
	"pipelines.Pipelines.Update":                                          true,
	"postgres.Postgres.CreateBranch":                                      true,
	"postgres.Postgres.CreateDataApi":                                     true,
	"postgres.Postgres.CreateDatabase":                                    true,
	"postgres.Postgres.CreateProject":                                     true,
	"postgres.Postgres.CreateRole":                                        true,
	"postgres.Postgres.DeleteRole":                                        true,
	"postgres.Postgres.UpdateBranch":                                      true,
	"postgres.Postgres.UpdateDataApi":                                     true,
	"postgres.Postgres.UpdateDatabase":                                    true,
	"postgres.Postgres.UpdateProject":                                     true,
	"postgres.Postgres.UpdateRole":                                        true,
	"serving.ServingEndpoints.Create":                                     true,
	"serving.ServingEndpoints.CreateProvisionedThroughputEndpoint":        true,
	"serving.ServingEndpoints.HttpRequest":                                true,
	"serving.ServingEndpoints.PatchTelemetryConfig":                       true,
	"serving.ServingEndpoints.Put":                                        true,
	"serving.ServingEndpoints.PutAiGateway":                               true,
	"serving.ServingEndpoints.UpdateConfig":                               true,
	"settings.TokenManagement.CreateOboToken":                             true,
	"settings.TokenManagement.Delete":                                     true,
	"sharing.Recipients.RotateToken":                                      true,
	"sql.AlertsV2.CreateAlert":                                            true,
	"sql.AlertsV2.UpdateAlert":                                            true,
	"sql.Dashboards.Update":                                               true,
	"sql.Queries.Create":                                                  true,
	"sql.Queries.Update":                                                  true,
	"sql.QueriesLegacy.Create":                                            true,
	"sql.QueriesLegacy.Update":                                            true,
	"sql.QueryVisualizationsLegacy.Update":                                true,
	"sql.Warehouses.CreateDefaultWarehouseOverride":                       true,
	"sql.Warehouses.DeleteDefaultWarehouseOverride":                       true,
	"sql.Warehouses.SetWorkspaceWarehouseConfig":                          true,
	"sql.Warehouses.UpdateDefaultWarehouseOverride":                       true,
	"tags.WorkspaceEntityTagAssignments.CreateTagAssignment":              true,
	"tags.WorkspaceEntityTagAssignments.DeleteTagAssignment":              true,
	"tags.WorkspaceEntityTagAssignments.UpdateTagAssignment":              true,
	"workspace.GitCredentials.Create":                                     true,
	"workspace.GitCredentials.Delete":                                     true,
	"workspace.GitCredentials.Update":                                     true,
	"workspace.Secrets.CreateScope":                                       true,
	"workspace.Secrets.DeleteAcl":                                         true,
	"workspace.Secrets.PutAcl":                                            true,
}

// databricksDeleteOperations can destroy data under a name that does not
// say so: repos update --dangerously-force-discard-all drops uncommitted
// work, uninstalling a library removes it at the next restart, an upload or
// import with overwrite replaces what was there, and an endpoint tag patch
// takes delete_tags.
var databricksDeleteOperations = map[string]bool{
	"compute.Libraries.Uninstall":    true,
	"files.Dbfs.Create":              true,
	"files.Dbfs.Put":                 true,
	"files.Files.Upload":             true,
	"serving.ServingEndpoints.Patch": true,
	"workspace.Repos.Update":         true,
	"workspace.Workspace.Import":     true,
}

// databricksConsumingGets are GETs that change state: retrieving a
// recipient's credential uses up its one-time activation link.
var databricksConsumingGets = map[string]bool{
	"sharing.RecipientActivation.RetrieveToken": true,
}

// databricksPostReads are the POST operations a reviewer confirmed change
// nothing. Every other POST is at least a write. Credential validation is
// not here: it can test WRITE and DELETE against external storage.
var databricksPostReads = map[string]bool{
	"agentkit.AgentKit.SearchMemories":                              true,
	"aisearch.AiSearch.QueryIndex":                                  true,
	"aisearch.AiSearch.ScanIndex":                                   true,
	"compute.Clusters.Events":                                       true,
	"mason.Mason.SearchMemories":                                    true,
	"ml.Experiments.SearchExperiments":                              true,
	"ml.Experiments.SearchLoggedModels":                             true,
	"ml.Experiments.SearchRuns":                                     true,
	"ml.ModelRegistry.GetLatestVersions":                            true,
	"vectorsearch.VectorSearchEndpoints.RetrieveUserVisibleMetrics": true,
	"vectorsearch.VectorSearchIndexes.QueryIndex":                   true,
	"vectorsearch.VectorSearchIndexes.QueryNextPage":                true,
	"vectorsearch.VectorSearchIndexes.ScanIndex":                    true,
}

// databricksCommandAliases map SDK API wrappers the CLI calls to the
// operation they make (SharesAPI.List in ext_api.go calls ListShares).
var databricksCommandAliases = map[string]string{
	"sharing.Shares.List": "sharing.Shares.ListShares",
}

// databricksHandCommands are hand-written CLI commands that run many
// requests rather than one route, and generated commands the CLI overloads
// (without an app name, apps deploy deploys the bundle and apps delete
// destroys it). bundle deploy applies
// the bundle's permissions blocks through SetPermissions, and bundle destroy
// can delete Postgres roles, so all three are admin unless the caller
// inspects the bundle. A command listed here is dropped
// from the operation it would otherwise map to.
var databricksHandCommands = []databricksEntry{
	{Operation: "cli.apps.delete", Commands: []string{"apps delete"}, Product: "workloads", Access: "admin"},
	{Operation: "cli.apps.deploy", Commands: []string{"apps deploy"}, Product: "execution", Access: "admin"},
	{Operation: "cli.bundle.deploy", Commands: []string{"bundle deploy"}, Product: "execution", Access: "admin"},
	{Operation: "cli.bundle.destroy", Commands: []string{"bundle destroy"}, Product: "workloads", Access: "admin"},
	{Operation: "cli.bundle.run", Commands: []string{"bundle run"}, Product: "execution", Access: "write"},
}
