package toolcatalog

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Access tiers a provider catalog assigns to each tool. Presets forbid by
// tier: read-only blocks everything that is not "read"; delete and admin are
// writes too, listed separately so narrower presets can target them.
const (
	AccessRead   = "read"
	AccessWrite  = "write"
	AccessDelete = "delete"
	AccessAdmin  = "admin"
)

// UnrecognizedToolName is the tool id suffix a provider's calls resolve to
// when the call is plainly that provider's but the catalog does not list it.
const UnrecognizedToolName = "unrecognized"

//go:embed providers/*.json
var providerCatalogFS embed.FS

// ProviderCatalog is one SaaS MCP server's tool list. The JSON files under
// providers/ are the contract shared with kontext-cloud, which carries a
// byte-identical copy and derives its presets from it.
type ProviderCatalog struct {
	Provider        string               `json:"provider"`
	ToolIDPrefix    string               `json:"toolIdPrefix"`
	Version         string               `json:"version"`
	ServerNameHints []string             `json:"serverNameHints"`
	Sources         []string             `json:"sources"`
	Dispatchers     []ProviderDispatcher `json:"dispatchers"`
	Tools           []ProviderTool       `json:"tools"`
}

// ProviderDispatcher is a meta-tool that runs another catalog operation by
// name (Atlassian's execute, executeRead, executeWrite, executeDestructive).
// The call is judged as the operation it names, never as the dispatcher.
type ProviderDispatcher struct {
	Name           string `json:"name"`
	OperationField string `json:"operationField"`
	// Distinctive dispatchers (executeWrite) are the provider's under any
	// server name, so an operation the catalog does not list is
	// unrecognized there too, not passed through. A generic name (execute)
	// is the provider's only on a hinted server or with a catalogued
	// operation.
	Distinctive bool `json:"distinctive,omitempty"`
}

type ProviderTool struct {
	Name    string `json:"name"`
	Product string `json:"product"`
	Access  string `json:"access"`
	// Distinctive names cannot plausibly belong to another product, so they
	// resolve under any server name. Generic names (search, getTeam) resolve
	// only on a server whose name carries one of ServerNameHints.
	Distinctive bool `json:"distinctive,omitempty"`
	// Definition fingerprints the tool's full upstream definition, so the
	// refresh notices a tool that changes behaviour under the same name. It
	// does not change a decision and is left out of the digest.
	Definition string `json:"definition,omitempty"`
}

type providerIndex struct {
	catalog     ProviderCatalog
	tools       map[string]ProviderTool
	dispatchers map[string]ProviderDispatcher
}

var providers = loadProviderCatalogs()

// Providers returns the embedded provider catalogs, ordered by provider.
func Providers() []ProviderCatalog {
	out := make([]ProviderCatalog, len(providers))
	for i := range providers {
		out[i] = providers[i].catalog
	}
	return out
}

// providerDigest pins a provider catalog the way the GitHub commit pins the
// GitHub one. It covers every field that changes a decision (version, tool
// names and tiers, dispatchers), so the cloud, computing the same value from
// its copy, notices any drift between the two. Tools are already sorted.
func providerDigest(catalog ProviderCatalog) string {
	var material strings.Builder
	material.WriteString(catalog.ToolIDPrefix + "\x00" + catalog.Version + "\x00")
	for _, dispatcher := range catalog.Dispatchers {
		material.WriteString("dispatch\t" + dispatcher.Name + "\t" + dispatcher.OperationField + "\n")
	}
	for _, tool := range catalog.Tools {
		material.WriteString(tool.Name + "\t" + tool.Access + "\n")
	}
	sum := sha256.Sum256([]byte(material.String()))
	return hex.EncodeToString(sum[:])
}

// resolveProvider maps an MCP call to a provider catalog id. A server named
// for the provider is held to the catalog (anything unlisted is
// unrecognized, fail-closed); under any other server name only distinctive
// tool names and dispatchers carrying a catalogued operation resolve.
func resolveProvider(server, tool string, input map[string]any) (string, bool) {
	lowerServer := strings.ToLower(server)
	for i := range providers {
		p := &providers[i]
		hinted := false
		for _, hint := range p.catalog.ServerNameHints {
			if strings.Contains(lowerServer, hint) {
				hinted = true
				break
			}
		}
		if dispatcher, ok := p.dispatchers[tool]; ok {
			operation, _ := input[dispatcher.OperationField].(string)
			if catalogued, known := p.tools[operation]; known {
				return p.catalog.ToolIDPrefix + catalogued.Name, true
			}
			if hinted || dispatcher.Distinctive {
				return p.catalog.ToolIDPrefix + UnrecognizedToolName, true
			}
			continue
		}
		catalogued, known := p.tools[tool]
		switch {
		case known && (hinted || catalogued.Distinctive):
			return p.catalog.ToolIDPrefix + catalogued.Name, true
		case hinted:
			return p.catalog.ToolIDPrefix + UnrecognizedToolName, true
		}
	}
	return "", false
}

func knownProviderTool(toolID string) bool {
	for i := range providers {
		name, ok := strings.CutPrefix(toolID, providers[i].catalog.ToolIDPrefix)
		if !ok {
			continue
		}
		if name == UnrecognizedToolName {
			return true
		}
		_, ok = providers[i].tools[name]
		return ok
	}
	return false
}

// ProviderToolAccess returns the catalog tier of a resolved provider tool id,
// or "" for unrecognized and non-provider ids.
func ProviderToolAccess(toolID string) string {
	for i := range providers {
		if name, ok := strings.CutPrefix(toolID, providers[i].catalog.ToolIDPrefix); ok {
			return providers[i].tools[name].Access
		}
	}
	return ""
}

// ProviderClassification is a catalogued provider tool's tier, which the
// daemon passes to Cedar so presets can forbid by tier.
type ProviderClassification struct {
	Provider string
	Product  string
	Access   string
}

// Classify returns the catalog entry behind a provider tool id. Unrecognized
// and non-provider ids have none.
func Classify(toolID string) (ProviderClassification, bool) {
	for i := range providers {
		name, ok := strings.CutPrefix(toolID, providers[i].catalog.ToolIDPrefix)
		if !ok {
			continue
		}
		tool, ok := providers[i].tools[name]
		if !ok {
			return ProviderClassification{}, false
		}
		return ProviderClassification{Provider: providers[i].catalog.Provider, Product: tool.Product, Access: tool.Access}, true
	}
	return ProviderClassification{}, false
}

func loadProviderCatalogs() []providerIndex {
	entries, err := providerCatalogFS.ReadDir("providers")
	if err != nil {
		panic("embedded provider catalogs: " + err.Error())
	}
	var out []providerIndex
	for _, entry := range entries {
		raw, err := providerCatalogFS.ReadFile("providers/" + entry.Name())
		if err != nil {
			panic("embedded provider catalog " + entry.Name() + ": " + err.Error())
		}
		catalog, err := ParseProviderCatalog(raw)
		if err != nil {
			panic("embedded provider catalog " + entry.Name() + ": " + err.Error())
		}
		index := providerIndex{
			catalog:     catalog,
			tools:       make(map[string]ProviderTool, len(catalog.Tools)),
			dispatchers: make(map[string]ProviderDispatcher, len(catalog.Dispatchers)),
		}
		for _, tool := range catalog.Tools {
			index.tools[tool.Name] = tool
		}
		for _, dispatcher := range catalog.Dispatchers {
			index.dispatchers[dispatcher.Name] = dispatcher
		}
		out = append(out, index)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].catalog.Provider < out[j].catalog.Provider })
	return out
}

// ParseProviderCatalog decodes and checks a provider catalog. Every tool
// needs a known access tier: a refresh that adds a tool without classifying
// it fails here instead of shipping an unclassified operation.
func ParseProviderCatalog(raw []byte) (ProviderCatalog, error) {
	var catalog ProviderCatalog
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return ProviderCatalog{}, err
	}
	if catalog.Provider == "" || catalog.Version == "" || !strings.HasSuffix(catalog.ToolIDPrefix, "-mcp/") {
		return ProviderCatalog{}, fmt.Errorf("provider, version and a <name>-mcp/ toolIdPrefix are required")
	}
	if catalog.ToolIDPrefix == GitHubToolPrefix {
		return ProviderCatalog{}, fmt.Errorf("the GitHub catalog is pinned separately")
	}
	seen := map[string]bool{}
	for _, dispatcher := range catalog.Dispatchers {
		if dispatcher.Name == "" || dispatcher.OperationField == "" || seen[dispatcher.Name] {
			return ProviderCatalog{}, fmt.Errorf("dispatcher %q is incomplete or duplicated", dispatcher.Name)
		}
		seen[dispatcher.Name] = true
	}
	for i, tool := range catalog.Tools {
		if tool.Name == "" || tool.Name == UnrecognizedToolName || seen[tool.Name] {
			return ProviderCatalog{}, fmt.Errorf("tool %q is empty, reserved or duplicated", tool.Name)
		}
		seen[tool.Name] = true
		switch tool.Access {
		case AccessRead, AccessWrite, AccessDelete, AccessAdmin:
		default:
			return ProviderCatalog{}, fmt.Errorf("tool %q has unclassified access %q", tool.Name, tool.Access)
		}
		if tool.Product == "" {
			return ProviderCatalog{}, fmt.Errorf("tool %q has no product", tool.Name)
		}
		if i > 0 && catalog.Tools[i-1].Name > tool.Name {
			return ProviderCatalog{}, fmt.Errorf("tools must be sorted by name (%q before %q)", catalog.Tools[i-1].Name, tool.Name)
		}
	}
	return catalog, nil
}
