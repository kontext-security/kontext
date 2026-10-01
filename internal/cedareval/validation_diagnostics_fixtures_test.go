package cedareval_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/toolcatalog"
)

// The validation-diagnostics corpus pins the portable policy dialect: entries
// the management plane accepts must construct and evaluate in this engine
// without engine errors, and rejected entries never reach an endpoint.
type validationDiagnosticsCorpus struct {
	Version       int                            `json:"version"`
	SmokeRequests []cedareval.ToolUseInput       `json:"smokeRequests"`
	Fixtures      []validationDiagnosticsFixture `json:"fixtures"`
}

type validationDiagnosticsFixture struct {
	Version             int     `json:"version"`
	Name                string  `json:"name"`
	Description         string  `json:"description"`
	PolicyText          *string `json:"policyText"`
	PolicyTextGenerator *struct {
		Kind  string `json:"kind"`
		Text  string `json:"text"`
		Count int    `json:"count"`
	} `json:"policyTextGenerator"`
	Expected struct {
		Valid           bool     `json:"valid"`
		DiagnosticCodes []string `json:"diagnosticCodes"`
	} `json:"expected"`
}

const (
	validationDiagnosticsCorpusVersion = 1
	unsupportedToolIDCode              = "unsupported_tool_id"
)

var toolResourcePattern = regexp.MustCompile(`Kontext::Tool::"([^"]*)"`)

// expectedWarningCodes mirrors the management plane's unsupported_tool_id
// emission (isReportedCedarToolId): resolveTool sends shell for every shell
// alias, github-mcp/* for GitHub MCP tools, and any other tool's own name, so
// only an empty id, a shell alias other than shell, a raw GitHub MCP name or an
// uncatalogued github-mcp id can never match. The warning never rejects the
// policy, so an accepted fixture may carry it.
func expectedWarningCodes(policyText string) []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, match := range toolResourcePattern.FindAllStringSubmatch(policyText, -1) {
		id := match[1]
		if reportedToolID(id) || seen[id] {
			continue
		}
		seen[id] = true
		codes = append(codes, unsupportedToolIDCode)
	}
	return codes
}

func reportedToolID(id string) bool {
	normalized := strings.ToLower(strings.TrimSpace(id))
	switch normalized {
	case "":
		return false
	case "bash", "shell", "shell_command", "unified_exec", "exec_command", "local_shell":
		return id == cedareval.ToolShellV2
	}
	if rest, ok := strings.CutPrefix(id, "mcp__"); ok {
		if server, _, found := strings.Cut(rest, "__"); found && strings.Contains(strings.ToLower(server), "github") {
			return false
		}
	}
	return !strings.HasPrefix(id, toolcatalog.GitHubToolPrefix) || toolcatalog.Known(id)
}

func TestPortableValidationDiagnosticsFixtures(t *testing.T) {
	var corpus validationDiagnosticsCorpus
	readFixture(t, "validation-diagnostics-v1.json", &corpus)

	if corpus.Version != validationDiagnosticsCorpusVersion {
		t.Fatalf("corpus version = %d, want %d", corpus.Version, validationDiagnosticsCorpusVersion)
	}
	if len(corpus.SmokeRequests) == 0 {
		t.Fatal("corpus carries no smoke requests")
	}
	accepted := 0
	for _, fixture := range corpus.Fixtures {
		if fixture.Expected.Valid {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatal("corpus carries no accepted-dialect fixtures")
	}

	for _, fixture := range corpus.Fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			if fixture.Version != validationDiagnosticsCorpusVersion {
				t.Fatalf("fixture version = %d, want %d", fixture.Version, validationDiagnosticsCorpusVersion)
			}
			if !fixture.Expected.Valid {
				if len(fixture.Expected.DiagnosticCodes) == 0 {
					t.Fatal("rejected fixture lists no diagnostic codes")
				}
				return
			}
			if fixture.PolicyText == nil {
				t.Fatal("accepted fixture carries no inline policy text")
			}
			want := expectedWarningCodes(*fixture.PolicyText)
			got := fixture.Expected.DiagnosticCodes
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("accepted fixture diagnostic codes = %v, want %v", got, want)
			}

			evaluator, err := cedareval.New(*fixture.PolicyText)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			for _, request := range corpus.SmokeRequests {
				result, err := evaluator.Evaluate(request)
				if err != nil {
					t.Fatalf("Evaluate(%s) error = %v", request.ToolName, err)
				}
				if len(result.EngineDiagnostics.Errors) != 0 {
					t.Errorf(
						"Evaluate(%s) EngineDiagnostics.Errors = %v, want none",
						request.ToolName,
						result.EngineDiagnostics.Errors,
					)
				}
			}
		})
	}
}
