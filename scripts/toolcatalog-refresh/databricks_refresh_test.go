package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestKeepDatabricksRoutes(t *testing.T) {
	old := &databricksTable{CLI: "v1.0.0", SDK: "v0.1.0", Routes: []databricksEntry{
		{Operation: "svc.A.Update", Method: "POST", Path: "/api/2.0/a", Commands: []string{"a update"}, Product: "compute", Access: "admin"},
		{Operation: "svc.A.Purge", Method: "POST", Path: "/api/2.0/a/purge", Commands: []string{"a purge"}, Product: "compute", Access: "delete"},
		{Operation: "svc.Old.Get", Method: "GET", Path: "/api/2.0/old", Commands: []string{"old get"}, Product: "compute", Access: "read"},
		{Operation: "svc.A.List", Method: "GET", Path: "/api/2.0/a", Commands: []string{"a list", "a ls"}, Product: "compute", Access: "read"},
	}}
	fresh := &databricksTable{CLI: "v1.1.0", SDK: "v0.2.0", Routes: []databricksEntry{
		{Operation: "svc.A.Update", Method: "POST", Path: "/api/2.0/a", Commands: []string{"a update"}, Product: "compute", Access: "write"},
		{Operation: "svc.New.Get", Method: "GET", Path: "/api/2.0/old", Commands: []string{"old get"}, Product: "sql", Access: "read"},
		{Operation: "svc.A.List", Method: "GET", Path: "/api/2.0/a", Commands: []string{"a list"}, Product: "compute", Access: "read"},
		{Operation: "svc.B.Run", Method: "POST", Path: "/api/2.0/b", Commands: []string{"b run"}, Product: "execution", Access: "write"},
	}}
	r := &refresher{}
	r.keepDatabricksRoutes(old, fresh)

	// The purge upstream dropped is kept with its command, and a dropped
	// alias stays on its operation.
	byOperation := map[string]databricksEntry{}
	for _, entry := range fresh.Routes {
		byOperation[entry.Operation] = entry
	}
	if got := byOperation["svc.A.Purge"]; got.Access != "delete" || !reflect.DeepEqual(got.Commands, []string{"a purge"}) {
		t.Fatalf("dropped operation not kept: %+v", got)
	}
	if got := byOperation["svc.A.List"].Commands; !reflect.DeepEqual(got, []string{"a list", "a ls"}) {
		t.Fatalf("dropped command not kept: %v", got)
	}
	if _, ok := byOperation["svc.Old.Get"]; ok {
		t.Fatal("a renamed operation must not be kept next to its replacement")
	}
	report := strings.Join(r.report, "\n")
	for _, want := range []string{
		"`svc.A.Purge` (delete)",
		"`svc.A.Update` (admin to write)",
		"`svc.Old.Get` renamed `svc.New.Get`",
		"`svc.Old.Get` (compute to sql)",
		"`a ls` (on `svc.A.List`)",
		"svc.B.Run (execution, write)",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	// svc.New.Get is a new read, and a tier and a product moved.
	if len(r.review) != 4 {
		t.Fatalf("review = %q", r.review)
	}
}

func TestKeepDatabricksRoutesStrictOnly(t *testing.T) {
	old := &databricksTable{Routes: []databricksEntry{{Operation: "svc.A.Update", Method: "POST", Path: "/a", Product: "compute", Access: "write"}}}
	fresh := &databricksTable{Routes: []databricksEntry{
		{Operation: "svc.A.Update", Method: "POST", Path: "/a", Product: "compute", Access: "admin"},
		{Operation: "svc.A.Delete", Method: "POST", Path: "/a/delete", Product: "compute", Access: "delete"},
	}}
	r := &refresher{routes: fresh}
	r.keepDatabricksRoutes(old, fresh)
	if r.kind() != "strict-only" {
		t.Fatalf("kind = %s, review %q", r.kind(), r.review)
	}
}

func TestHandWrittenCommands(t *testing.T) {
	got := handWrittenCommands(sourceTree{
		"cmd/cmd.go":                 []byte(`Use: "databricks"`),
		"cmd/bundle/bundle.go":       []byte(`cmd := &cobra.Command{Use: "bundle"}`),
		"cmd/bundle/deploy.go":       []byte(`cmd := &cobra.Command{Use: "deploy [flags]"}`),
		"cmd/bundle/sub/purge.go":    []byte(`cmd.Use = "purge"`),
		"cmd/bundle/deploy_test.go":  []byte(`Use: "fake"`),
		"cmd/workspace/jobs/jobs.go": []byte(`Use: "list"`),
	})
	want := map[string]bool{"bundle deploy": true, "bundle purge": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

// fakeDatabricks serves the OAuth token endpoint and MCP servers whose
// tools/list returns tools[path].
func fakeDatabricks(t *testing.T, tools map[string][]map[string]any) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oidc/v1/token" {
			id, secret, ok := request.BasicAuth()
			body, _ := io.ReadAll(request.Body)
			if !ok || id != "client" || secret != "s3cret" || string(body) != "grant_type=client_credentials&scope=all-apis" {
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"error":"invalid_client"}`)
				return
			}
			io.WriteString(w, `{"access_token":"tok","token_type":"Bearer"}`)
			return
		}
		served, ok := tools[request.URL.Path]
		if !ok || request.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var message struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		json.NewDecoder(request.Body).Decode(&message)
		if message.ID == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		result := map[string]any{}
		if message.Method == "tools/list" {
			result["tools"] = served
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": result})
	}))
}

func TestDatabricksToken(t *testing.T) {
	server := fakeDatabricks(t, nil)
	defer server.Close()
	r := &refresher{client: server.Client()}
	if token, err := r.databricksToken(server.URL, "client", "s3cret"); err != nil || token != "tok" {
		t.Fatalf("token %q, %v", token, err)
	}
	_, err := r.databricksToken(server.URL, "client", "wrong-secret")
	if err == nil || strings.Contains(err.Error(), "wrong-secret") || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("err = %v", err)
	}
}

func TestRefreshDatabricksMCP(t *testing.T) {
	server := fakeDatabricks(t, map[string][]map[string]any{
		"/api/2.0/mcp/sql": {
			{"name": "execute_sql", "description": "runs SQL"},
			{"name": "execute_sql_read_only", "annotations": map[string]any{"destructiveHint": true}},
		},
		"/ai-gateway/mcp-services/system.ai.sandbox":       {{"name": "run_code"}, {"name": "upload_file"}},
		"/ai-gateway/mcp-services/system.ai.genie_one_mcp": {{"name": "genie_new_thing"}},
		"/api/2.0/mcp/functions/main/default":              {{"name": "main__default__add"}},
		"/ai-gateway/mcp-services/system.ai.unknown":       {{"name": "x"}},
	})
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	t.Setenv("DATABRICKS_HOST", server.URL+"/")
	t.Setenv("DATABRICKS_CLIENT_ID", "client")
	t.Setenv("DATABRICKS_CLIENT_SECRET", "s3cret")
	t.Setenv("DATABRICKS_MCP_ENDPOINTS", "/api/2.0/mcp/sql, /ai-gateway/mcp-services/system.ai.sandbox\n/ai-gateway/mcp-services/system.ai.genie_one_mcp /api/2.0/mcp/functions/main/default /ai-gateway/mcp-services/system.ai.unknown /api/2.0/mcp/missing")

	databricks, err := readCatalog("../../internal/toolcatalog/providers/databricks-mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	atlassian := &catalog{Provider: "atlassian"}
	r := &refresher{client: server.Client()}
	r.refreshDatabricksMCP(databricks, atlassian, filepath.Join(t.TempDir(), "github-mcp.json"))
	report := strings.Join(r.report, "\n")

	tools := map[string]tool{}
	for _, item := range databricks.Tools {
		tools[item.Name] = item
	}
	for name, want := range map[string]tool{
		"upload_file":           {Name: "upload_file", Product: "execution", Access: "write"},
		"genie_new_thing":       {Name: "genie_new_thing", Product: "ai", Access: "write", Distinctive: true},
		"execute_sql_read_only": {Name: "execute_sql_read_only", Product: "sql", Access: "delete"},
	} {
		got := tools[name]
		got.Definition = ""
		if got != want {
			t.Errorf("%s = %+v, want %+v", name, got, want)
		}
	}
	if _, ok := tools["main__default__add"]; ok {
		t.Error("a per-workspace function name was catalogued")
	}
	for _, want := range []string{
		"per-workspace tool names, classified by URL as databricks-mcp/uc-function (1): `main__default__add`",
		`no product for server "system.ai.unknown"`,
		"/api/2.0/mcp/missing: check failed: initialize: HTTP 403",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	// A failed server means the listing is partial, so nothing is reported
	// gone, and the host never appears.
	if strings.Contains(report, "no longer listed") || strings.Contains(report, host) || strings.Contains(report, "s3cret") {
		t.Errorf("report:\n%s", report)
	}
	if r.kind() != "strict-only" || !r.dirty[databricks] || r.dirty[atlassian] {
		t.Fatalf("kind %s, review %q, dirty %v", r.kind(), r.review, r.dirty)
	}
}

func TestRefreshDatabricksMCPSkipsWithoutSecrets(t *testing.T) {
	for _, name := range []string{"DATABRICKS_HOST", "DATABRICKS_CLIENT_ID", "DATABRICKS_CLIENT_SECRET", "DATABRICKS_MCP_ENDPOINTS"} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	r := &refresher{}
	r.refreshDatabricksMCP(&catalog{}, &catalog{}, "")
	if len(r.report) != 1 || !strings.Contains(r.report[0], "skipped") {
		t.Fatalf("report = %q", r.report)
	}
}

func TestProductForHasNoDatabricksNameRule(t *testing.T) {
	if got := productFor("databricks", "execute_sql"); got != "" {
		t.Fatalf("productFor(databricks) = %q", got)
	}
	r := &refresher{}
	c := &catalog{Provider: "databricks"}
	r.merge(c, "src", []upstreamTool{{name: "nameless"}}, func(string) bool { return false })
	if len(c.Tools) != 0 || r.changed {
		t.Fatalf("a Databricks tool without a server product was added: %+v", c.Tools)
	}
}

// A dropped admin operation whose command moved to a write operation, and a
// new literal route that takes over an admin template's requests, both
// loosen a classification without changing any operation's own tier.
func TestKeepDatabricksRoutesCatchesIndirectLoosening(t *testing.T) {
	old := &databricksTable{Routes: []databricksEntry{
		{Operation: "svc.A.SetOwner", Method: "POST", Path: "/api/2.0/a/owner", Commands: []string{"a set-owner"}, Product: "admin", Access: "admin"},
		{Operation: "svc.Agents.Update", Method: "PATCH", Path: "/api/2.0/agents/{name}", Product: "ai", Access: "admin"},
	}}
	for _, fresh := range []*databricksTable{
		{Routes: []databricksEntry{
			{Operation: "svc.A.Edit", Method: "POST", Path: "/api/2.0/a/edit", Commands: []string{"a set-owner"}, Product: "admin", Access: "write"},
			{Operation: "svc.Agents.Update", Method: "PATCH", Path: "/api/2.0/agents/{name}", Product: "ai", Access: "admin"},
		}},
		{Routes: []databricksEntry{
			{Operation: "svc.A.SetOwner", Method: "POST", Path: "/api/2.0/a/owner", Commands: []string{"a set-owner"}, Product: "admin", Access: "admin"},
			{Operation: "svc.Agents.Update", Method: "PATCH", Path: "/api/2.0/agents/{name}", Product: "ai", Access: "admin"},
			{Operation: "svc.Agents.UpdateConfig", Method: "PATCH", Path: "/api/2.1/agents/config", Product: "ai", Access: "write"},
		}},
	} {
		r := &refresher{routes: fresh}
		r.keepDatabricksRoutes(old, fresh)
		if r.kind() != "review" {
			t.Errorf("kind = %s for %+v\n%s", r.kind(), fresh.Routes, strings.Join(r.report, "\n"))
		}
	}
}

func TestRouteTemplate(t *testing.T) {
	for _, c := range []struct {
		template, path string
		want           bool
	}{
		{"/api/2.0/agents/{name}", "/api/2.1/agents/config", true},
		{"/api/2.0/agents/{name}", "/api/2.0/agents/{other}", true},
		{"/api/2.0/agents/{name}", "/api/2.0/agents/a/b", false},
		{"/api/2.0/fs/files{file_path+}", "/api/2.0/fs/files/a/b", true},
		{"/oidc/{x}", "/oidc/v1", true},
		{"/oidc/{x}", "/api/2.0/oidc/v1", false},
	} {
		if got := routeTemplate(c.template).MatchString(c.path); got != c.want {
			t.Errorf("routeTemplate(%q).Match(%q) = %v", c.template, c.path, got)
		}
	}
}

func TestRefreshDatabricksMCPNeverEchoesAFullURL(t *testing.T) {
	server := fakeDatabricks(t, nil)
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	t.Setenv("DATABRICKS_HOST", host)
	t.Setenv("DATABRICKS_CLIENT_ID", "client")
	t.Setenv("DATABRICKS_CLIENT_SECRET", "s3cret")
	t.Setenv("DATABRICKS_MCP_ENDPOINTS", server.URL+"/api/2.0/mcp/sql")
	r := &refresher{client: server.Client()}
	r.refreshDatabricksMCP(&catalog{Provider: "databricks"}, &catalog{}, "")
	if report := strings.Join(r.report, "\n"); strings.Contains(report, host) || !strings.Contains(report, "not a server path") {
		t.Fatalf("report:\n%s", report)
	}
}
