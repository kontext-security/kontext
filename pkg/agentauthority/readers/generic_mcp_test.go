package readers

import "testing"

// serverUrl is a legacy key one agent still accepts, in a reader every generic
// config goes through. Ways it can fail: a server that uses it has no URL; it
// beats a server's own url; or a value of another type, meaningless to agents
// that never read the key, fails the file and loses all of its servers.
func TestGenericMCPReadsTheLegacyServerURLKey(t *testing.T) {
	t.Parallel()
	servers, err := GenericMCP([]byte(`{"mcpServers":{
		"plain":{"url":"https://plain.example/mcp"},
		"legacy":{"serverUrl":"https://legacy.example/mcp"},
		"both":{"url":"https://url-wins.example/mcp","serverUrl":"https://ignored.example/mcp"},
		"number":{"command":"node","serverUrl":5},
		"object":{"command":"node","serverUrl":{"nested":true}},
		"null":{"command":"node","serverUrl":null}
	}}`), "mcpServers")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"plain":  "https://plain.example/mcp",
		"legacy": "https://legacy.example/mcp",
		"both":   "https://url-wins.example/mcp",
		"number": "",
		"object": "",
		"null":   "",
	} {
		server, ok := servers[name]
		if !ok {
			t.Errorf("%s was dropped", name)
			continue
		}
		if server.URL != want {
			t.Errorf("%s url = %q, want %q", name, server.URL, want)
		}
	}
	if servers["number"].Command != "node" {
		t.Fatalf("number lost its command: %+v", servers["number"])
	}
	if servers, err := GenericMCP([]byte(`{}`), "mcpServers"); err != nil || servers != nil {
		t.Fatalf("no key = %v, %v", servers, err)
	}
	if servers, err := GenericMCP([]byte(`{"mcpServers":null}`), "mcpServers"); err != nil || servers != nil {
		t.Fatalf("null key = %v, %v", servers, err)
	}
	if _, err := GenericMCP([]byte(`{"mcpServers":{"bad":{"url":5}}}`), "mcpServers"); err == nil {
		t.Fatal("a url of another type stays an error")
	}
}
