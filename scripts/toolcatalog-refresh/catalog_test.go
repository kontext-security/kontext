package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Every embedded catalog, URL fields included, survives a read and a write
// byte for byte, so a refresh never drops or reorders a field it does not
// manage.
func TestCatalogRoundTripPreservesEveryField(t *testing.T) {
	paths, err := filepath.Glob("../../internal/toolcatalog/providers/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no catalogs: %v", err)
	}
	withKinds := filepath.Join(t.TempDir(), "kinds.json")
	if err := os.WriteFile(withKinds, []byte(`{
  "provider": "x",
  "toolIdPrefix": "x-mcp/",
  "version": "1",
  "serverNameHints": [
    "x"
  ],
  "serverUrlHints": [
    {
      "host": "*.example.com",
      "pathPrefix": "/api/2.0/mcp/"
    }
  ],
  "urlKinds": [
    {
      "pathPrefix": "/api/2.0/mcp/functions/",
      "toolId": "x-mcp/a"
    }
  ],
  "sources": [],
  "dispatchers": [],
  "tools": [
    {
      "name": "a",
      "product": "p",
      "access": "write"
    }
  ]
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range append(paths, withKinds) {
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		c, err := readCatalog(path)
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "out.json")
		if err := writeCatalog(out, c); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(out)
		if !bytes.Equal(got, want) {
			t.Errorf("%s does not round-trip:\n%s", filepath.Base(path), got)
		}
	}
}
