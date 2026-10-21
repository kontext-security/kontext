package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
)

// A shell command carrying a connection string must not leave the endpoint
// with its password. Failure modes this test pins:
//
//  1. scheme://user:pass@ for a non-HTTP scheme survives into the stored
//     action and so into the ledger batch the uploader sends;
//  2. a password with a literal @ leaks the part after its first @;
//  3. redaction drops the scheme or host, so the admin cannot see what the
//     agent connected to.
func TestURLCredentialsNeverLeaveTheEndpoint(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)

	schemes := []string{"postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "amqp", "https"}
	commands := map[string]string{
		// 2
		"at-sign":    "psql postgres://app:FAKE-at@sign-tail@db.example.test/app",
		"apostrophe": `psql "postgres://app:FAKE-quote'pw@db.example.test/app"`,
	}
	passwords := []string{"FAKE-at", "sign-tail", "FAKE-quote'pw"}
	for _, scheme := range schemes {
		password := "FAKE-" + scheme + "-pw"
		passwords = append(passwords, password)
		commands[scheme] = "DATABASE_URL=" + scheme + "://app:" + password + "@db.example.test:5432/app ./migrate"
	}
	// One hook event per command: the stored command summary is bounded.
	for name, command := range commands {
		if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
			SessionID:     "s1",
			HookEventName: "PreToolUse",
			ToolName:      "Bash",
			ToolUseID:     "toolu_" + name,
			ToolInput:     map[string]any{"command": command},
		}); err != nil {
			t.Fatal(err)
		}
	}

	batch, err := store.LedgerBatch(context.Background(), sqlite.LedgerExportOptions{Limit: 100, ReceiptLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Actions) < len(commands) {
		t.Fatalf("ledger batch has %d actions, want at least %d", len(batch.Actions), len(commands))
	}
	encoded, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	upload := string(encoded)
	for _, password := range passwords {
		if strings.Contains(upload, password) {
			t.Errorf("password %q leaves the endpoint in the ledger batch", password)
		}
	}
	for _, scheme := range schemes {
		if !strings.Contains(upload, "DATABASE_URL="+scheme+"://[REDACTED_SECRET]@db.example.test:5432/app") {
			t.Errorf("redacted %s URL lost its scheme or host", scheme)
		}
	}
}
