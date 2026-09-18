// cost-register-codex attaches one explicitly selected local transcript to the
// existing collector. It does not execute hooks or create policy/tool events.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
)

func register(db, path, session string) error {
	if !filepath.IsAbs(path) || session == "" {
		return fmt.Errorf("an absolute transcript path and session ID are required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var meta struct {
		Type    string `json:"type"`
		Payload struct {
			ID       string `json:"id"`
			Provider string `json:"model_provider"`
			CWD      string `json:"cwd"`
		} `json:"payload"`
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	if !scanner.Scan() {
		return fmt.Errorf("missing session metadata: %v", scanner.Err())
	}
	if err := json.Unmarshal(scanner.Bytes(), &meta); err != nil {
		return err
	}
	if meta.Type != "session_meta" || meta.Payload.ID != session || meta.Payload.Provider != "openai" {
		return fmt.Errorf("transcript does not belong to the selected OpenAI session")
	}
	store, err := sqlite.OpenStore(db)
	if err != nil {
		return err
	}
	defer store.Close()
	// The cloud requires each usage batch to include its owning session.
	if _, err := store.BackfillObservedSessionWithMode(context.Background(), "codex-"+session, "codex", meta.Payload.CWD, "observe"); err != nil {
		return err
	}
	// Reuse source registration only. No fabricated Stop event is ingested.
	return store.TrackToolTranscript(context.Background(), hook.Event{
		SessionID: "codex-" + session, Agent: "codex",
		HookName: hook.HookStop, TranscriptPath: path,
	})
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: cost-register-codex DB TRANSCRIPT SESSION_ID")
		os.Exit(1)
	}
	if err := register(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Registered Codex session for ongoing local usage capture:", os.Args[3])
}
