package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHasCoworkSessionsSince(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	since := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if _, err := HasCoworkSessionsSince(ctx, path, since); err == nil {
		t.Fatal("missing store must be unknown")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("read created a store")
	}
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, tt := range []struct {
		name, agent string
		at          time.Time
		want        bool
	}{
		{"other agent", "claude", time.Now(), false},
		{"expired cowork", "cowork", since.Add(-time.Second), false},
		{"recent cowork", "cowork", since.Add(time.Second), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := store.EnsureObservedSession(ctx, tt.name, tt.agent, "/tmp"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, "update agent_sessions set updated_at = ? where id = ?", tt.at.UTC().Format(time.RFC3339Nano), NormalizeSessionID(tt.name)); err != nil {
				t.Fatal(err)
			}
			got, err := HasCoworkSessionsSince(ctx, path, since)
			if err != nil || got != tt.want {
				t.Fatalf("got %t, %v; want %t", got, err, tt.want)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := HasCoworkSessionsSince(canceled, path, since); err == nil {
		t.Fatal("canceled query must be unknown")
	}
}
