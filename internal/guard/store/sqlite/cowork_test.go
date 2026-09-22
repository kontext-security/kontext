package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHasCoworkSession(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	if _, err := HasCoworkSession(ctx, path, "fixture"); err == nil {
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
	if _, err := store.EnsureObservedSession(ctx, "other-agent", "claude", "/tmp"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureObservedSession(ctx, "other-cowork", "cowork", "/tmp"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureObservedSession(ctx, "fixture", "cowork", "/tmp"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, id string
		want     bool
	}{
		{"other agent", "other-agent", false},
		{"other Cowork session", "other-cowork", true},
		{"exact Cowork session", "fixture", true},
		{"missing session", "missing", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HasCoworkSession(ctx, path, tt.id)
			if err != nil || got != tt.want {
				t.Fatalf("got %t, %v; want %t", got, err, tt.want)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := HasCoworkSession(canceled, path, "fixture"); err == nil {
		t.Fatal("canceled query must be unknown")
	}
}
