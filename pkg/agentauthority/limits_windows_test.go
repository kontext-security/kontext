//go:build windows

package agentauthority

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadGuardedFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// stat is answered by guardedInfo in access, not by readGuarded.
	for _, mode := range []string{"read", "list", "tail", "cursor"} {
		result := readGuarded(context.Background(), path, mode)
		if !errors.Is(result.err, os.ErrPermission) || result.opened || result.data != nil || result.entries != nil || result.parsed != nil {
			t.Errorf("%s: got %+v, want a refused read", mode, result)
		}
	}
	if isEvictedErr(os.ErrPermission) {
		t.Error("isEvictedErr reported an ordinary refusal as an eviction")
	}
}
