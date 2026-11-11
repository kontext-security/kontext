//go:build windows

package autostart

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// The entry in the user's own Run key: written, read back, replaced and
// removed, under a name of this test's own.
func TestEntryRoundTrip(t *testing.T) {
	previous := Value
	Value = fmt.Sprintf("KontextTest-%d-%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { _ = Remove(); Value = previous })

	if got, err := Entry(); err != nil || got != "" {
		t.Fatalf("entry before a write = %q, %v, want none", got, err)
	}
	if err := Set(`C:\Program Files\Kontext\kontextw.exe`); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, err := Entry(); err != nil || got != `"C:\Program Files\Kontext\kontextw.exe" managed-observe-daemon` {
		t.Fatalf("entry = %q, %v", got, err)
	}
	if err := Set(`C:\other\kontextw.exe`); err != nil {
		t.Fatalf("Set over an entry: %v", err)
	}
	if got, _ := Entry(); got != `"C:\other\kontextw.exe" managed-observe-daemon` {
		t.Fatalf("entry after a second write = %q", got)
	}
	if err := Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if got, err := Entry(); err != nil || got != "" {
		t.Fatalf("entry after Remove = %q, %v, want none", got, err)
	}
	if err := Remove(); err != nil {
		t.Fatalf("Remove with no entry: %v", err)
	}
}
