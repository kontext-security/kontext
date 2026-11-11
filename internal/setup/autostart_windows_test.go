//go:build windows

package setup

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// The sign-in entry in the user's own Run key: written, read back, replaced
// and removed, under a name of this test's own.
func TestAutostartEntryRoundTrip(t *testing.T) {
	overrideVar(t, &autostartValue, fmt.Sprintf("KontextTest-%d-%d", os.Getpid(), time.Now().UnixNano()))
	t.Cleanup(func() { _ = removeAutostart() })

	if got, err := autostartEntry(); err != nil || got != "" {
		t.Fatalf("entry before a write = %q, %v, want none", got, err)
	}
	if err := setAutostart(`C:\Program Files\Kontext\kontextw.exe`); err != nil {
		t.Fatalf("setAutostart: %v", err)
	}
	if got, err := autostartEntry(); err != nil || got != `"C:\Program Files\Kontext\kontextw.exe" managed-observe-daemon` {
		t.Fatalf("entry = %q, %v", got, err)
	}
	if err := setAutostart(`C:\other\kontextw.exe`); err != nil {
		t.Fatalf("setAutostart over an entry: %v", err)
	}
	if got, _ := autostartEntry(); got != `"C:\other\kontextw.exe" managed-observe-daemon` {
		t.Fatalf("entry after a second write = %q", got)
	}
	if err := removeAutostart(); err != nil {
		t.Fatalf("removeAutostart: %v", err)
	}
	if got, err := autostartEntry(); err != nil || got != "" {
		t.Fatalf("entry after the removal = %q, %v, want none", got, err)
	}
	if err := removeAutostart(); err != nil {
		t.Fatalf("removeAutostart of nothing: %v", err)
	}
}
