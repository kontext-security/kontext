package managedconfig

import (
	"context"
	"errors"
	"testing"
)

// The real check: a token file this user wrote can't be the organization's, so a
// system config doesn't take it. An elevated token's files may belong to
// Administrators, which this can't show.
func TestInstallTokenOfASystemConfigRefusesAFileThisUserOwns(t *testing.T) {
	loaded := writeTokenConfig(t, "test-install-token")
	loaded.Scope = ScopeSystem
	if _, err := loaded.InstallToken(context.Background()); !errors.Is(err, ErrUntrustedSystemConfig) {
		t.Fatalf("error = %v, want %v", err, ErrUntrustedSystemConfig)
	}
}
