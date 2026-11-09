package managedobserve

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/managedconfig"
)

// The fix doctor suggests has to fit where the token comes from: a registry
// value is an administrator's or the MDM's to set, not a keychain to unlock.
func TestInstallTokenFixHintFitsTheSource(t *testing.T) {
	registry := installTokenFixHint(managedconfig.TokenRef{Source: "registry", Name: "InstallToken"})
	if !strings.Contains(registry, `HKLM\SOFTWARE\Policies\Kontext\InstallToken`) || strings.Contains(registry, "keychain") {
		t.Errorf("registry hint = %q", registry)
	}
	keychain := installTokenFixHint(managedconfig.TokenRef{Source: "keychain", Name: "kontext-install-token"})
	if keychain != "re-run `kontext setup` or unlock your login keychain" {
		t.Errorf("keychain hint = %q", keychain)
	}
}
