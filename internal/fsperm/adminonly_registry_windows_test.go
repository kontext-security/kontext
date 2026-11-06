package fsperm

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// A key's read rights include a bit a file counts as a write, so keys get their
// own mask: what users get under SOFTWARE\Policies passes, a value they may set
// doesn't.
func TestAdminOnlyKeyDescriptors(t *testing.T) {
	for name, test := range map[string]struct {
		sddl   string
		refuse bool
	}{
		"users can read":          {sddl: "O:BAD:(A;;KA;;;BA)(A;;KA;;;SY)(A;;KR;;;BU)"},
		"users can set a value":   {sddl: "O:BAD:(A;;KA;;;BA)(A;;0x2;;;BU)", refuse: true},
		"users can add a subkey":  {sddl: "O:BAD:(A;;KA;;;BA)(A;;0x4;;;BU)", refuse: true},
		"users can create a link": {sddl: "O:BAD:(A;;KA;;;BA)(A;;0x20;;;BU)", refuse: true},
		"owned by a user":         {sddl: "O:BUD:(A;;KA;;;BA)", refuse: true},
	} {
		t.Run(name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			reason, err := notAdminOnly(sd, keyWriteAccess)
			if err != nil {
				t.Fatal(err)
			}
			if (reason != "") != test.refuse {
				t.Fatalf("reason = %q, want refused %v", reason, test.refuse)
			}
		})
	}
}

// What this user creates is theirs, so a value there is refused however it reads.
func TestRegistryStringRefusedInAKeyThisUserOwns(t *testing.T) {
	path := fmt.Sprintf(`Software\KontextTest-%d`, os.Getpid())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, path) })
	if err := key.SetStringValue("InstallToken", "test-install-token"); err != nil {
		t.Fatal(err)
	}
	key.Close()

	_, err = readAdminOnlyRegistryString(registry.CURRENT_USER, `HKCU\`, path, "InstallToken")
	var refused *NotAdminOnlyError
	if !errors.As(err, &refused) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

// HKLM\SOFTWARE\Policies is admin-only on a stock install, and users can read it:
// a missing value there is a plain not-found, not a refusal.
func TestRegistryStringInPoliciesPassesTheCheck(t *testing.T) {
	_, err := ReadAdminOnlyRegistryString(`SOFTWARE\Policies`, "KontextTestValueThatDoesNotExist")
	var refused *NotAdminOnlyError
	if errors.As(err, &refused) {
		t.Fatalf("HKLM\\SOFTWARE\\Policies refused: %v", err)
	}
	if !errors.Is(err, registry.ErrNotExist) {
		t.Fatalf("error = %v, want not found", err)
	}
}
