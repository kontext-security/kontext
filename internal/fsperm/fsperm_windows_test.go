//go:build windows

package fsperm

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRestrictFileMakesFilePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if private, err := PrivateFile(path, nil); err != nil || private {
		t.Fatalf("PrivateFile() before RestrictFile = %v, %v; want false: the inherited DACL grants others access", private, err)
	}
	if err := RestrictFile(file); err != nil {
		t.Fatalf("RestrictFile() error = %v", err)
	}
	if private, err := PrivateFile(path, nil); err != nil || !private {
		t.Fatalf("PrivateFile() after RestrictFile = %v, %v; want true", private, err)
	}
}

func TestPrivateFileRefusesEntriesForOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, sid := range []*windows.SID{user, users} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Protected, so only the inheritance check is passed: the Users entry must still refuse it.
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if private, err := PrivateFile(path, nil); err != nil || private {
		t.Fatalf("PrivateFile() = %v, %v; want false for a DACL that also grants Users", private, err)
	}
}

func TestOwnerAllowedRefusesOtherOwners(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if !OwnerAllowed(user.User.Sid, user.User.Sid, admins) {
		t.Fatal("the user must own its socket directory")
	}
	if !OwnerAllowed(admins, user.User.Sid, admins) {
		t.Fatal("an elevated process's default owner must be accepted")
	}
	if OwnerAllowed(system, user.User.Sid, admins) {
		t.Fatal("a directory another principal owns must be refused")
	}
	if OwnerAllowed(nil, user.User.Sid) || OwnerAllowed(system, nil) {
		t.Fatal("a missing SID must never match")
	}
}
