//go:build windows

package managedobserve

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/kontext-security/kontext/internal/fsperm"
)

// ensurePrivateOwner refuses a socket directory owned by anyone but this process's user, the
// token's default owner, Administrators or LocalSystem, then replaces its DACL with a protected one that grants only the user full
// control, inherited by the socket inside. The default owner counts because an elevated process
// creates objects owned by its default owner (Administrators) rather than by the user.
func ensurePrivateOwner(dir string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("socket directory %s: read owner: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("socket directory %s: read owner: %w", dir, err)
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("socket directory %s: read token user: %w", dir, err)
	}
	defaultOwner, err := fsperm.TokenDefaultOwner(token)
	if err != nil {
		return fmt.Errorf("socket directory %s: read token owner: %w", dir, err)
	}
	// Administrators and LocalSystem can take any folder anyway: one an
	// elevated daemon of this user created and made private is used again
	// unelevated.
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	if !fsperm.OwnerAllowed(owner, user.User.Sid, defaultOwner) {
		if !fsperm.OwnerAllowed(owner, admins, system) {
			return fmt.Errorf("socket directory %s is owned by %s, want %s", dir, owner, user.User.Sid)
		}
		// Only a folder an earlier daemon of this user already made
		// private is adopted: a shared folder of another product keeps
		// its grants.
		if err := checkPrivateOwner(dir, nil); err != nil {
			return fmt.Errorf("socket directory %s is owned by %s and is not private to %s: %w", dir, owner, user.User.Sid, err)
		}
	}
	acl, err := fsperm.OwnerOnlyACL(user.User.Sid, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil {
		return fmt.Errorf("socket directory %s: %w", dir, err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("socket directory %s: set owner-only ACL: %w", dir, err)
	}
	return nil
}

// checkPrivateOwner refuses a socket directory unless its protected DACL
// grants access to this user alone, as ensurePrivateOwner leaves it, and its
// owner is this user, the token's default owner, Administrators or
// LocalSystem. An elevated daemon creates the folder owned by Administrators;
// the browser host runs without elevation, so its default owner is the user.
// Administrators and LocalSystem can take any folder anyway. It changes
// nothing: owning a folder does not mean nobody else can write to it.
func checkPrivateOwner(dir string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("socket directory %s: read security: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("socket directory %s: read owner: %w", dir, err)
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("socket directory %s: read token user: %w", dir, err)
	}
	defaultOwner, err := fsperm.TokenDefaultOwner(token)
	if err != nil {
		return fmt.Errorf("socket directory %s: read token owner: %w", dir, err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	if !fsperm.OwnerAllowed(owner, user.User.Sid, defaultOwner, admins, system) {
		return fmt.Errorf("socket directory %s is owned by %s", dir, owner)
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("socket directory %s inherits its DACL", dir)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("socket directory %s has no DACL", dir)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
				return fmt.Errorf("socket directory %s grants access to another account", dir)
			}
		default:
			return fmt.Errorf("socket directory %s has an entry this check cannot read", dir)
		}
	}
	return nil
}
