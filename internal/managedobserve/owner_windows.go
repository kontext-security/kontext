//go:build windows

package managedobserve

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ensurePrivateOwner refuses a socket directory owned by anyone but this process's user or the
// token's default owner, then replaces its DACL with a protected one that grants only the user full
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
	defaultOwner, err := tokenDefaultOwner(token)
	if err != nil {
		return fmt.Errorf("socket directory %s: read token owner: %w", dir, err)
	}
	if !ownerAllowed(owner, user.User.Sid, defaultOwner) {
		return fmt.Errorf("socket directory %s is owned by %s, want %s", dir, owner, user.User.Sid)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("socket directory %s: build owner-only ACL: %w", dir, err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("socket directory %s: set owner-only ACL: %w", dir, err)
	}
	return nil
}

// ownerAllowed reports whether owner is one of the allowed SIDs.
func ownerAllowed(owner *windows.SID, allowed ...*windows.SID) bool {
	if owner == nil {
		return false
	}
	for _, sid := range allowed {
		if sid != nil && owner.Equals(sid) {
			return true
		}
	}
	return false
}

// tokenDefaultOwner returns the SID the token assigns as owner of new objects (TokenOwner).
func tokenDefaultOwner(token windows.Token) (*windows.SID, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if size == 0 {
		return nil, err
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buf[0], size, &size); err != nil {
		return nil, err
	}
	// TOKEN_OWNER holds a single pointer into buf; copy the SID out before buf goes away.
	return (*struct{ Owner *windows.SID })(unsafe.Pointer(&buf[0])).Owner.Copy()
}
