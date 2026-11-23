//go:build windows

package managedobserve

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/kontext-security/kontext/internal/fsperm"
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
	defaultOwner, err := fsperm.TokenDefaultOwner(token)
	if err != nil {
		return fmt.Errorf("socket directory %s: read token owner: %w", dir, err)
	}
	if !fsperm.OwnerAllowed(owner, user.User.Sid, defaultOwner) {
		return fmt.Errorf("socket directory %s is owned by %s, want %s", dir, owner, user.User.Sid)
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

// checkPrivateOwner refuses a socket directory unless it is owned by this
// process's user or the token's default owner and its protected DACL grants
// access to this user alone, as ensurePrivateOwner leaves it. It changes
// nothing: owning a folder does not mean nobody else can write to it.
func checkPrivateOwner(dir string, info os.FileInfo) error {
	private, err := fsperm.PrivateFile(dir, info)
	if err != nil {
		return fmt.Errorf("socket directory %s: read security: %w", dir, err)
	}
	if !private {
		return fmt.Errorf("socket directory %s is not private to this user", dir)
	}
	return nil
}
