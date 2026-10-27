//go:build windows

package fsperm

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Requirement names what PrivateFile checks, for error messages.
const Requirement = "an owner-only protected DACL"

// RestrictFile gives an open file a protected DACL that grants only the current user full
// control, so it inherits nothing from its directory. Mode bits do not exist on Windows.
func RestrictFile(file *os.File) error {
	user, err := currentUser()
	if err != nil {
		return err
	}
	acl, err := OwnerOnlyACL(user, windows.NO_INHERITANCE)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(file.Name(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// PrivateFile reports whether the file at path is private to the current user: owned by the user
// or the token's default owner, with a protected DACL that grants access to that user alone.
func PrivateFile(path string, _ os.FileInfo) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	user, err := currentUser()
	if err != nil {
		return false, err
	}
	defaultOwner, err := TokenDefaultOwner(windows.GetCurrentProcessToken())
	if err != nil {
		return false, err
	}
	if !OwnerAllowed(owner, user, defaultOwner) {
		return false, nil
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, err
	}
	return grantsOnly(dacl, user)
}

// grantsOnly reports whether every entry of dacl that can grant access is a plain allow entry
// for sid. Deny entries grant nothing; object, callback and compound allow entries can grant
// access too and are not read here, so a DACL holding one is not known to be private.
func grantsOnly(dacl *windows.ACL, sid *windows.SID) (bool, error) {
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	return true, nil
}

// SyncDir flushes a directory, so a rename or link inside it survives a crash. FlushFileBuffers
// needs a handle with write access, which os.Open never asks for on a directory (it fails with
// ERROR_ACCESS_DENIED), so the directory is opened directly with FILE_FLAG_BACKUP_SEMANTICS.
func SyncDir(dir string) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return &os.PathError{Op: "sync", Path: dir, Err: err}
	}
	defer windows.CloseHandle(handle)
	if err := windows.FlushFileBuffers(handle); err != nil {
		return &os.PathError{Op: "sync", Path: dir, Err: err}
	}
	return nil
}

// OwnerOnlyACL builds a DACL with one entry: full control for sid, inherited as given.
func OwnerOnlyACL(sid *windows.SID, inheritance uint32) (*windows.ACL, error) {
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return nil, fmt.Errorf("build owner-only ACL: %w", err)
	}
	return acl, nil
}

// OwnerAllowed reports whether owner is one of the allowed SIDs.
func OwnerAllowed(owner *windows.SID, allowed ...*windows.SID) bool {
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

// TokenDefaultOwner returns the SID the token assigns as owner of new objects (TokenOwner). An
// elevated process creates objects owned by its default owner (Administrators), not by the user.
func TokenDefaultOwner(token windows.Token) (*windows.SID, error) {
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

func currentUser() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read token user: %w", err)
	}
	return user.User.Sid, nil
}
