//go:build windows

package fsperm

import (
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedInstallerSID owns most of the Windows folder. It has no well-known SID
// type in the API; this is the value Windows reports for NT SERVICE\TrustedInstaller.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// fileDeleteChild is FILE_DELETE_CHILD, which x/sys/windows does not name.
const fileDeleteChild = 0x40

// writeAccess is every right that lets someone change a file, what a folder
// holds, or who may do either.
const writeAccess = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild | windows.DELETE | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// NotAdminOnlyError says why someone other than an administrator could have
// changed a file or its folder.
type NotAdminOnlyError struct {
	Path   string
	Reason string
}

func (e *NotAdminOnlyError) Error() string { return e.Path + " " + e.Reason }

// ReadAdminOnly reads a file only if it and its folder are owned by SYSTEM,
// Administrators or TrustedInstaller and nobody else can write to them. A user
// can create folders under ProgramData and at the root of a drive, so a path
// there says nothing about who wrote the file. It checks the handles it reads
// from, so the check and the read see the same file, and it follows no symlink
// or junction. Everyone may still read; a per-user process has to.
func ReadAdminOnly(path string) ([]byte, error) {
	dir := filepath.Dir(path)
	folder, err := openNoFollow(dir, 0, windows.FILE_FLAG_BACKUP_SEMANTICS)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(folder)
	if err := checkAdminOnly(folder, dir); err != nil {
		return nil, err
	}
	handle, err := openNoFollow(path, windows.GENERIC_READ, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	if err := checkAdminOnly(handle, path); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func openNoFollow(path string, access, flags uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, access|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|flags, 0)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return handle, nil
}

func checkAdminOnly(handle windows.Handle, path string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return &NotAdminOnlyError{Path: path, Reason: "is a reparse point"}
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return &os.PathError{Op: "read security of", Path: path, Err: err}
	}
	reason, err := notAdminOnly(sd)
	if err != nil {
		return &os.PathError{Op: "read security of", Path: path, Err: err}
	}
	if reason != "" {
		return &NotAdminOnlyError{Path: path, Reason: reason}
	}
	return nil
}

// notAdminOnly returns why sd lets someone other than an administrator change
// the object, or "" if it doesn't. An entry it can't read counts against it.
func notAdminOnly(sd *windows.SECURITY_DESCRIPTOR) (string, error) {
	owner, _, err := sd.Owner()
	if err != nil {
		return "", err
	}
	if !isAdmin(owner) {
		return "is owned by " + accountName(owner), nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	if dacl == nil {
		return "has no access list, so anyone can write to it", nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return "", err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // Applies to what is created inside, not to this object.
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if uint32(ace.Mask)&writeAccess != 0 && !isAdmin(sid) {
				return "can be written by " + accountName(sid), nil
			}
		default:
			return "has an access entry this check can't read", nil
		}
	}
	return "", nil
}

func isAdmin(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.String() == trustedInstallerSID)
}

func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
