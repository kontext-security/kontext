//go:build windows

package managedobserve

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/kontext-security/kontext/internal/hermetic"
)

func TestEnsureSocketDirSetsOwnerOnlyDACL(t *testing.T) {
	// A short parent: t.TempDir carries the test name and can push the socket past 107 bytes.
	dir := filepath.Join(hermetic.SocketDir(t), "run")
	for i := 0; i < 2; i++ { // a second start finds the directory and must accept it
		if err := EnsureSocketDir(filepath.Join(dir, "kontext.sock")); err != nil {
			t.Fatalf("EnsureSocketDir() call %d error = %v", i+1, err)
		}
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL is not protected; inherited entries would still apply")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount == 0 {
		t.Fatalf("DACL has %v entries, want the user's", aceCount(dacl))
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// Windows stores an inheritable GENERIC_ALL grant as two entries for the same SID: full file
	// access on the directory itself, and an inherit-only GENERIC_ALL for what is created inside.
	const fileAllAccess = 0x1F01FF
	const inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	var onDir, toChildren bool
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.Equals(user.User.Sid) {
			t.Fatalf("entry %d grants type %d to %s; want only allow entries for the user %s", i, ace.Header.AceType, sid, user.User.Sid)
		}
		full := ace.Mask == fileAllAccess || ace.Mask == windows.GENERIC_ALL
		if full && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			onDir = true
		}
		if full && ace.Header.AceFlags&inherit == inherit {
			toChildren = true
		}
	}
	if !onDir || !toChildren {
		t.Fatalf("user entries: full access on the directory %v, inherited by the socket %v; want both", onDir, toChildren)
	}
}

func aceCount(acl *windows.ACL) any {
	if acl == nil {
		return "no DACL"
	}
	return acl.AceCount
}
