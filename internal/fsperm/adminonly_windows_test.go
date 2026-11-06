package fsperm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func TestAdminOnlyDescriptors(t *testing.T) {
	for name, test := range map[string]struct {
		sddl   string
		refuse string
	}{
		"system and administrators":   {sddl: "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"},
		"owned by administrators":     {sddl: "O:BAD:(A;;FA;;;BA)(A;;FR;;;BU)"},
		"owned by trusted installer":  {sddl: "O:" + trustedInstaller + "D:(A;;FA;;;" + trustedInstaller + ")(A;;FR;;;BU)"},
		"an inherit-only entry":       {sddl: "O:BAD:(A;;FA;;;BA)(A;OICIIO;GA;;;CO)(A;;0x1200a9;;;BU)"},
		"a deny entry":                {sddl: "O:BAD:(D;;FA;;;WD)(A;;FA;;;BA)"},
		"owned by a user":             {sddl: "O:BUD:(A;;FA;;;BA)", refuse: "owned by"},
		"users can write":             {sddl: "O:BAD:(A;;FA;;;BA)(A;;FW;;;BU)", refuse: "can be written"},
		"users can append":            {sddl: "O:BAD:(A;;FA;;;BA)(A;;0x4;;;BU)", refuse: "can be written"},
		"users can delete children":   {sddl: "O:BAD:(A;;FA;;;BA)(A;;0x40;;;BU)", refuse: "can be written"},
		"users can change its access": {sddl: "O:BAD:(A;;FA;;;BA)(A;;WD;;;BU)", refuse: "can be written"},
		"everyone has full control":   {sddl: "O:SYD:(A;;GA;;;WD)", refuse: "can be written"},
		// What a folder created under ProgramData inherits unless it is protected.
		"programdata's user entry": {sddl: "O:BAD:(A;;FA;;;BA)(A;CIID;0x116;;;BU)", refuse: "can be written"},
		"no access list":           {sddl: "O:BAD:NO_ACCESS_CONTROL", refuse: "no access list"},
		"an entry it can't read":   {sddl: "O:BAD:(A;;FA;;;BA)(XA;;FR;;;BU;(@User.x==1))", refuse: "can't read"},
	} {
		t.Run(name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			reason, err := notAdminOnly(sd, writeAccess)
			if err != nil {
				t.Fatal(err)
			}
			if test.refuse == "" && reason != "" {
				t.Fatalf("refused: %s", reason)
			}
			if !strings.Contains(reason, test.refuse) {
				t.Fatalf("reason = %q, want it to say %q", reason, test.refuse)
			}
		})
	}
}

func systemFile(t testing.TB) string {
	t.Helper()
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "kernel32.dll")
}

// A file only administrators can write, in a folder only they can write to.
func TestReadAdminOnlyReadsASystemFile(t *testing.T) {
	data, err := ReadAdminOnly(systemFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("read nothing")
	}
}

// Whoever runs this, a standard user or an elevated CI runner, the user's temp
// folder and what they create there are not admin-only.
func TestReadAdminOnlyRefusesAUsersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadAdminOnly(path)
	var refused *NotAdminOnlyError
	if !errors.As(err, &refused) {
		t.Fatalf("ReadAdminOnly() error = %v, want a refusal", err)
	}
}

func TestFindNotAdminFileAcceptsASystemFile(t *testing.T) {
	if found, err := FindNotAdminFile(systemFile(t)); err != nil || found != nil {
		t.Fatalf("FindNotAdminFile() = %v, %v; want none", found, err)
	}
}

// wantNotAdminFile fails unless the path is ruled out for the given reason.
func wantNotAdminFile(t *testing.T, path, reason string) {
	t.Helper()
	found, err := FindNotAdminFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if found == nil || !strings.Contains(found.String(), reason) {
		t.Fatalf("FindNotAdminFile(%s) = %v, want %q", path, found, reason)
	}
}

// What a standard user creates is theirs. An elevated token's files may belong
// to Administrators, so that case can't show it.
func TestFindNotAdminFileFindsAUsersFile(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs a standard user's token")
	}
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantNotAdminFile(t, path, path+" is owned by")
}

// A user can plant a folder under a file's name, and it has to count like a file.
func TestFindNotAdminFileFindsAUsersFolderUnderTheFilesName(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs a standard user's token")
	}
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	wantNotAdminFile(t, path, path+" is owned by")
}

// A user's file in a folder administrators own: ProgramData lets a user create one.
func TestFindNotAdminFileFindsAUsersFileInAnAdminFolder(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs a standard user's token")
	}
	file, err := os.CreateTemp(os.Getenv("ProgramData"), "kontext-owner-test-*")
	if err != nil {
		t.Skipf("can't create a file in ProgramData: %v", err)
	}
	file.Close()
	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	wantNotAdminFile(t, file.Name(), file.Name()+" is owned by")
}

// An administrator's file through a user's junction: a junction is theirs whatever
// it points at, so it can't take the machine from anyone by pointing at a real file.
func TestFindNotAdminFileFindsAUsersJunction(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs a standard user's token")
	}
	target := filepath.Dir(systemFile(t))
	junction := filepath.Join(t.TempDir(), "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	wantNotAdminFile(t, filepath.Join(junction, filepath.Base(systemFile(t))), junction+" is a link owned by")
}

// Everyone has to be able to read an administrator's file, so one this user can't
// open isn't that. An entry for OWNER RIGHTS takes away what an owner keeps
// otherwise; only a token holding the backup privilege still gets through.
func TestFindNotAdminFileFindsAFileThisUserCantOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;0x80;;;OW)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if file, err := os.Open(path); err == nil {
		file.Close()
		t.Skip("the access list doesn't keep this token out")
	}
	wantNotAdminFile(t, path, path+" can't be opened by this user")
}

// Not there says nothing about an owner, and the caller has to be able to tell.
func TestFindNotAdminFileKeepsANotFoundError(t *testing.T) {
	path := filepath.Join(filepath.Dir(systemFile(t)), "kontext-absent.json")
	if _, err := FindNotAdminFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FindNotAdminFile() error = %v, want not-exist", err)
	}
}

// The layout an installer leaves, built for real. Creating it needs an elevated
// token: a standard user skips, and CI must not, because nothing else covers a
// bad file in a good folder.
func TestReadAdminOnlyWithAnAdminOnlyFolder(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		if os.Getenv("GITHUB_ACTIONS") != "" {
			t.Fatal("this runner is not elevated, so the test can't run here")
		}
		t.Skip("needs an elevated token")
	}
	dir := filepath.Join(t.TempDir(), "Kontext")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(sid *windows.SID, rights windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: rights,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	protect := func(path string, entries ...windows.EXPLICIT_ACCESS) {
		t.Helper()
		acl, err := windows.ACLFromEntries(entries, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			admins, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	const read = windows.GENERIC_READ | windows.GENERIC_EXECUTE
	adminOnly := []windows.EXPLICIT_ACCESS{entry(system, windows.GENERIC_ALL), entry(admins, windows.GENERIC_ALL), entry(users, read)}
	protect(dir, adminOnly...)
	path := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	protect(path, adminOnly...)
	data, err := ReadAdminOnly(path)
	if err != nil {
		t.Fatalf("admin-only file: %v", err)
	}
	if string(data) != "{}" {
		t.Fatalf("read %q", data)
	}

	// The folder is fine but the file isn't: the check has to look at both.
	protect(path, append(adminOnly, entry(users, windows.GENERIC_WRITE))...)
	var refused *NotAdminOnlyError
	if _, err := ReadAdminOnly(path); !errors.As(err, &refused) || refused.Path != path {
		t.Fatalf("user-writable file: error = %v, want a refusal naming the file", err)
	}
	protect(path, adminOnly...)

	// And the other way round.
	protect(dir, append(adminOnly, entry(users, windows.GENERIC_WRITE))...)
	if _, err := ReadAdminOnly(path); !errors.As(err, &refused) || refused.Path != dir {
		t.Fatalf("user-writable folder: error = %v, want a refusal naming the folder", err)
	}
	protect(dir, adminOnly...)

	// A link in a good folder may point anywhere, so the file's own check refuses it.
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAdminOnly(link); !errors.As(err, &refused) || refused.Path != link || !strings.Contains(refused.Reason, "reparse point") {
		t.Fatalf("link: error = %v, want a reparse point refusal naming the link", err)
	}
}

// A junction needs no privilege, so a user could point one at a real admin folder.
func TestReadAdminOnlyRefusesAJunctionedFolder(t *testing.T) {
	target := filepath.Dir(systemFile(t))
	junction := filepath.Join(t.TempDir(), "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	_, err := ReadAdminOnly(filepath.Join(junction, filepath.Base(systemFile(t))))
	var refused *NotAdminOnlyError
	if !errors.As(err, &refused) || !strings.Contains(refused.Reason, "reparse point") {
		t.Fatalf("ReadAdminOnly() error = %v, want a reparse point refusal", err)
	}
}

func TestReadAdminOnlyReportsAMissingFile(t *testing.T) {
	dir := filepath.Dir(systemFile(t))
	if _, err := ReadAdminOnly(filepath.Join(dir, "kontext-absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: error = %v, want not-exist", err)
	}
	if _, err := ReadAdminOnly(filepath.Join(dir, "kontext-absent", "managed.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing folder: error = %v, want not-exist", err)
	}
}

// Hooks load the config on every call, against a 1 s budget.
func BenchmarkReadAdminOnly(b *testing.B) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(dir, "drivers", "etc", "services")
	for b.Loop() {
		if _, err := ReadAdminOnly(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPlainRead(b *testing.B) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(dir, "drivers", "etc", "services")
	for b.Loop() {
		if _, err := os.ReadFile(path); err != nil {
			b.Fatal(err)
		}
	}
}
