//go:build windows

package agentauthority

import "golang.org/x/sys/windows"

// ProbeEnvironment says who the scan runs as, in the terms the report has
// for it. Windows has no numeric user id; the nearest thing is the last
// part of the user's SID, which tells the accounts of one machine or domain
// apart as a uid does. Root is a process that runs elevated, as SYSTEM and
// an administrator's elevated programs do. Admin is an account in the
// Administrators group, whether or not this process is elevated: for a
// process that is not, Windows lists the group as one it may only be denied
// by, and that still counts.
func ProbeEnvironment() Environment {
	var e Environment
	token := windows.GetCurrentProcessToken()
	if user, err := token.GetTokenUser(); err == nil {
		if count := user.User.Sid.SubAuthorityCount(); count > 0 {
			e.UID = int(user.User.Sid.SubAuthority(uint32(count) - 1))
		}
	}
	e.Root = token.IsElevated()
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return e
	}
	if groups, err := token.GetTokenGroups(); err == nil {
		for _, group := range groups.AllGroups() {
			if group.Sid.Equals(administrators) {
				e.Admin = true
			}
		}
	}
	return e
}
