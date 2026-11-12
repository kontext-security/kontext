//go:build !windows

package hookinstall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// usersDir holds the local users' home folders on macOS.
// ponytail: a home outside /Users (a network account) is not found; the
// package's remover cleans the same folder.
const usersDir = "/Users"

// localHomes lists the real folders in dir that a user other than root owns.
func localHomes(dir string) []userHome {
	entries, _ := os.ReadDir(dir)
	var homes []userHome
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.IsDir() || entry.Name() == "Shared" {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
			homes = append(homes, userHome{Path: filepath.Join(dir, entry.Name()), UID: int(stat.Uid), GID: int(stat.Gid)})
		}
	}
	return homes
}

// asOwner runs fn as the user who owns home. Root gives up its identity and
// groups for the call, so a link a user planted in their home reaches nothing
// that user could not change anyway, and a new file belongs to the user.
func asOwner(home userHome, fn func() error) (err error) {
	if home.UID == os.Geteuid() {
		return fn()
	}
	if os.Geteuid() != 0 {
		return errors.New("not this user's home")
	}
	groups, err := syscall.Getgroups()
	if err != nil {
		return err
	}
	gid := os.Getegid()
	// Root again before anything else runs; a process that cannot return is
	// left as the user, which only ever has less access.
	restore := func(step string, call error) {
		if call != nil && err == nil {
			err = fmt.Errorf("restore %s: %w", step, call)
		}
	}
	if err := syscall.Setgroups([]int{home.GID}); err != nil {
		return err
	}
	defer func() { restore("groups", syscall.Setgroups(groups)) }()
	if err := syscall.Setegid(home.GID); err != nil {
		return err
	}
	defer func() { restore("group", syscall.Setegid(gid)) }()
	if err := syscall.Seteuid(home.UID); err != nil {
		return err
	}
	defer func() { restore("user", syscall.Seteuid(0)) }()
	return fn()
}
