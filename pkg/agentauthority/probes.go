package agentauthority

import (
	"os"
	"os/user"
	"strings"
)

func ProbeEnvironment() Environment {
	uid := os.Getuid()
	e := Environment{UID: uid, Root: uid == 0}
	if current, err := user.Current(); err == nil {
		if group, err := user.LookupGroup("admin"); err == nil {
			if groups, err := current.GroupIds(); err == nil {
				for _, id := range groups {
					if id == group.Gid {
						e.Admin = true
					}
				}
			}
		}
	}
	if _, err := os.Lstat("/.dockerenv"); err == nil {
		e.Container = true
	}
	// This fixed kernel metadata path is the only probe that reads outside scan roots.
	if info, err := os.Lstat("/proc/1/cgroup"); err == nil && info.Mode().IsRegular() {
		if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
			e.Container = e.Container || strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd")
		}
	}
	return e
}
