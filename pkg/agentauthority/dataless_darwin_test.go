//go:build darwin

package agentauthority

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type datalessInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i datalessInfo) Sys() any { return &i.stat }

func TestDatalessSkippedBeforeOpen(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	path := filepath.Join(home, ".claude/settings.json")
	writeFixture(t, home, ".claude/settings.json", "{}")
	r := Report{}
	g := guard{ctx: context.Background(), home: home, roots: allowedRoots(home, managedRoot), report: &r,
		lstat: func(p string) (os.FileInfo, error) {
			info, err := os.Lstat(p)
			if p == path && err == nil {
				stat := *info.Sys().(*syscall.Stat_t)
				stat.Flags |= unix.SF_DATALESS
				return datalessInfo{info, stat}, nil
			}
			return info, err
		},
		readFile: func(string, string) fileResult { t.Error("opened dataless file"); return fileResult{} },
	}
	if g.read(path) != nil || r.Coverage.SkippedFiles != 1 || r.Truncated {
		t.Fatalf("dataless result: %+v", r)
	}
}
