package agentinventory

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext/pkg/agentauthority"
)

const (
	coworkHostSessions = "Library/Application Support/Claude/local-agent-mode-sessions"
	coworkVMBundle     = "Library/Application Support/Claude/vm_bundles/claudevm.bundle"

	coworkSidecarEntryLimit = 10000
	coworkSidecarSizeLimit  = 1024 * 1024
	coworkSidecarTimeout    = time.Second
)

type coworkSidecar struct {
	CreatedAt      int64  `json:"createdAt"`
	LastActivityAt int64  `json:"lastActivityAt"`
	HostLoopMode   *bool  `json:"hostLoopMode"`
	CLISessionID   string `json:"cliSessionId"`
}

func coworkSandbox(ctx context.Context, home string, now time.Time, hasSession func(string) (bool, error)) *bool {
	sidecar, complete := latestCoworkSidecar(ctx, filepath.Join(home, coworkHostSessions), now)
	if !complete {
		return nil
	}
	remote, remoteFound, err := latestRemoteCoworkSession(ctx, home, now)
	if err != nil && !os.IsNotExist(err) {
		return nil
	}
	if remoteFound && (sidecar == nil || remote.After(time.UnixMilli(sidecar.CreatedAt))) {
		return boolPointer(true)
	}
	if sidecar == nil {
		return nil
	}
	if sidecar.HostLoopMode != nil && !*sidecar.HostLoopMode {
		return boolPointer(true)
	}
	if hasSession == nil {
		return nil
	}
	if _, err := hasSession(sidecar.CLISessionID); err != nil {
		return nil
	}
	return boolPointer(false)
}

func latestCoworkSidecar(ctx context.Context, root string, now time.Time) (*coworkSidecar, bool) {
	ctx, cancel := context.WithTimeout(ctx, coworkSidecarTimeout)
	defer cancel()
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil, true
	}
	if err != nil || !info.IsDir() {
		return nil, false
	}
	var latest *coworkSidecar
	visited := 0
	var walk func(string, int) bool
	walk = func(dir string, depth int) bool {
		if ctx.Err() != nil {
			return false
		}
		file, err := os.Open(dir)
		if err != nil {
			return false
		}
		defer file.Close()
		for {
			entries, readErr := file.ReadDir(min(64, coworkSidecarEntryLimit+1-visited))
			for _, entry := range entries {
				visited++
				if visited > coworkSidecarEntryLimit || ctx.Err() != nil {
					return false
				}
				path := filepath.Join(dir, entry.Name())
				if entry.IsDir() {
					if depth < 2 && !walk(path, depth+1) {
						return false
					}
					continue
				}
				if !strings.HasPrefix(entry.Name(), "local_") || filepath.Ext(entry.Name()) != ".json" {
					continue
				}
				info, err := entry.Info()
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				// The filename still proves a host session when Claude's payload is
				// oversized or malformed; use a bounded mtime to order that evidence.
				mtime := info.ModTime()
				if mtime.After(now) {
					mtime = now
				}
				sidecar := &coworkSidecar{CreatedAt: mtime.UnixMilli()}
				if info.Size() <= coworkSidecarSizeLimit {
					if parsed, err := readCoworkSidecar(path); err == nil {
						sidecar = parsed
					}
				}
				if latest == nil || sidecar.CreatedAt > latest.CreatedAt {
					latest = sidecar
				}
			}
			if errors.Is(readErr, io.EOF) {
				return true
			}
			if readErr != nil {
				return false
			}
		}
	}
	return latest, walk(root, 0)
}

func readCoworkSidecar(path string) (*coworkSidecar, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > coworkSidecarSizeLimit {
		return nil, errors.New("invalid Cowork sidecar")
	}
	var sidecar coworkSidecar
	if err := json.NewDecoder(io.LimitReader(file, coworkSidecarSizeLimit)).Decode(&sidecar); err != nil || sidecar.CreatedAt <= 0 {
		return nil, errors.New("invalid Cowork sidecar")
	}
	return &sidecar, nil
}

func latestRemoteCoworkSession(ctx context.Context, home string, now time.Time) (time.Time, bool, error) {
	data, err := agentauthority.CoworkWebLogTail(ctx, home)
	if err != nil {
		return time.Time{}, false, err
	}
	var latest time.Time
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "remote_cowork.") || len(line) < len("2006-01-02 15:04:05") {
			continue
		}
		stamp, err := time.ParseInLocation("2006-01-02 15:04:05", line[:len("2006-01-02 15:04:05")], now.Location())
		if err == nil && !stamp.After(now) && stamp.After(latest) {
			latest = stamp
		}
	}
	return latest, !latest.IsZero(), nil
}

func boolPointer(value bool) *bool { return &value }
