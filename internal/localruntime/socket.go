package localruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func DefaultSocketPath() string {
	if path := os.Getenv("KONTEXT_GUARD_SOCKET"); path != "" {
		return path
	}
	return SocketPath("guard")
}

// SocketPath returns the per-user path of the socket called name. On Unix it
// is /tmp/kontext-<name>-<uid>/kontext.sock, short because sun_path is 104
// bytes on macOS. On Windows os.Getuid returns -1, so that path would be one
// directory for every user; the socket lives in the user's local app data
// instead, as %LOCALAPPDATA%\Kontext\run\<name>.sock, kept short because
// Windows limits a socket path too (see CheckSocketPath). Without
// LOCALAPPDATA the Unix form remains, as before; the daemon's owner check
// refuses it to a second user, the guard socket's directory has no such check
// yet (ENG-816).
func SocketPath(name string) string {
	if runtime.GOOS == "windows" {
		if dir, err := os.UserCacheDir(); err == nil {
			return filepath.Join(dir, "Kontext", "run", name+".sock")
		}
	}
	return filepath.Join("/tmp", fmt.Sprintf("kontext-%s-%d", name, os.Getuid()), "kontext.sock")
}

// maxWindowsSocketPath is the longest path Windows binds as a Unix socket:
// sun_path holds 108 bytes, the terminating NUL included.
const maxWindowsSocketPath = 107

// CheckSocketPath refuses, on Windows, a socket path too long to bind, such as
// one under a long or non-ASCII profile path, and names the variable that sets
// a shorter one. Elsewhere the bind itself reports a path that is too long.
func CheckSocketPath(path, override string) error {
	if runtime.GOOS == "windows" && len(path) > maxWindowsSocketPath {
		return fmt.Errorf("socket path %s is %d bytes, longer than the %d Windows can bind; set %s to a shorter path", path, len(path), maxWindowsSocketPath, override)
	}
	return nil
}

func EnsureSocketDir(socketPath string) error {
	if err := CheckSocketPath(socketPath, "KONTEXT_GUARD_SOCKET"); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(socketPath), 0o700)
}
