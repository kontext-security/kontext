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
	return filepath.Join(SocketDir("guard"), "kontext.sock")
}

// SocketDir returns the per-user directory for the socket called name. On
// Unix it is /tmp/kontext-<name>-<uid>, short because sun_path is 104 bytes on
// macOS. On Windows os.Getuid returns -1, so that path would be one directory
// for every user; the user's local app data (%LOCALAPPDATA%\Kontext\run\<name>)
// is used instead. Without LOCALAPPDATA the Unix form remains, which the
// daemon's owner check refuses for a second user.
func SocketDir(name string) string {
	if runtime.GOOS == "windows" {
		if dir, err := os.UserCacheDir(); err == nil {
			return filepath.Join(dir, "Kontext", "run", name)
		}
	}
	return filepath.Join("/tmp", fmt.Sprintf("kontext-%s-%d", name, os.Getuid()))
}

func EnsureSocketDir(socketPath string) error {
	return os.MkdirAll(filepath.Dir(socketPath), 0o700)
}
