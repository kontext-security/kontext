package agenthooks

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// IsKontextBinary reports whether path names a Kontext executable: kontext,
// or kontext.exe in any letter case, as Windows matches file names. It splits
// on both separators, so a hook file written on Windows is recognised on any
// OS.
func IsKontextBinary(path string) bool {
	base := path[strings.LastIndexAny(path, `/\`)+1:]
	return base == "kontext" || strings.EqualFold(base, "kontext.exe")
}

// IsExecutable reports whether path is a regular file this OS runs directly.
// Windows files carry no execute bit, so there it has to be an .exe.
func IsExecutable(path string) bool {
	return isExecutableOn(runtime.GOOS, path)
}

func isExecutableOn(goos, path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if goos == "windows" {
		return strings.EqualFold(filepath.Ext(path), ".exe")
	}
	return info.Mode()&0o111 != 0
}
