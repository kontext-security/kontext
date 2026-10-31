// Package privacyfolder tells whether a path lies in a folder macOS guards
// with a privacy prompt: Desktop, Documents, Downloads, iCloud Drive,
// file-provider cloud storage, and removable or network volumes.
//
// The kontext daemon runs as its own process, not as a child of the agent
// that already has access, so touching a file there (or running git there)
// asks the user to let kontext into the folder. Callers skip such paths.
package privacyfolder

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Enabled is false off macOS, where these folders carry no prompt.
var Enabled = runtime.GOOS == "darwin"

var homeFolders = []string{"Desktop", "Documents", "Downloads", "Library/Mobile Documents", "Library/CloudStorage"}

// Guarded reports whether reading path would touch a guarded folder. It
// resolves symlinks one component at a time and checks each resolved prefix
// before touching it, so a link into a guarded folder is caught by its text
// and never followed. home is the user's home directory; "" means the
// current user's. A relative path is never guarded.
func Guarded(home, path string) bool {
	if !Enabled || !filepath.IsAbs(path) {
		return false
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	roots, homeVolume := guardedRoots(home)
	inside := func(p string) bool {
		// A home on an external volume is the user's own; every other
		// volume carries the removable or network volume prompt.
		if within(p, "/Volumes") && !strings.EqualFold(filepath.Clean(p), "/Volumes") && !within(p, homeVolume) {
			return true
		}
		for _, root := range roots {
			if within(p, root) {
				return true
			}
		}
		return false
	}
	if inside(path) {
		return true
	}
	resolved := "/"
	pending := strings.Split(filepath.Clean(path), "/")
	for hops := 0; len(pending) > 0; {
		part := pending[0]
		pending = pending[1:]
		if part == "" || part == "." {
			continue
		}
		next := filepath.Join(resolved, part)
		if inside(next) {
			return true
		}
		info, err := os.Lstat(next)
		if err != nil {
			// Nothing exists past here to link elsewhere; the rest of the
			// path is as written.
			return inside(filepath.Join(append([]string{next}, pending...)...))
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if hops++; hops > 32 {
			// A link loop is not a path worth reading.
			return true
		}
		target, err := os.Readlink(next)
		if err != nil {
			return false
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return false
}

// Encloses reports whether path holds a guarded folder, so that reading
// everything below it reaches one: the root, /Users, the home directory,
// ~/Library or /Volumes, say. home is as for Guarded.
func Encloses(home, path string) bool {
	if !Enabled || !filepath.IsAbs(path) {
		return false
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	path = filepath.Clean(path)
	if path == "/" || strings.EqualFold(path, "/Volumes") {
		return true
	}
	roots, _ := guardedRoots(home)
	for _, root := range append(roots, "/Volumes") {
		if within(root, path) && !strings.EqualFold(filepath.Clean(root), path) {
			return true
		}
	}
	return false
}

// GuardedPattern reports whether a shell wildcard pattern may name a
// guarded folder, a path inside one, or a folder that holds one (see
// Encloses). Wildcards above its last element cannot be checked and count
// as guarded. home is as for Guarded.
func GuardedPattern(home, pattern string) bool {
	if !Enabled || !filepath.IsAbs(pattern) {
		return false
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	dir, base := filepath.Split(filepath.Clean(pattern))
	dir = filepath.Clean(dir)
	if strings.ContainsAny(dir, "*?[") || Guarded(home, dir) || strings.EqualFold(dir, "/Volumes") {
		return true
	}
	roots, _ := guardedRoots(home)
	for _, root := range append(roots, "/Volumes") {
		// The element of the root's path right below dir is what the
		// pattern would have to match.
		rel, err := filepath.Rel(strings.ToLower(dir), strings.ToLower(filepath.Clean(root)))
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		first, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
		if matched, _ := filepath.Match(strings.ToLower(base), first); matched {
			return true
		}
	}
	return false
}

// guardedRoots lists the guarded folders under home: as given, with its
// symlinks resolved (/var/folders is /private/var/folders), and through the
// data volume firmlink (/System/Volumes/Data/Users/...), which is no symlink
// to resolve. It also returns the external volume home lives on, if any.
func guardedRoots(home string) (roots []string, homeVolume string) {
	if home == "" {
		return nil, ""
	}
	homes := []string{home}
	if physical, err := filepath.EvalSymlinks(home); err == nil && physical != home {
		homes = append(homes, physical)
	}
	for _, h := range homes {
		homes = append(homes, filepath.Join("/System/Volumes/Data", h))
	}
	for _, h := range homes {
		for _, dir := range homeFolders {
			roots = append(roots, filepath.Join(h, dir))
		}
		if within(h, "/Volumes") {
			name, _, _ := strings.Cut(strings.TrimPrefix(filepath.Clean(h), "/Volumes/"), "/")
			homeVolume = filepath.Join("/Volumes", name)
		}
	}
	return roots, homeVolume
}

// within reports path at or below root. APFS volumes are case-insensitive by
// default.
func within(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	path, root = strings.ToLower(filepath.Clean(path)), strings.ToLower(filepath.Clean(root))
	return path == root || strings.HasPrefix(path, root+"/")
}
