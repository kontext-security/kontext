package codexmanaged

import "os"

// readSystemHooks reads the System layer's file (a test seam).
var readSystemHooks = readAdminOnly

// readLayer reads a layer's hooks file. Codex treats the System layer's hooks as
// managed, so that file counts only if a user couldn't have written it. A folder
// without the file is no layer at all, whoever created it.
func readLayer(path string) ([]byte, error) {
	if path != SystemHooksPath {
		return os.ReadFile(path)
	}
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	return readSystemHooks(path)
}
