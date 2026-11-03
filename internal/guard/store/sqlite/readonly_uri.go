package sqlite

import (
	"net/url"
	"path/filepath"
	"strings"
)

// readOnlyURI builds the URI that opens the store at path read-only. Handing
// SQLite the path as it stands fails twice over: a '#' or '%' in a folder name
// means something in a URI, and a Windows drive has to be file:///C:/..., since
// anything else after file:// reads as a host. The path isn't cleaned, because
// ".." after a symlink doesn't mean what it looks like.
func readOnlyURI(path string) string {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro"}
	switch {
	case !filepath.IsAbs(path):
		u.OmitHost = true
	case !strings.HasPrefix(u.Path, "/"):
		u.Path = "/" + u.Path
	}
	return u.String()
}
