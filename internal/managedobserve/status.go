package managedobserve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/kontext-security/kontext-cli/internal/buildinfo"
)

// DaemonStatus is the on-disk breadcrumb a daemon leaves after its socket is
// serving. It is written once at daemon startup; readers must verify the PID is
// alive before trusting it. A stale file from a dead daemon is expected and
// harmless.
type DaemonStatus struct {
	Version string `json:"version"`
	// Revision is the VCS revision the running daemon was built from. It is the
	// only field here that identifies the build: Version is a link-time label
	// and two different sources can share one. Empty for daemons built without a
	// VCS stamp, and for every daemon started before this field existed, so
	// readers must tolerate its absence rather than treat "" as a mismatch.
	Revision string `json:"revision,omitempty"`
	// Modified records that the daemon was built from a tree with uncommitted
	// changes, which makes Revision the commit it was based on rather than the
	// source that ran. Without this field two different dirty builds of one
	// commit are indistinguishable, and a reader comparing revisions alone would
	// call them the same build.
	Modified  bool   `json:"modified,omitempty"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
}

// DaemonStatusPath puts the breadcrumb next to the observe database — the one
// directory both the daemon and doctor can always derive.
func DaemonStatusPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "daemon-status.json")
}

// WriteDaemonStatus records the running daemon's identity. The build stamp is
// read from this process rather than passed in: the daemon is the authority on
// what the daemon is, and a caller-supplied value could disagree with the code
// actually executing.
func WriteDaemonStatus(dbPath, version string) error {
	return writeJSONBreadcrumb(DaemonStatusPath(dbPath), DaemonStatus{
		Version:   version,
		Revision:  buildinfo.Revision(),
		Modified:  buildinfo.Modified(),
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func LoadDaemonStatus(dbPath string) *DaemonStatus {
	data, err := os.ReadFile(DaemonStatusPath(dbPath))
	if err != nil {
		return nil
	}
	var status DaemonStatus
	// Doctor treats missing, unreadable, and bad status as the same no-status case.
	if err := json.Unmarshal(data, &status); err != nil {
		return nil
	}
	return &status
}
