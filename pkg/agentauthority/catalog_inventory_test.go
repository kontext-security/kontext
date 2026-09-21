package agentauthority_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

func TestWholeCatalogKnown(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var agents []agentauthority.AgentLocation
	for _, d := range agentinventory.Catalog {
		agents = append(agents, agentauthority.AgentLocation{ID: d.ID, ConfigPath: filepath.Join(home, d.ConfigDirs[0])})
	}
	r := agentauthority.Scan(context.Background(), home, agentauthority.Environment{}, agents, time.Now())
	if len(r.Agents) != 25 || len(r.Coverage.UnknownFormat) != 0 {
		t.Fatalf("catalog coverage: %+v", r.Coverage)
	}
	r = agentauthority.Scan(context.Background(), home, agentauthority.Environment{}, []agentauthority.AgentLocation{{ID: "future_agent", ConfigPath: home}}, time.Now())
	if len(r.Coverage.UnknownFormat) != 1 {
		t.Fatal("future agent must remain unknown")
	}
}
