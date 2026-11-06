package cedarpolicy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// A daemon restarting on an enrolled endpoint loads the persisted policy
// before it serves hooks, so it does not await enrolment and holds nothing
// (ENG-939). A fresh install, with no cache file, does.
func TestRestartWithACachedPolicyDoesNotAwaitEnrolment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cedar-policy.json")
	deployment := testDeployment(t, cedareval.RolloutModeEnforce)
	before := NewCache(path, 0)
	if err := before.Apply(FetchResult{State: StateSuccess, Deployment: &deployment}, time.Now()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	restarted := NewCache(path, 0)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if state := restarted.Current().State; AwaitingEnrolment(state) {
		t.Fatalf("restarted state = %q, want a loaded policy that does not await enrolment", state)
	}

	fresh := NewCache(filepath.Join(t.TempDir(), "cedar-policy.json"), 0)
	if err := fresh.Load(); err != nil {
		t.Fatalf("Load() without a cache file error = %v", err)
	}
	if state := fresh.Current().State; !AwaitingEnrolment(state) {
		t.Fatalf("fresh state = %q, want it to await enrolment", state)
	}
}
