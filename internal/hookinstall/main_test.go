package hookinstall

import (
	"fmt"
	"os"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// A system removal also cleans per-user files: no test may reach a real home,
// whoever runs it.
func TestMain(m *testing.M) {
	// No fixture's system removal reaches a real home: a test that cleans
	// homes names its own.
	perUserHomes = func(Options) []userHome { return nil }
	home, err := hermetic.MainHome()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}
