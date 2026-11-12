package hookinstall

import (
	"fmt"
	"os"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// A system removal also cleans the caller's own per-user files: no test may
// reach the developer's real home.
func TestMain(m *testing.M) {
	home, err := hermetic.MainHome()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}
