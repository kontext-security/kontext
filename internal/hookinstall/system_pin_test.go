package hookinstall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Organization packages install with --scope system. Self-serve changes must
// leave every byte they write identical; regenerate only for an intended MDM
// change with KONTEXT_UPDATE_SYSTEM_PIN=1.
func TestSystemScopeOutputPinned(t *testing.T) {
	opts, defs := fixture(t, System)
	if err := runDefinitions(opts, defs, false); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(opts.Binary)
	for _, d := range defs {
		for _, f := range d.Files {
			got := strings.ReplaceAll(read(t, f.Path), opts.Binary, "<bin>")
			rel, err := filepath.Rel(root, f.Path)
			if err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", "system-pin", strings.NewReplacer("/", "_", " ", "-").Replace(filepath.ToSlash(rel)))
			if os.Getenv("KONTEXT_UPDATE_SYSTEM_PIN") == "1" {
				write(t, golden, got, 0644)
				continue
			}
			if want := read(t, golden); got != want {
				t.Fatalf("%s changed:\n%s", f.Path, got)
			}
		}
	}
}
