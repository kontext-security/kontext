//go:build darwin || linux

package codexroute

import (
	"os"
	"path/filepath"
	"testing"
)

// Where the volume cannot clone the binary, the job gets a copy.
func TestTheBinaryIsCopiedWhereItCannotBeCloned(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kontext"), build2, 0o755)
	binary, err := os.Open(filepath.Join(dir, "kontext"))
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	copied := filepath.Join(dir, "copy")
	if err := copyBinary(binary, copied); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(copied); err != nil || info.Mode().Perm() != 0o700 || readFile(t, copied) != build2 {
		t.Fatalf("copy: %v, %v", info, err)
	}
}
