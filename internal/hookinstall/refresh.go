package hookinstall

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext/internal/claudemanaged"
)

// ClaudeRefreshDigest plans an upgrade of an existing, Kontext-owned drop-in.
// An empty digest means the installed hooks already satisfy this binary.
// Missing and foreign files are errors: upgrades must not enroll a new machine
// or take ownership of an administrator's configuration.
func ClaudeRefreshDigest(path, binary string) (string, error) {
	c, err := claudeRefreshPlan(path, binary)
	if err != nil {
		return "", err
	}
	if claudemanaged.Validate(c.before, binary) == nil {
		return "", nil
	}
	return fmt.Sprintf("%x", sha256.Sum256(c.before)), nil
}

// RefreshClaude upgrades only Claude's existing drop-in. The caller must have
// root privileges. Rechecking the approved digest after elevation prevents an
// administrator's intervening changes from being overwritten during a prompt.
func RefreshClaude(path, binary, expectedDigest string) error {
	c, err := claudeRefreshPlan(path, binary)
	if err != nil {
		return err
	}
	if expectedDigest == "" || fmt.Sprintf("%x", sha256.Sum256(c.before)) != expectedDigest {
		return fmt.Errorf("Claude hooks changed while awaiting approval; refusing to overwrite")
	}
	if c.result.Action == "skip" {
		return nil
	}
	return apply(c, Options{WriteClaude: func(path string, data []byte) error {
		return WriteClaudeFile(path, data, 0, nil)
	}})
}

func claudeRefreshPlan(path, binary string) (change, error) {
	if !filepath.IsAbs(binary) || filepath.Base(binary) != "kontext" || strings.ContainsAny(binary, "\n\r\x00") || !executable(binary) {
		return change{}, fmt.Errorf("hook binary is not executable: %s", binary)
	}
	file := File{Kind: "claude", Path: path, Scope: System}
	c, err := plan(file, Options{Binary: binary}, false)
	if err != nil {
		return c, err
	}
	if c.missing {
		return c, fmt.Errorf("Claude hook migration requires an existing drop-in: %w", os.ErrNotExist)
	}
	return c, nil
}
