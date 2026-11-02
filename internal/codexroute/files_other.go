//go:build !darwin && !linux

package codexroute

import (
	"errors"
	"io/fs"
	"os"
)

// Off macOS nothing is routed, so nothing takes these.

func lockFile(string, bool) (func(), bool, error) { return func() {}, true, nil }

func installBinary(*os.File, string) error { return errors.New("the Codex proxy runs on macOS only") }

func fileIdentity(fs.FileInfo) string { return "" }
