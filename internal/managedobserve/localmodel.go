package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/guard/judge"
	"github.com/kontext-security/kontext/internal/managedconfig"
)

func localRiskModelWarning(managed, binary string) string {
	enabled, _ := strconv.ParseBool(strings.TrimSpace(managed))
	if !enabled {
		return ""
	}
	if strings.TrimSpace(binary) == "" {
		binary = judge.DefaultLlamaServerBinary
	}
	if _, err := exec.LookPath(binary); err == nil {
		return ""
	}
	return fmt.Sprintf("local risk model is enabled but llama-server is missing at %s; install it with: brew install llama.cpp", binary)
}

func doctorLocalRiskModelWarning(scope managedconfig.Scope) (string, error) {
	managed, binary := os.Getenv("KONTEXT_JUDGE_MANAGED"), os.Getenv("KONTEXT_JUDGE_SERVER_BIN")
	if scope == managedconfig.ScopeUser || scope == managedconfig.ScopeSystem {
		dir := "/Library/LaunchAgents"
		if scope == managedconfig.ScopeUser {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(home, "Library", "LaunchAgents")
		}
		path := filepath.Join(dir, DefaultLabel()+".plist")
		_, err := os.Stat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err == nil {
			// Setup persists the opt-in in launchd's environment, which doctor
			// does not inherit when it runs from the user's shell.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			readEnv := func(key string) string {
				value, err := runCommand(ctx, "/usr/bin/plutil", "-extract", "EnvironmentVariables."+key, "raw", "-o", "-", path)
				if err != nil {
					return ""
				}
				return strings.TrimSpace(value)
			}
			managed, binary = readEnv("KONTEXT_JUDGE_MANAGED"), readEnv("KONTEXT_JUDGE_SERVER_BIN")
		}
	}
	return localRiskModelWarning(managed, binary), nil
}
