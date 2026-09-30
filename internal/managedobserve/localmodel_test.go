package managedobserve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLocalRiskModelWarning(t *testing.T) {
	for name, test := range map[string]struct {
		managed string
		mode    os.FileMode
		present bool
		want    bool
	}{
		"enabled missing": {managed: "1", want: true},
		"enabled present": {managed: "true", present: true, mode: 0o755},
		"not executable":  {managed: "1", present: true, mode: 0o644, want: true},
		"disabled":        {managed: "false"},
		"not configured":  {},
	} {
		t.Run(name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "llama-server")
			if test.present {
				if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), test.mode); err != nil {
					t.Fatal(err)
				}
			}
			warning := localRiskModelWarning(test.managed, binary)
			want := ""
			if test.want {
				want = fmt.Sprintf("local risk model is enabled but llama-server is missing at %s; install it with: brew install llama.cpp", binary)
			}
			if warning != want {
				t.Fatalf("localRiskModelWarning() = %q, want %q", warning, want)
			}
		})
	}
}

func TestDoctorLocalRiskModelFromLaunchAgent(t *testing.T) {
	for _, name := range []string{"enabled missing", "enabled present", "not executable", "disabled", "missing keys", "no plist"} {
		t.Run(name, func(t *testing.T) {
			env := newDoctorTestEnv(t)
			resetUpdaterSeams(t)
			env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
			binary := filepath.Join(env.dir, "llama & server")
			t.Setenv("KONTEXT_JUDGE_MANAGED", "1")
			t.Setenv("KONTEXT_JUDGE_SERVER_BIN", binary)
			if name == "enabled present" || name == "not executable" {
				mode := os.FileMode(0o755)
				if name == "not executable" {
					mode = 0o644
				}
				if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), mode); err != nil {
					t.Fatal(err)
				}
			}
			managed := "1"
			if name == "disabled" {
				managed = "0"
			}
			path := filepath.Join(env.dir, "Library", "LaunchAgents", DefaultLabel()+".plist")
			if name != "no plist" {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			runCommand = func(ctx context.Context, command string, args ...string) (string, error) {
				key := []string{"KONTEXT_JUDGE_MANAGED", "KONTEXT_JUDGE_SERVER_BIN"}[calls]
				calls++
				if command != "/usr/bin/plutil" || !reflect.DeepEqual(args, []string{"-extract", "EnvironmentVariables." + key, "raw", "-o", "-", path}) {
					t.Fatalf("unexpected command: %s %v", command, args)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("plutil command has no timeout")
				}
				if name == "missing keys" {
					return "No value at that key path", errors.New("exit status 1")
				}
				if key == "KONTEXT_JUDGE_MANAGED" {
					return managed + "\n", nil
				}
				return binary + "\n", nil
			}
			var out bytes.Buffer
			status, report := printStatus(&out, "1.2.3", env.options())
			wantCalls := 2
			if name == "no plist" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("plutil calls = %d, want %d", calls, wantCalls)
			}
			wantWarning := name == "enabled missing" || name == "not executable" || name == "no plist"
			message := fmt.Sprintf("local risk model is enabled but llama-server is missing at %s; install it with: brew install llama.cpp", binary)
			if got := strings.Contains(out.String(), "WARNING: "+message); got != wantWarning {
				t.Fatalf("warning = %v, want %v:\n%s", got, wantWarning, out.String())
			}
			if got := strings.Contains(strings.Join(report.Warnings, "\n"), message); got != wantWarning {
				t.Fatalf("report warnings = %v, want local model warning %v", report.Warnings, wantWarning)
			}
			if !status.Healthy || !report.Healthy {
				t.Fatalf("status = %+v, report healthy = %v, want healthy:\n%s", status, report.Healthy, out.String())
			}
		})
	}
}
