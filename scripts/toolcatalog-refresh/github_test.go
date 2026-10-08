package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadToolsnapsCountsEveryVariant(t *testing.T) {
	dir := t.TempDir()
	snaps := filepath.Join(dir, githubToolsnaps)
	if err := os.MkdirAll(snaps, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(file, description, annotations string) {
		t.Helper()
		body := `{"name":"get_file","description":"` + description + `","annotations":` + annotations + `}`
		if err := os.WriteFile(filepath.Join(snaps, file), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func() string {
		t.Helper()
		for _, args := range [][]string{{"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "snap"}} {
			if output, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v: %s", args, err, output)
			}
		}
		output, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(output))
	}
	if output, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	write("get_file.snap", "a", `{"readOnlyHint":true}`)
	write("get_file_v2.snap", "b", `{"destructiveHint":true}`)
	before := commit()
	write("get_file.snap", "a, changed", `{"readOnlyHint":true}`)
	after := commit()

	old, err := readToolsnaps(dir, before)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := readToolsnaps(dir, after)
	if err != nil {
		t.Fatal(err)
	}
	if got := old["get_file"].Hint; got != "delete" {
		t.Fatalf("hint = %q, want the strictest variant's delete", got)
	}
	if old["get_file"].Definition == changed["get_file"].Definition {
		t.Fatal("a change to the first variant did not change the fingerprint")
	}
}
