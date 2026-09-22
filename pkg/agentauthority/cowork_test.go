package agentauthority

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCoworkWebLogTail(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	path := filepath.Join(home, "Library/Logs/Claude/claude.ai-web.log")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data := append([]byte("outside tail\n"), bytes.Repeat([]byte("z"), 8*1024*1024)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := CoworkWebLogTail(context.Background(), home)
	if err != nil || !bytes.Equal(got, data[len(data)-8*1024*1024:]) {
		t.Fatalf("tail length=%d, error=%v", len(got), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := CoworkWebLogTail(ctx, home); err == nil || len(got) != 0 {
		t.Fatal("cancelled scan read the log")
	}
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if got, err := CoworkWebLogTail(context.Background(), home); err == nil || len(got) != 0 {
		t.Fatal("guard followed a log symlink")
	}
}
