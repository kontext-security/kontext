package agentauthority

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCoworkVMLogTail(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	path := filepath.Join(home, "Library/Logs/Claude/cowork_vm_swift.log")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data := append(bytes.Repeat([]byte("outside tail\n"), 200000), bytes.Repeat([]byte("z"), 64*1024)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := CoworkVMLogTail(context.Background(), home)
	if err != nil || !bytes.Equal(got, data[len(data)-64*1024:]) {
		t.Fatalf("tail length=%d, error=%v", len(got), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := CoworkVMLogTail(ctx, home); err == nil || len(got) != 0 {
		t.Fatal("cancelled scan read the log")
	}
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if got, err := CoworkVMLogTail(context.Background(), home); err == nil || len(got) != 0 {
		t.Fatal("guard followed a log symlink")
	}
}
