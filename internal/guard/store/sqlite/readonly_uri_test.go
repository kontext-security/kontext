package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func checkReadOnlyOpens(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	observed, err := HasCoworkSession(ctx, path, "fixture")
	if err != nil || !observed {
		t.Errorf("HasCoworkSession = %t, %v; want true", observed, err)
	}
	if _, _, err := LedgerLag(ctx, path, nil); err != nil {
		t.Errorf("LedgerLag: %v", err)
	}
	db, err := sql.Open("sqlite", readOnlyURI(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "create table not_read_only (x)"); err == nil {
		t.Error("a write through the URI succeeded")
	}
}

func openFixtureStore(t *testing.T, path string) {
	t.Helper()
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if _, err := store.EnsureObservedSession(context.Background(), "fixture", "cowork", "/tmp"); err != nil {
		t.Fatal(err)
	}
}

// The store sits under a user's home, whose name is not ours to choose. These
// are the characters a URI gives a meaning to and a folder name can hold on
// every OS. On Windows each path also starts with a drive.
func TestReadOnlyStoresOpenFromAnyFolderName(t *testing.T) {
	root := t.TempDir()
	for _, folder := range []string{"plain", "with space", "a#b", "100%", "a%20b", "a&b"} {
		t.Run(folder, func(t *testing.T) {
			dir := filepath.Join(root, folder)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "guard.db")
			openFixtureStore(t, path)
			checkReadOnlyOpens(t, path)
		})
	}
}

// The store path can come from the environment, so it can be relative.
func TestReadOnlyStoresOpenFromARelativePath(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("sub", 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("sub", "guard.db")
	openFixtureStore(t, path)
	checkReadOnlyOpens(t, path)
}

// ".." after a symlink is the link target's parent, so cleaning the path
// lexically would read a different file. Windows resolves ".." in the text
// before it looks at links, so the case doesn't arise there.
func TestReadOnlyStoresKeepAPathUncleaned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip(`Windows resolves ".." before links`)
	}
	root := t.TempDir()
	real := filepath.Join(root, "real", "deep")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	openFixtureStore(t, filepath.Join(root, "real", "guard.db"))
	checkReadOnlyOpens(t, link+string(filepath.Separator)+".."+string(filepath.Separator)+"guard.db")
}
