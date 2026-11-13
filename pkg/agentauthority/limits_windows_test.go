//go:build windows

package agentauthority

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The walk reads a plain file and lists a plain folder, and refuses each in
// the other's mode.
func TestReadGuardedReadsPlainFilesAndFolders(t *testing.T) {
	home := t.TempDir()
	folder := filepath.Join(home, ".claude")
	path := filepath.Join(folder, "settings.json")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"read", "tail"} {
		result := readGuarded(context.Background(), path, mode)
		if result.err != nil || string(result.data) != `{"a":1}` || !result.opened || result.info == nil || result.info.Size() != 7 {
			t.Errorf("%s: got %+v, want the file's content", mode, result)
		}
	}
	// Windows names are not case sensitive, and the walk opens them as a path open does.
	if result := readGuarded(context.Background(), filepath.Join(home, ".CLAUDE", "Settings.JSON"), "read"); result.err != nil || string(result.data) != `{"a":1}` {
		t.Errorf("another spelling of the same names: %+v", result)
	}
	list := readGuarded(context.Background(), folder, "list")
	if list.err != nil || len(list.entries) != 1 || list.entries[0].Name() != "settings.json" || list.opened {
		t.Errorf("list: got %+v, want the one entry and no file opened", list)
	}
	if result := readGuarded(context.Background(), folder, "read"); result.err == nil || result.data != nil {
		t.Errorf("a folder read as a file: %+v, want a refusal", result)
	}
	if result := readGuarded(context.Background(), path, "list"); result.err == nil || result.entries != nil {
		t.Errorf("a file listed as a folder: %+v, want a refusal", result)
	}
	if result := readGuarded(context.Background(), filepath.Join(folder, "absent.json"), "read"); !errors.Is(result.err, os.ErrNotExist) || result.opened {
		t.Errorf("a missing file: %+v, want not-exist and nothing opened", result)
	}
	if isEvictedErr(os.ErrPermission) {
		t.Error("isEvictedErr reported an ordinary refusal as an eviction")
	}
}

// A junction among the ancestors, or as the last name, is not gone through:
// the file behind it is never read.
func TestReadGuardedRefusesAJunction(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "settings.json"), []byte("behind the junction"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".claude")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if result := readGuarded(context.Background(), filepath.Join(link, "settings.json"), "read"); !errors.Is(result.err, os.ErrPermission) || result.data != nil || result.opened {
		t.Errorf("a junction ancestor: %+v, want a refusal and nothing read", result)
	}
	if result := readGuarded(context.Background(), link, "list"); !errors.Is(result.err, os.ErrPermission) || result.entries != nil {
		t.Errorf("a junction listed: %+v, want a refusal", result)
	}
}

// A symlink as the file itself is not followed. Making one needs a right a
// standard user may not have; without it the case cannot be made here.
func TestReadGuardedRefusesASymlink(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "real.json")
	if err := os.WriteFile(target, []byte("behind the link"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this account cannot make a symlink: %v", err)
	}
	if result := readGuarded(context.Background(), link, "read"); !errors.Is(result.err, os.ErrPermission) || result.data != nil {
		t.Errorf("a symlink: %+v, want a refusal and nothing read", result)
	}
}

// A name with a colon means a stream of a file, and a step up or a relative
// path means another place: none is opened.
func TestReadGuardedRefusesNamesThatAreNotEntries(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "settings.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+":hidden", []byte("a stream"), 0o600); err != nil {
		t.Fatalf("write a stream: %v", err)
	}
	if err := os.Mkdir(filepath.Join(home, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path + ":hidden", path + "::$DATA", home + `\sub\..\settings.json`, "settings.json", `\settings.json`} {
		if result := readGuarded(context.Background(), name, "read"); !errors.Is(result.err, os.ErrPermission) || result.data != nil {
			t.Errorf("%q: %+v, want a refusal and nothing read", name, result)
		}
	}
}

// The scan should not be why an agent's write fails: while the walk holds a
// file and its folders, the file can be rewritten, replaced (ReplaceFile) and
// removed. One thing Windows allows no reader: a plain rename over a file
// that is open fails for as long as the handle lives ("Access is denied",
// seen on Windows 11 with every share flag set), so the walk holds the file
// only for the read itself.
func TestTheWalkHoldsNothingAgainstAWriter(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "settings.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	volume := filepath.VolumeName(path)
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(root, windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE|windows.SYNCHRONIZE, shareAll, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	var held []windows.Handle
	defer func() {
		for _, h := range held {
			windows.CloseHandle(h)
		}
	}()
	held = append(held, handle)
	parts := strings.Split(strings.Trim(filepath.ToSlash(path[len(volume):]), "/"), "/")
	for i, part := range parts {
		last := i == len(parts)-1
		if handle, err = openBelow(handle, part, !last, last); err != nil {
			t.Fatalf("open %q: %v", part, err)
		}
		held = append(held, handle)
	}
	// Every handle of the walk is still open here, the file's among them.
	if err := os.WriteFile(path, []byte("rewritten"), 0o600); err != nil {
		t.Errorf("write in place: %v", err)
	}
	next := path + ".tmp"
	if err := os.WriteFile(next, []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	from, _ := windows.UTF16PtrFromString(next)
	to, _ := windows.UTF16PtrFromString(path)
	if err := replaceFile.Find(); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := replaceFile.Call(uintptr(unsafe.Pointer(to)), uintptr(unsafe.Pointer(from)), 0, 0, 0, 0); ok == 0 {
		t.Errorf("ReplaceFile: %v", err)
	} else if data, _ := os.ReadFile(path); string(data) != "replaced" {
		t.Errorf("after ReplaceFile the file holds %q", data)
	}
	if err := os.Remove(path); err != nil {
		t.Errorf("remove: %v", err)
	}
}

// A file over the limit is refused by its size before a byte is read, and a
// tail reads its end.
func TestReadGuardedKeepsTheSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("end"), maxFileBytes-2); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if result := readGuarded(context.Background(), path, "read"); !errors.Is(result.err, errTooLarge) || result.data != nil {
		t.Errorf("read: err %v, %d bytes; want too large and nothing read", result.err, len(result.data))
	}
	// The limit holds before any mode looks at the file, as on unix.
	if result := readGuarded(context.Background(), path, "stat"); !errors.Is(result.err, errTooLarge) {
		t.Errorf("stat: err %v, want too large", result.err)
	}
	if result := readGuarded(context.Background(), path, "tail"); result.err != nil || !strings.HasSuffix(string(result.data), "end") {
		t.Errorf("tail: err %v, %d bytes; want the file's end", result.err, len(result.data))
	}
}

// A file whose content a sync provider would have to fetch is refused before
// anything is read. The offline attribute is the one of the placeholder
// attributes a test can set on a plain file.
func TestReadGuardedRefusesAPlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_OFFLINE); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"read", "stat", "tail"} {
		if result := readGuarded(context.Background(), path, mode); !errors.Is(result.err, errDataless) || result.data != nil {
			t.Errorf("%s: err %v, %d bytes; want content not on disk and nothing read", mode, result.err, len(result.data))
		}
	}
}

var replaceFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

func TestGuardedInfoStartsAtTheVolume(t *testing.T) {
	dir, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want []string
	}{
		{`C:\Users\a\.ssh\id`, []string{`C:\`, `C:\Users`, `C:\Users\a`, `C:\Users\a\.ssh`, `C:\Users\a\.ssh\id`}},
		{`\\server\share\home\a\.ssh\id`, []string{`\\server\share\`, `\\server\share\home`, `\\server\share\home\a`, `\\server\share\home\a\.ssh`, `\\server\share\home\a\.ssh\id`}},
	} {
		var walked []string
		stat := func(p string) (os.FileInfo, error) {
			walked = append(walked, p)
			return dir, nil
		}
		if _, err := guardedInfo(tc.path, stat, false); err != nil {
			t.Errorf("%s: %v", tc.path, err)
		}
		if !slices.Equal(walked, tc.want) {
			t.Errorf("%s: walked %q, want %q", tc.path, walked, tc.want)
		}
	}
}

func TestGuardedInfoRefusesAFlaggedRoot(t *testing.T) {
	dir, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{`C:\`, `\\server\share\`} {
		stat := func(p string) (os.FileInfo, error) {
			if p == root {
				return attributeInfo{dir, syscall.Win32FileAttributeData{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_RECALL_ON_OPEN}}, nil
			}
			return dir, nil
		}
		if _, err := guardedInfo(root+`home\a\.ssh\id`, stat, false); !errors.Is(err, os.ErrPermission) {
			t.Errorf("%s as a placeholder: err = %v, want a refusal", root, err)
		}
	}
}

func TestStatRefusesJunctionAndPlaceholderAncestors(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	key := filepath.Join(ssh, "id_ed25519.pub")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	stat := func(lstat func(string) (os.FileInfo, error)) fileResult {
		r := Report{}
		g := guard{ctx: context.Background(), home: home, roots: allowedRoots(home, managedRoot), report: &r, lstat: lstat}
		return g.access(key, "stat")
	}
	if result := stat(nil); result.err != nil || result.info == nil || !result.info.Mode().IsRegular() {
		t.Fatalf("plain file: %+v", result)
	}
	// A placeholder directory keeps the directory bit; the walk refuses it before the file.
	placeholder := func(p string) (os.FileInfo, error) {
		info, err := os.Lstat(p)
		if p == ssh && err == nil {
			return attributeInfo{info, syscall.Win32FileAttributeData{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_RECALL_ON_OPEN}}, nil
		}
		return info, err
	}
	if result := stat(placeholder); !errors.Is(result.err, os.ErrPermission) {
		t.Errorf("placeholder ancestor: err = %v, want a refusal", result.err)
	}
	// Go reports a junction as irregular, neither a symlink nor a directory.
	target := filepath.Join(home, "target")
	if err := os.Rename(ssh, target); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", ssh, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if result := stat(nil); !errors.Is(result.err, os.ErrPermission) {
		t.Errorf("junction ancestor: err = %v, want a refusal", result.err)
	}
}

// A rename over a file fails while anything holds the file open, even for
// its attributes alone, unless the holder lets the kernel make the writer
// wait. The scan touches a file three ways, to ask what it is, to ask
// whether it can still be read, and to read it, and each gives way: with
// all three running without pause, every rename over the file goes through.
func TestARenameOverWaitsForTheRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan int)
	go func() {
		reads := 0
		for {
			select {
			case <-stop:
				done <- reads
				return
			default:
			}
			if _, err := statGuarded(context.Background(), path, "read"); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("stat: %v", err)
			}
			if err := readable(path, "read"); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("readable: %v", err)
			}
			if result := readGuarded(context.Background(), path, "read"); result.err != nil && !errors.Is(result.err, os.ErrNotExist) {
				t.Errorf("read: %v", result.err)
			}
			reads++
		}
	}()
	failed := 0
	var first error
	for i := range 400 {
		next := filepath.Join(dir, "config.toml.tmp")
		if err := os.WriteFile(next, []byte("version "+strings.Repeat("x", i)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(next, path); err != nil {
			failed++
			if first == nil {
				first = err
			}
		}
	}
	close(stop)
	// Each round of the reader waits for the renames it meets, so it makes
	// fewer rounds than there are renames; far fewer would mean the two
	// did not run side by side.
	if rounds := <-done; rounds < 50 {
		t.Fatalf("only %d rounds of the reader ran beside 400 renames; the two barely met", rounds)
	}
	if failed != 0 {
		t.Errorf("%d of 400 renames over the file failed while it was being read; first: %v", failed, first)
	}
}

// A file whose content this user may not read is still there: asking what
// it is needs only its attributes, as lstat does, while reading it and the
// cache's readable check are refused.
func TestStatNeedsNoRightToReadTheContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	who, err := exec.Command("whoami").Output()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", path, "/deny", strings.TrimSpace(string(who))+":(RD)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	info, err := statGuarded(context.Background(), path, "stat")
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() != 9 {
		t.Errorf("stat: info %v, err %v; want the file seen", info, err)
	}
	if result := readGuarded(context.Background(), path, "read"); !errors.Is(result.err, os.ErrPermission) || result.data != nil {
		t.Errorf("read: err %v, %d bytes; want a refusal", result.err, len(result.data))
	}
	if err := readable(path, "read"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("readable: err %v, want a refusal", err)
	}
}
