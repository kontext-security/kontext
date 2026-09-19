//go:build darwin

package agentauthority

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
)

// SQLite needs the real pathname to discover WAL/SHM siblings. Keep the guarded
// descriptor pinned and verify its identity around the pathname-based query;
// the immutable fallback reads that descriptor directly.
// Only the boolean leaves SQLite, and both attempts share the read deadline.
func readCursor(ctx context.Context, file *os.File) (*bool, error) {
	const query = `select case json_type(value,'$.composerState.useYoloMode') when 'true' then 1 when 'false' then 0 else 'unknown' end from ItemTable where key='src.vs.platform.reactivestorage.browser.reactiveStorageServiceImpl.persistentStorage.applicationUser' limit 1`
	var output []byte
	var err error
	uri := (&url.URL{Scheme: "file", Path: file.Name(), RawQuery: "mode=ro"}).String()
	for _, database := range []string{uri, "file:/dev/fd/3?immutable=1"} {
		if database == uri {
			if err = cursorPathUnchanged(file); err != nil {
				continue
			}
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/sqlite3", "-init", "/dev/null", "-readonly", database, query)
		cmd.ExtraFiles = []*os.File{file}
		output, err = cmd.Output()
		if err == nil {
			if database == uri {
				if err = cursorPathUnchanged(file); err != nil {
					return nil, err
				}
			}
			break
		}
	}
	if err != nil {
		return nil, errors.New("Cursor settings query failed")
	}
	switch string(output) {
	case "1\n":
		value := true
		return &value, nil
	case "0\n":
		value := false
		return &value, nil
	default:
		return nil, errors.New("unknown Cursor auto-run setting")
	}
}

func cursorPathUnchanged(file *os.File) error {
	pinned, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := guardedInfo(file.Name(), os.Lstat, true)
	if err != nil || !os.SameFile(pinned, current) {
		return os.ErrPermission
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := guardedInfo(file.Name()+suffix, os.Lstat, true)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return os.ErrPermission
		}
	}
	return nil
}
