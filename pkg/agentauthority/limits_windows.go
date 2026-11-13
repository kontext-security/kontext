//go:build windows

package agentauthority

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Every open shares reading, writing and deleting. With less, another
// process's write in place, ReplaceFile or delete fails while the scan holds
// the file. A rename over the file fails even so; giveWay is for that one.
const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// isEvictedErr has no equivalent here: a placeholder is refused before any read.
func isEvictedErr(error) bool { return false }

// readable reports whether what was read before can still be opened for
// reading, a file or a folder as the mode says. The cache asks it before
// answering from an earlier read, since a changed ACL leaves the version
// alone.
func readable(path, mode string) error {
	to := walkTo(mode)
	to.mode = ""
	return walk(context.Background(), path, to).err
}

// statGuarded says what a path is, from the handle the walk ends on. A
// plain lstat would do for the answer, but it opens the file for a moment
// with nothing that makes a writer wait, and measured, that moment is
// enough to fail a rename over the file. Like lstat it asks for no more
// than the attributes, so a file whose content this user may not read is
// still seen to be there.
func statGuarded(ctx context.Context, path, mode string) (os.FileInfo, error) {
	to := walkTo(mode)
	to.mode, to.content = "", false
	result := walk(ctx, path, to)
	return result.info, result.err
}

// walkFor is what a walk is for: a folder or a file at its end, with or
// without the size limit, giving way to a writer or not, and which read to
// make there; none, when only what the path is is asked.
type walkFor struct {
	folder, noLimit, lock bool
	// content opens the end for reading; without it, for its attributes.
	content bool
	mode    string
}

// walkTo is the walk a read mode makes. Only reads of files that are
// replaced as a whole, as configs are, give way to a writer: a log or a
// database that its agent appends to is not renamed over, and its agent
// should not wait for a long read of it.
func walkTo(mode string) walkFor {
	to := walkFor{folder: mode == "list" || mode == "sessions", noLimit: mode == "tail" || mode == "cursor", content: true, mode: mode}
	to.lock = !to.folder && !to.noLimit
	return to
}

// readGuarded is the walk the unix build makes with openat and O_NOFOLLOW:
// it opens the path's volume, then every component by its name alone,
// relative to the handle of the one before, and never follows a reparse
// point. What it checks (no reparse point, no cloud placeholder, a folder
// where one is needed, the size) it reads from the handle it then goes on
// with, so the file that is read is the file that was checked, whatever
// happens to the path meanwhile. What the walk cannot decide is refused.
func readGuarded(ctx context.Context, path, mode string) fileResult {
	return walk(ctx, path, walkTo(mode))
}

func walk(ctx context.Context, path string, to walkFor) (result fileResult) {
	tail, wantsFolder, mode := to.noLimit, to.folder, to.mode
	volume := filepath.VolumeName(path)
	if volume == "" || !filepath.IsAbs(path) {
		result.err = os.ErrPermission
		return
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		result.err = os.ErrPermission
		return
	}
	handle, err := windows.CreateFile(root, windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE|windows.SYNCHRONIZE, shareAll, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		result.err = err
		return
	}
	if _, err := checkHandle(handle, true, tail); err != nil {
		windows.CloseHandle(handle)
		result.err = err
		return
	}
	rest := strings.Trim(filepath.ToSlash(path[len(volume):]), "/")
	if rest == "" {
		windows.CloseHandle(handle)
		result.err = os.ErrPermission
		return
	}
	parts := strings.Split(rest, "/")
	for i, part := range parts {
		last := i == len(parts)-1
		if last && to.lock {
			// Deferred before the file is, so it lets go after the file is closed.
			defer giveWay(handle, part)()
		}
		next, err := openBelow(handle, part, !last || wantsFolder, last && to.content)
		windows.CloseHandle(handle)
		if err != nil {
			result.err = err
			return
		}
		handle = next
		if _, err := checkHandle(handle, !last || wantsFolder, tail); err != nil {
			windows.CloseHandle(handle)
			result.err = err
			return
		}
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		result.err = os.ErrPermission
		return
	}
	result.info = info
	// Only opened regular files spend the file budget, not the folders on
	// the way.
	result.opened = info.Mode().IsRegular()
	if wantsFolder != info.IsDir() || (!wantsFolder && !info.Mode().IsRegular()) {
		result.err = os.ErrPermission
		return
	}
	switch mode {
	case "":
	case "cursor":
		value, err := readCursor(ctx, file)
		result.parsed = value
		if err != nil {
			result.parseErr = errParse
			if errors.Is(err, errUnsupportedFormat) {
				result.parseErr = errors.Join(errParse, errUnsupportedFormat)
			}
		}
	case "stat":
	case "read":
		if info.Size() > maxFileBytes {
			result.err = errTooLarge
			return
		}
		result.data, result.err = io.ReadAll(io.LimitReader(file, maxFileBytes+1))
		if len(result.data) > maxFileBytes {
			result.data = nil
			result.err = errTooLarge
		}
	case "tail":
		const tailBytes = 8 * 1024 * 1024
		_, result.err = file.Seek(max(0, info.Size()-tailBytes), io.SeekStart)
		if result.err == nil {
			result.data, result.err = io.ReadAll(io.LimitReader(file, tailBytes))
		}
	case "sessions":
		result.entries, result.err = file.ReadDir(maxSessionEntries + 1)
		if result.err == io.EOF {
			result.err = nil
		}
	case "list":
		result.entries, result.err = file.ReadDir(maxFiles + 1)
		if result.err == io.EOF {
			result.err = nil
		}
	default:
		result.err = os.ErrPermission
	}
	return
}

// requestOplock is FSCTL_REQUEST_OPLOCK, with its input and output as
// winioctl.h lays them out.
const (
	requestOplock         = 0x00090240
	oplockCacheRead       = 0x1
	oplockCacheHandle     = 0x2
	oplockInputRequest    = 0x1
	oplockStructureLength = 12
	// FILE_OPEN_REQUIRING_OPLOCK: the open and the request for the lock
	// count as one step, so no writer meets the handle before the lock is
	// on it.
	openRequiringOplock = 0x00010000
)

type oplockInput struct {
	StructureVersion     uint16
	StructureLength      uint16
	RequestedOplockLevel uint32
	Flags                uint32
}

// oplockHold is what the kernel writes to when the request ends, so it must
// stay where it is until then.
type oplockHold struct {
	input      oplockInput
	output     [32]byte
	overlapped windows.Overlapped
}

// stuck keeps the memory of a request that did not end in time.
var stuck sync.Map

// giveWay makes the read give way to a writer. While a file is open, a
// rename over it fails unless it asks for POSIX semantics, whatever the
// open shares; that is how Codex persists its config. So before the file is
// opened for the read, a second handle takes an opportunistic lock on it:
// the kernel then holds a writer's rename or delete back until that handle
// is closed, instead of failing it. The returned function closes it, and is
// called after the file is closed, so the writer finds no handle left. This
// is a courtesy to writers and guards nothing: where the lock is not granted
// (another file system, a file already locked), the read goes on without it.
func giveWay(parent windows.Handle, name string) func() {
	none := func() {}
	object, err := windows.NewNTUnicodeString(name)
	if err != nil || name == "" || strings.ContainsAny(name, `\/:`) {
		return none
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: object, Attributes: windows.OBJ_CASE_INSENSITIVE}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	// No synchronous flag: the request for the lock stays pending on the
	// handle, which only an asynchronous handle allows.
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&handle, windows.FILE_READ_ATTRIBUTES, &attributes, &status, nil, 0, shareAll, windows.FILE_OPEN, windows.FILE_OPEN_REPARSE_POINT|windows.FILE_NON_DIRECTORY_FILE|openRequiringOplock, 0, 0); err != nil {
		return none
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(handle)
		return none
	}
	hold := &oplockHold{input: oplockInput{StructureVersion: 1, StructureLength: oplockStructureLength, RequestedOplockLevel: oplockCacheRead | oplockCacheHandle, Flags: oplockInputRequest}}
	hold.overlapped.HEvent = event
	err = windows.DeviceIoControl(handle, requestOplock, (*byte)(unsafe.Pointer(&hold.input)), oplockStructureLength, &hold.output[0], uint32(len(hold.output)), nil, &hold.overlapped)
	pending := err == windows.ERROR_IO_PENDING
	return func() {
		windows.CloseHandle(handle)
		if pending {
			// Closing the handle ends the request; the kernel is done with
			// the memory once the event is set.
			if wait, _ := windows.WaitForSingleObject(event, 5000); wait != windows.WAIT_OBJECT_0 {
				stuck.Store(hold, event)
				return
			}
		}
		windows.CloseHandle(event)
		runtime.KeepAlive(hold)
	}
}

// openBelow opens one name inside the folder parent holds, and the thing
// itself where the name is a reparse point. A name that could mean anything
// but an entry of that folder is refused: a separator, a step up, or a colon,
// which names a stream of a file.
func openBelow(parent windows.Handle, name string, folder, read bool) (windows.Handle, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return 0, os.ErrPermission
	}
	object, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, os.ErrPermission
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: object, Attributes: windows.OBJ_CASE_INSENSITIVE}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	// On the way: the attributes, and for a folder the right to go on below
	// it. At the end, when its content is wanted: the right to read it.
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	switch {
	case read:
		access = windows.FILE_GENERIC_READ
	case folder:
		access |= windows.FILE_TRAVERSE
	}
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if folder {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&handle, access, &attributes, &status, nil, 0, shareAll, windows.FILE_OPEN, options, 0, 0); err != nil {
		// As the error a path open gives, so that a missing file reads as one.
		if code, ok := err.(windows.NTStatus); ok {
			return 0, code.Errno()
		}
		return 0, err
	}
	return handle, nil
}

// checkHandle refuses what the walk does not go through or read, by what the
// open handle itself says: any reparse point (a junction, a symlink, a mount
// point, a cloud file), a cloud placeholder, a file where a folder is needed,
// and a file over the size limit.
func checkHandle(handle windows.Handle, folder, tail bool) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, os.ErrPermission
	}
	isFolder := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, folder != isFolder:
		return info, os.ErrPermission
	case info.FileAttributes&placeholderAttributes != 0:
		return info, errDataless
	case !tail && !isFolder && (info.FileSizeHigh != 0 || int64(info.FileSizeLow) > maxFileBytes):
		return info, errTooLarge
	}
	return info, nil
}
