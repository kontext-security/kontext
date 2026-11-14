//go:build windows

package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// stopProcess ends the process pid when it is the Kontext daemon, and waits
// for it to be gone. The pid comes from the daemon's status file, which can
// be stale, so the process is ended only if its program is named as the
// daemon's is (the CLI's own name does not count: a hook may have the pid);
// another program that got the same pid is left alone. A process that is not
// there any more is not an error.
//
// With program set, the process also has to run that very file. A user's own
// install and a machine-wide one write the same status file, so the pid may
// be the other install's daemon; program is the one this install starts.
//
// stopped says whether a process was ended by this call.
//
// The daemon has no console on Windows and takes no signal, so this is an
// abrupt end: records it had queued and not yet written are lost.
func stopProcess(pid int, program string) (stopped bool, err error) {
	if pid == os.Getpid() {
		return false, nil // a stale pid that this very process got
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// No such process, or one this user may not end: the user's own
		// daemon can always be opened, so that one is not it.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return false, nil
		}
		return false, fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)
	// A process that has ended can still be opened while anything holds a
	// handle on it, and naming its program then fails (seen on Windows 11 on
	// arm64 with error 31): it is not there to stop.
	if event, err := windows.WaitForSingleObject(handle, 0); err == nil && event == windows.WAIT_OBJECT_0 {
		return false, nil
	}

	path := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(path))
	if err := windows.QueryFullProcessImageName(handle, 0, &path[0], &size); err != nil {
		return false, fmt.Errorf("name the program of process %d: %w", pid, err)
	}
	image := windows.UTF16ToString(path[:size])
	if !isDaemonProgram(filepath.Base(image)) {
		return false, nil // the pid belongs to another program now
	}
	if program != "" && !sameFile(image, program) {
		return false, nil // a daemon, but not this install's
	}
	if err := windows.TerminateProcess(handle, 1); err != nil {
		// Access denied is also what a process that has just exited answers.
		if event, waitErr := windows.WaitForSingleObject(handle, 0); waitErr == nil && event == windows.WAIT_OBJECT_0 {
			return false, nil
		}
		return false, fmt.Errorf("end process %d: %w", pid, err)
	}
	event, err := windows.WaitForSingleObject(handle, uint32((10 * time.Second).Milliseconds()))
	if err != nil {
		return false, fmt.Errorf("wait for process %d: %w", pid, err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return false, fmt.Errorf("process %d did not end within 10 s", pid)
	}
	return true, nil
}

// isDaemonProgram also takes the daemon's program renamed by an update: a
// running program can be renamed on Windows, and its process then reports
// the new name.
func isDaemonProgram(name string) bool {
	return strings.EqualFold(name, windowsDaemonName) || strings.EqualFold(name, windowsDaemonName+".old")
}

// sameFile compares by the files' identity, not their spelling.
func sameFile(a, b string) bool {
	left, err := os.Stat(a)
	if err != nil {
		return false
	}
	right, err := os.Stat(b)
	return err == nil && os.SameFile(left, right)
}

// stopProgramProcesses ends every daemon process that runs program. It finds
// them by listing the processes, not through the status file, so it also
// finds a daemon that has not written its status yet. It reports how many it
// ended.
func stopProgramProcesses(program string) (int, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("list processes: %w", err)
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ended := 0
	var errs []error
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if !isDaemonProgram(windows.UTF16ToString(entry.ExeFile[:])) {
			continue
		}
		stopped, err := stopProcess(int(entry.ProcessID), program)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if stopped {
			ended++
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		errs = append(errs, fmt.Errorf("list processes: %w", err))
	}
	return ended, errors.Join(errs...)
}
