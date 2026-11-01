package codexroute

import (
	"bytes"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// codexSince counts the person's Codex processes, the ChatGPT app's
// included, that started before t: they may have read the config line. A
// release binary keeps its target in its name (codex-aarch64-apple-darwin).
func codexSince(t time.Time) (int, error) {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Getuid())
	if err != nil {
		return 0, err
	}
	count := 0
	for _, process := range processes {
		name := process.Proc.P_comm[:]
		if end := bytes.IndexByte(name, 0); end >= 0 {
			name = name[:end]
		}
		if bytes.HasPrefix(name, []byte("codex")) && startTime(&process).Before(t) {
			count++
		}
	}
	return count, nil
}

// processStarted reports when process pid started, or false when none runs.
func processStarted(pid int) (time.Time, bool) {
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(process.Proc.P_pid) != pid {
		return time.Time{}, false
	}
	return startTime(process), true
}

func startTime(process *unix.KinfoProc) time.Time {
	return time.Unix(process.Proc.P_starttime.Sec, int64(process.Proc.P_starttime.Usec)*int64(time.Microsecond))
}
