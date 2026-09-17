//go:build darwin

package managedobserve

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"golang.org/x/sys/unix"
)

// setiopolicy_np's iopolicysys ABI from Darwin sys/resource_private.h.
// x/sys/unix exposes the syscall, but no setiopolicy_np wrapper.
func setScanIOPolicy(kind, scope, policy int32) error {
	param := struct{ scope, kind, policy int32 }{scope, kind, policy}
	_, _, errno := unix.Syscall(unix.SYS_IOPOLICYSYS, 2, uintptr(unsafe.Pointer(&param)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func authorityIOPolicy(log diagnostic.Logger) func() func() {
	// IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, PROCESS, OFF. TN3150.
	if err := setScanIOPolicy(3, 0, 1); err != nil {
		logAlways(log, "authority scan: cannot disable dataless materialization: %v\n", err)
	}
	var warned sync.Once
	return func() func() {
		runtime.LockOSThread()
		// Apply to the scan and its filesystem workers: thread policy is not inherited
		// when Go schedules a goroutine on a different OS thread.
		if err := setScanIOPolicy(0, 1, 3); err != nil {
			warned.Do(func() { logAlways(log, "authority scan: cannot lower disk priority: %v\n", err) })
		}
		return func() {
			if err := setScanIOPolicy(0, 1, 0); err != nil {
				warned.Do(func() { logAlways(log, "authority scan: cannot reset disk priority: %v\n", err) })
			}
			runtime.UnlockOSThread()
		}
	}
}
