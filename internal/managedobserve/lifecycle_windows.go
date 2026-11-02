//go:build windows

package managedobserve

import (
	"errors"

	"golang.org/x/sys/windows"
)

// winsockConnectionLost matches the Winsock errnos a dropped connection fails
// with on Windows. syscall.ECONNRESET and the rest are Go's own numbers there,
// which no socket error equals. A daemon that closes before reading the RPC,
// or dies holding it even after reading it, resets the hook's write or read
// with WSAECONNRESET. A dial after it is refused with WSAECONNREFUSED, whether
// or not the socket file is left behind.
func winsockConnectionLost(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNREFUSED)
}
