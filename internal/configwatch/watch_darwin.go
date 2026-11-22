//go:build darwin

package configwatch

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// kqueue watches each target by an event-only descriptor, which never
// blocks an unmount and reads nothing.
type kqueue struct{ fd int }

const vnodeChanges = unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_ATTRIB | unix.NOTE_DELETE | unix.NOTE_RENAME | unix.NOTE_REVOKE | unix.NOTE_LINK

func newBackend() (backend, error) {
	fd, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	return &kqueue{fd: fd}, nil
}

func (k *kqueue) add(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_EVTONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	var change unix.Kevent_t
	unix.SetKevent(&change, fd, unix.EVFILT_VNODE, unix.EV_ADD|unix.EV_CLEAR|unix.EV_ENABLE)
	change.Fflags = vnodeChanges
	if _, err := unix.Kevent(k.fd, []unix.Kevent_t{change}, nil, nil); err != nil {
		_ = unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

// remove closes the descriptor, which drops its registration too.
func (k *kqueue) remove(handle int) { _ = unix.Close(handle) }

func (k *kqueue) wait(timeout time.Duration) ([]event, error) {
	buf := make([]unix.Kevent_t, 64)
	ts := unix.NsecToTimespec(timeout.Nanoseconds())
	n, err := unix.Kevent(k.fd, nil, buf, &ts)
	if errors.Is(err, unix.EINTR) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	events := make([]event, 0, n)
	for _, e := range buf[:n] {
		gone := e.Fflags&(unix.NOTE_DELETE|unix.NOTE_RENAME|unix.NOTE_REVOKE) != 0
		events = append(events, event{handle: int(e.Ident), gone: gone})
	}
	return events, nil
}

func (k *kqueue) close() error { return unix.Close(k.fd) }
