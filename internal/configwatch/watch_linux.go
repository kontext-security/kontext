//go:build linux

package configwatch

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// inotify watches each target by a watch descriptor on one shared queue.
type inotify struct{ fd int }

const inotifyChanges = unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF

// inotifyEntries are the folder events that change which files it holds.
const inotifyEntries = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO

func newBackend() (backend, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	return &inotify{fd: fd}, nil
}

func (i *inotify) add(path string) (int, error) {
	// The final component is never followed: a link is refused before here,
	// and one swapped in since stays unwatched.
	return unix.InotifyAddWatch(i.fd, path, inotifyChanges|unix.IN_DONT_FOLLOW)
}

func (i *inotify) remove(handle int) { _, _ = unix.InotifyRmWatch(i.fd, uint32(handle)) }

func (i *inotify) wait(timeout time.Duration) ([]event, error) {
	fds := []unix.PollFd{{Fd: int32(i.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, int(timeout.Milliseconds()))
	if errors.Is(err, unix.EINTR) || n == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.PathMax))
	size, err := unix.Read(i.fd, buf)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var events []event
	for offset := 0; offset+unix.SizeofInotifyEvent <= size; {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		offset += unix.SizeofInotifyEvent + int(raw.Len)
		if raw.Len > 0 && raw.Mask&inotifyEntries == 0 {
			// A child of a watched folder changed content, such as a log
			// appended next to settings.json. A watched file reports its
			// own writes, so only entries added, removed or renamed count,
			// as kqueue reports for a folder.
			continue
		}
		gone := raw.Mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0
		if raw.Mask&unix.IN_Q_OVERFLOW != 0 {
			// Lost events: report a change so the scan reads everything.
			events = append(events, event{handle: overflow})
		} else {
			events = append(events, event{handle: int(raw.Wd), gone: gone})
		}
	}
	return events, nil
}

func (i *inotify) close() error { return unix.Close(i.fd) }
