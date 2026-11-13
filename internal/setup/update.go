package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/autostart"
	"github.com/kontext-security/kontext/internal/credstore"
	"github.com/kontext-security/kontext/internal/instancelock"
	"github.com/kontext-security/kontext/internal/managedobserve"
)

// UpdateOptions configures Update.
type UpdateOptions struct {
	// Version is this program's version, which the new background agent has to
	// report before the update counts as done.
	Version string
	Stdout  io.Writer
}

// Seams for Update.
var (
	renameFile       = os.Rename
	stopOldAgents    = stopProgramProcesses
	probeNewDaemon   = probeDaemon
	loadDaemonStatus = func() *managedobserve.DaemonStatus {
		return managedobserve.LoadDaemonStatus(managedobserve.DefaultDBPath())
	}
	updateStatusEvery = 250 * time.Millisecond
)

// updateLockName is the lock an update holds in the install folder.
const updateLockName = "kontext-update.lock"

// updatePrograms are the files an update replaces, the background agent
// first: it is the one that is running.
var updatePrograms = []string{windowsDaemonName, "kontext.exe"}

// Update puts this program, and the background agent beside it, in place of
// the user's own install on Windows. It runs from the folder of a newer
// release, not from the installed one, so a release can be installed by its
// own code whatever the installed version knows.
//
// Windows does not replace a program that is running, but lets it be renamed.
// So the background agent is stopped, each installed program is renamed to
// <name>.old, the new one is put in its place, and the agent is started again.
// The update counts as done only when an agent with a new process id reports
// this program's version: a hook may start the old agent again in between,
// and a second agent gives way to the first. If putting the programs in place
// fails, the old ones are put back and the old agent is started again.
//
// The install key, the config, the hooks and the sign-in entry name the same
// paths before and after, so they are left as they are. The .old copies are
// removed by the next update; one that still runs cannot be deleted.
func Update(ctx context.Context, opts UpdateOptions) error {
	out := opts.Stdout
	if out == nil {
		out = io.Discard
	}
	if goos != "windows" {
		return errors.New("`kontext update` updates the install from a Windows release zip; on macOS and Linux, update kontext with the package manager you installed it with (on macOS: brew upgrade kontext)")
	}
	if _, err := os.Lstat(systemConfigPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("this machine is managed by your organization (%s): its installer updates Kontext", systemConfigPath)
	}
	entry, err := readWindowsAutostart()
	if err != nil {
		return fmt.Errorf("read the sign-in entry of your install: %w", err)
	}
	installedDaemon := autostart.Program(entry)
	if installedDaemon == "" {
		return errors.New("there is no install of yours to update (no sign-in entry): set Kontext up with `kontext setup` first")
	}
	installDir := filepath.Dir(installedDaemon)
	self, err := executablePath()
	if err != nil {
		return fmt.Errorf("find this program: %w", err)
	}
	sourceDir := filepath.Dir(self)
	if samePath(sourceDir, installDir) {
		return fmt.Errorf("this is the installed program (%s). Unzip the newer release to a folder of its own and run its `kontext.exe update` from there", installDir)
	}
	for _, name := range updatePrograms {
		if info, err := os.Stat(filepath.Join(sourceDir, name)); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s is missing beside this program in %s: unzip the whole release and run update from there", name, sourceDir)
		}
		if info, err := os.Stat(filepath.Join(installDir, name)); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s is missing in %s, the folder your sign-in entry names: run `kontext setup` from this release's folder to install it there instead", name, installDir)
		}
	}

	// The agent started below reads the install key from the credential store,
	// which a session without one (SSH with a key) cannot reach: stopping the
	// working agent there would leave the PC unobserved until the next sign-in.
	if _, err := readWindowsToken(WindowsCredentialName); errors.Is(err, credstore.ErrNoLogonSession) {
		return errors.New("this session has no Windows credential store, so the background agent could not read the install key after the update: run `kontext update` in a desktop session, not over SSH with a key")
	}

	// One update at a time: two would remove each other's staged and kept
	// copies. The operating system lets the lock go when this process ends.
	lock, err := instancelock.Acquire(filepath.Join(installDir, updateLockName), 0)
	if err != nil {
		var held *instancelock.HeldError
		if errors.As(err, &held) {
			return fmt.Errorf("another kontext update is running for %s; wait for it to finish", installDir)
		}
		return fmt.Errorf("lock %s for the update: %w", installDir, err)
	}
	defer lock.Release()

	fmt.Fprintln(out, "Kontext update")
	fmt.Fprintf(out, "  From: %s\n  Into: %s\n", sourceDir, installDir)
	before := loadDaemonStatus()
	oldPID, oldVersion := 0, "unknown"
	if before != nil {
		oldPID = before.PID
		if before.Version != "" {
			oldVersion = before.Version
		}
	}

	// Leftovers of an earlier update first: an .old copy that cannot be
	// removed is still running, and renaming onto it would fail half-way.
	for _, name := range updatePrograms {
		for _, leftover := range []string{name + ".old", name + ".new"} {
			path := filepath.Join(installDir, leftover)
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%s from an earlier update is still in use and cannot be removed (%v). Sign out and in again, then run update again", path, err)
			}
		}
	}
	// The new programs go into the install folder under a temporary name
	// first, so the swap below is two renames on one volume.
	for _, name := range updatePrograms {
		if err := copyProgram(filepath.Join(sourceDir, name), filepath.Join(installDir, name+".new")); err != nil {
			removeStaged(installDir)
			return fmt.Errorf("copy %s into %s: %w", name, installDir, err)
		}
	}

	daemon := filepath.Join(installDir, windowsDaemonName)
	stopped, err := stopWindowsDaemon(daemon)
	if err != nil {
		removeStaged(installDir)
		return fmt.Errorf("stop the background agent: %w", err)
	}
	if stopped {
		fmt.Fprintln(out, "  ✓ Background agent stopped")
	}

	var swapped []string
	putBack := func() {
		for i := len(swapped) - 1; i >= 0; i-- {
			path := filepath.Join(installDir, swapped[i])
			_ = renameFile(path, path+".new")
			_ = renameFile(path+".old", path)
		}
		removeStaged(installDir)
	}
	for _, name := range updatePrograms {
		path := filepath.Join(installDir, name)
		if err := renameFile(path, path+".old"); err != nil {
			putBack()
			return errors.Join(fmt.Errorf("move the installed %s aside: %w", name, err), restartOld(daemon, out))
		}
		if err := renameFile(path+".new", path); err != nil {
			_ = renameFile(path+".old", path)
			putBack()
			return errors.Join(fmt.Errorf("put the new %s in place: %w", name, err), restartOld(daemon, out))
		}
		swapped = append(swapped, name)
	}
	fmt.Fprintln(out, "  ✓ New programs in place")

	// A hook may have started the old agent again before it was renamed; it
	// now runs from the .old copy and would keep the new one from starting. It
	// may not have written its status yet, so it is found by its program.
	// A failure here is no reason to leave the PC without an agent: the check
	// below finds an old agent that still answers.
	if _, err := stopOldAgents(daemon + ".old"); err != nil {
		fmt.Fprintf(out, "  • Could not check for an older background agent started during the update (%v)\n", err)
	}
	if err := startWindowsDaemon(daemon, autostart.DaemonSubcommand); err != nil {
		return fmt.Errorf("the new programs are in place, but the background agent did not start: %w; it starts at your next sign-in, and `kontext doctor` shows its state", err)
	}
	if err := waitForNewDaemon(ctx, oldPID, opts.Version); err != nil {
		return fmt.Errorf("the new programs are in place, but %w; `kontext doctor` shows which agent runs", err)
	}
	// The status file stays when an agent exits, so the new one also has to
	// answer on its socket.
	if err := probeNewDaemon(ctx); err != nil {
		return fmt.Errorf("the new programs are in place and the new background agent started, but it does not answer: %w; `kontext doctor` shows its state", err)
	}
	fmt.Fprintf(out, "  ✓ Background agent runs %s (was %s)\n", opts.Version, oldVersion)
	fmt.Fprintln(out, "\nThe install key, config, hooks and sign-in entry are unchanged.")
	return nil
}

// waitForNewDaemon waits until the status file names an agent other than the
// one before the update, running version.
func waitForNewDaemon(ctx context.Context, oldPID int, version string) error {
	deadline := time.Now().Add(daemonStartWait)
	for {
		status := loadDaemonStatus()
		if status != nil && status.PID > 0 && status.PID != oldPID && status.Version == version {
			return nil
		}
		if time.Now().After(deadline) {
			if status == nil {
				return fmt.Errorf("no background agent reported within %s", daemonStartWait)
			}
			return fmt.Errorf("the background agent that reports is version %q (pid %d), not the new %q", status.Version, status.PID, version)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(updateStatusEvery):
		}
	}
}

// restartOld starts the old background agent again after a failed swap, so
// the install keeps working as it was.
func restartOld(daemon string, out io.Writer) error {
	if err := startWindowsDaemon(daemon, autostart.DaemonSubcommand); err != nil {
		return fmt.Errorf("start the old background agent again: %w; it starts at your next sign-in", err)
	}
	fmt.Fprintln(out, "  • The installed programs are unchanged and the background agent runs again")
	return nil
}

func removeStaged(dir string) {
	for _, name := range updatePrograms {
		_ = os.Remove(filepath.Join(dir, name+".new"))
	}
}

func copyProgram(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(to)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(to)
		return err
	}
	return out.Close()
}

// samePath compares two folders as Windows does: by their cleaned spelling,
// ignoring case.
func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
