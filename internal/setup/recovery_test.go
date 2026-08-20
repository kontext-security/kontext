package setup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/profile"
)

// Regression tests for three failure paths raised in review. Each is a partial
// failure that leaves the machine in a worse state than not having tried, and
// none of them is reachable through the happy path.

// A migration that fails partway must leave the machine exactly as it was.
// Otherwise state is split across both layouts, the daemon cannot find its
// config, and every retry is refused because profiles/default now exists.
func TestMigrateRollsBackWhenAMoveFails(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_legacy", pingServer(t, "kt_legacy"))); err != nil {
		t.Fatal(err)
	}
	root := kontextRoot(h.home)
	observeDir := filepath.Join(root, profile.ManagedObserveDir)
	if err := os.MkdirAll(observeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(observeDir, "guard.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Fail the SECOND move, so the first has already happened and must be undone.
	moves := 0
	overrideVar(t, &renameFn, func(from, to string) error {
		moves++
		if moves == 2 {
			return errors.New("simulated disk failure")
		}
		return os.Rename(from, to)
	})

	_, err := MigrateLegacyInstall(context.Background(), nil)
	if err == nil {
		t.Fatal("MigrateLegacyInstall() = nil error, want the move failure surfaced")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("error does not mention rollback: %v", err)
	}

	// Everything is back where it started.
	for _, name := range []string{profile.ManagedConfigFile, profile.InstallationFile, profile.ManagedObserveDir} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); statErr != nil {
			t.Errorf("%s was not restored to the legacy root: %v", name, statErr)
		}
	}
	// And no active pointer was left behind.
	if _, activeErr := profile.ActiveName(); !errors.Is(activeErr, profile.ErrNoActive) {
		t.Errorf("ActiveName() = %v, want ErrNoActive after rollback", activeErr)
	}
	// The install is still usable: the config loads from where it always was.
	if _, loadErr := managedconfigLoadLegacy(); loadErr != nil {
		t.Errorf("legacy config is not loadable after rollback: %v", loadErr)
	}
}

// A rolled-back migration must be retryable without manual repair — the previous
// behavior refused forever because profiles/default already existed.
func TestMigrateIsRetryableAfterRollback(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_legacy", pingServer(t, "kt_legacy"))); err != nil {
		t.Fatal(err)
	}
	failNext := true
	restore := renameFn
	renameFn = func(from, to string) error {
		if failNext {
			failNext = false
			return errors.New("simulated disk failure")
		}
		return os.Rename(from, to)
	}
	t.Cleanup(func() { renameFn = restore })

	if _, err := MigrateLegacyInstall(context.Background(), nil); err == nil {
		t.Fatal("expected the first attempt to fail")
	}
	// No manual repair: the rollback already left the machine retryable.
	migrated, err := MigrateLegacyInstall(context.Background(), nil)
	if err != nil {
		t.Fatalf("retry after rollback failed: %v", err)
	}
	if !migrated {
		t.Fatal("retry after rollback reported nothing to migrate")
	}
	if name, _ := profile.ActiveName(); name != profile.DefaultName {
		t.Errorf("ActiveName() = %q, want %q", name, profile.DefaultName)
	}
}

// `profile use <already active>` must be a repair path. A switch whose agent
// start failed leaves the pointer moved and the daemon stopped, and re-running
// the same command is exactly what happens next — a bare "already active" would
// report success over a stopped daemon.
func TestUseActiveProfileRestartsAStoppedAgent(t *testing.T) {
	h := switchHarness(t)
	// No live daemon for this profile — a failed start, or a foreign process on
	// the shared socket.
	overrideVar(t, &daemonLive, func(string, string) bool { return false })
	callsBefore := len(h.calls)
	var out, errOut bytes.Buffer

	if err := Activate(context.Background(), "prod", &out, &errOut); err != nil {
		t.Fatalf("Activate() on the active profile error = %v", err)
	}

	var order []string
	for _, call := range h.calls[callsBefore:] {
		if call.name == "launchctl" && len(call.args) > 0 {
			if call.args[0] == "bootout" || call.args[0] == "bootstrap" {
				order = append(order, call.args[0])
			}
		}
	}
	if len(order) < 2 || order[0] != "bootout" || order[len(order)-1] != "bootstrap" {
		t.Fatalf("launchctl order = %v, want the agent restarted", order)
	}
	if !strings.Contains(out.String(), "not running") {
		t.Errorf("output did not explain the restart:\n%s", out.String())
	}
}

// When the daemon IS running, the same command must stay a cheap no-op rather
// than bouncing a healthy agent.
func TestUseActiveProfileLeavesAHealthyAgentAlone(t *testing.T) {
	h := switchHarness(t)
	overrideVar(t, &daemonLive, func(string, string) bool { return true })
	callsBefore := len(h.calls)
	var out, errOut bytes.Buffer

	if err := Activate(context.Background(), "prod", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	for _, call := range h.calls[callsBefore:] {
		if call.name == "launchctl" {
			t.Errorf("a healthy agent was restarted: %v", call.args)
		}
	}
	if !strings.Contains(out.String(), "already active") {
		t.Errorf("output = %q, want an already-active notice", out.String())
	}
}

// Uninstall must clear the token each profile's config actually NAMES. A renamed
// profile references an item whose name does not match its directory, so
// deriving from the name alone leaves the real token behind while reporting that
// every token was removed.
func TestUninstallRemovesTheTokenOfARenamedProfile(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_stg")
	opts := h.options("kt_stg", server)
	opts.Profile = "staging"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	// Created as "staging", so its token lives under ...token.staging.
	originalItem := "kontext-install-token.staging"
	if _, ok := h.keychain[originalItem]; !ok {
		t.Fatalf("expected %s in the keychain", originalItem)
	}

	var out bytes.Buffer
	if err := RenameProfile(context.Background(), "staging", "stg", &out); err != nil {
		t.Fatal(err)
	}
	// The rename does not touch the keychain, so the ref still names the old item
	// while the directory is now "stg" — the exact mismatch under test.

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v\n%s", err, h.out.String())
	}
	if _, ok := h.keychain[originalItem]; ok {
		t.Errorf("%s survived uninstall despite the summary claiming every token was removed", originalItem)
	}
}

// managedconfigLoadLegacy reads the pre-profile config directly, asserting an
// install is intact without going through profile resolution.
func managedconfigLoadLegacy() ([]byte, error) {
	return os.ReadFile(profile.LegacyPath(profile.ManagedConfigFile))
}

// A reachable socket is not proof that OUR agent is running. This is the state a
// leftover enterprise daemon produces: it binds the same socket path, so
// reachability says "healthy" while no self-serve agent is installed at all.
// Reported as an actionable error rather than a false success.
func TestUseActiveProfileRefusesWhenNoAgentIsInstalled(t *testing.T) {
	h := switchHarness(t)
	// A daemon answers, but the plist — the only evidence a self-serve agent
	// exists — is gone.
	overrideVar(t, &daemonLive, func(string, string) bool { return true })
	plist := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer

	err := Activate(context.Background(), "prod", &out, &errOut)
	if err == nil {
		t.Fatal("Activate() = nil, want a refusal naming the missing agent")
	}
	if !strings.Contains(err.Error(), "no background agent is installed") {
		t.Fatalf("error = %v, want it to name the missing agent", err)
	}
	if !strings.Contains(err.Error(), "kontext setup") {
		t.Errorf("error = %v, want it to name the fix", err)
	}
	if strings.Contains(out.String(), "is running") {
		t.Errorf("reported a running agent with no plist:\n%s", out.String())
	}
}

// The Claude drop-in write needs root, so it costs an administrator password.
// Re-running setup does not change its content — it names the binary and the
// hook events, neither of which varies per profile — so an identical rewrite
// must not ask for one.
func TestSetupSkipsThePrivilegedWriteWhenSettingsAreUnchanged(t *testing.T) {
	h := profileHarness(t)
	first := pingServer(t, "kt_1")
	opts := h.options("kt_1", first)
	opts.Profile = "one"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	if _, err := os.Lstat(managedSettingsPath); err != nil {
		t.Fatalf("expected the drop-in to exist after the first run: %v", err)
	}
	// Assert on whether the FILE was written, not on whether sudo ran: the test
	// harness fakes root, so the privileged path writes directly and a sudo check
	// would pass vacuously.
	marker := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(managedSettingsPath, marker, marker); err != nil {
		t.Fatal(err)
	}

	// A second profile: same binary, same hooks, so the drop-in content is
	// identical and nothing should be written.
	second := pingServer(t, "kt_2")
	opts2 := h.options("kt_2", second)
	opts2.Profile = "two"
	if err := Run(context.Background(), opts2); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}

	info, err := os.Stat(managedSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(marker) {
		t.Error("identical settings were rewritten; that costs an administrator password for nothing")
	}
	data, err := os.ReadFile(managedSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("drop-in is empty after the skipped write")
	}
}

// Changed content must still be written, or an upgrade that moves the binary
// would leave hooks pointing at the old path.
func TestSetupWritesWhenSettingsContentChanges(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_1", pingServer(t, "kt_1"))); err != nil {
		t.Fatal(err)
	}
	// A drop-in that is recognizably OURS but names a different binary — what an
	// upgrade or a path change produces. A foreign file is refused by the
	// ownership preflight instead, which is a different (pre-existing) behavior.
	stale, err := claudemanaged.TemplateJSON("/usr/local/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedSettingsPath, stale, 0o644); err != nil {
		t.Fatal(err)
	}
	marker := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(managedSettingsPath, marker, marker); err != nil {
		t.Fatal(err)
	}

	if err := Run(context.Background(), h.options("kt_2", pingServer(t, "kt_2"))); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(managedSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "/usr/local/bin/kontext") {
		t.Error("drop-in still names the old binary; the changed content was not written")
	}
	info, err := os.Stat(managedSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Equal(marker) {
		t.Error("changed settings were not written")
	}
}

// A command-line argument is visible in `ps` to every process on the machine, so
// a caller that is not a human at a terminal needs another way in.
func TestTokenIsReadFromStdinWhenRequested(t *testing.T) {
	h := profileHarness(t)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := write.WriteString("  kt_piped_token\n"); err != nil {
		t.Fatal(err)
	}
	write.Close()
	original := os.Stdin
	os.Stdin = read
	t.Cleanup(func() { os.Stdin = original; read.Close() })

	opts := h.options("", pingServer(t, "kt_piped_token"))
	opts.Profile = "piped"
	opts.TokenFromStdin = true

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() error = %v\n%s", err, h.errOut.String())
	}
	// Surrounding whitespace from a pipe or heredoc is trimmed; the token itself
	// reaches the keychain intact.
	if got := h.keychain["kontext-install-token.piped"]; got != "kt_piped_token" {
		t.Errorf("stored token = %q, want the piped value", got)
	}
}

func TestEmptyStdinTokenIsRejected(t *testing.T) {
	h := profileHarness(t)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	write.Close()
	original := os.Stdin
	os.Stdin = read
	t.Cleanup(func() { os.Stdin = original; read.Close() })

	opts := h.options("", pingServer(t, "unused"))
	opts.Profile = "piped"
	opts.TokenFromStdin = true

	err = Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "no install token on stdin") {
		t.Fatalf("Run() error = %v, want an empty-stdin refusal", err)
	}
}

// Two profiles for one workspace on one backend would hold that workspace's
// records in two ledgers and present it two device identities. The check can
// only live here: the workspace is unknown until the hosted API answers.
func TestSetupRefusesADuplicateWorkspaceOnTheSameBackend(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_same")
	first := h.options("kt_same", server)
	first.Profile = "work"
	if err := Run(context.Background(), first); err != nil {
		t.Fatalf("first Run() error = %v", err)
	}

	// Same backend, same token, therefore the same workspace — under a new name.
	second := h.options("kt_same", server)
	second.Profile = "work-again"
	err := Run(context.Background(), second)
	if err == nil {
		t.Fatal("Run() = nil, want a duplicate-workspace refusal")
	}
	if !strings.Contains(err.Error(), "already set up as profile \"work\"") {
		t.Fatalf("error = %v, want it to name the existing profile", err)
	}
	// Refused before anything was written.
	if exists, _ := profile.Exists("work-again"); exists {
		if _, statErr := os.Lstat(filepath.Join(kontextRoot(h.home), "profiles", "work-again", "managed.json")); statErr == nil {
			t.Error("a refused setup left a config behind")
		}
	}
}

// Rotating an existing profile's token must not read as a duplicate of itself.
func TestSetupRerunForTheSameProfileIsNotADuplicate(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_same")
	opts := h.options("kt_same", server)
	opts.Profile = "work"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("re-running setup for the same profile was refused: %v", err)
	}
}

// Plain `kontext setup` — no profile name — rewrites the ACTIVE profile, which
// is how a token is rotated on a machine that already has profiles. So the
// duplicate check has to exclude the active profile, not only an explicitly
// named one: excluding just opts.Profile made the re-run find the very profile
// it was about to write and refuse itself, breaking the documented promise that
// re-running setup is safe.
func TestSetupRerunWithoutAProfileNameRotatesTheActiveProfile(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_same")
	first := h.options("kt_same", server)
	first.Profile = "work"
	if err := Run(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("work"); err != nil {
		t.Fatal(err)
	}

	// Profile deliberately unset: resolveTarget falls back to the active one.
	rerun := h.options("kt_same", server)
	if err := Run(context.Background(), rerun); err != nil {
		t.Fatalf("plain `kontext setup` against the active profile was refused: %v", err)
	}
	names, err := profile.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "work" {
		t.Errorf("profiles = %v, want the re-run to rewrite \"work\" rather than add another", names)
	}
}

// The profile excluded from duplicate detection and the profile written to must
// be the SAME one. When the active pointer was read twice — once to exclude,
// once to write — a `kontext profile use` landing between the two reads sent
// the write to a profile the guard had never cleared. The menu bar app switches
// profiles on one click, so the window is reachable.
//
// The seam fires at exactly that instant.
func TestSetupWritesToTheProfileItCleared(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_same")
	first := h.options("kt_same", server)
	first.Profile = "work"
	if err := Run(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	other := h.options("kt_other", multiWorkspacePingServer(t, map[string]string{"kt_other": "org_other"}))
	other.Profile = "other"
	if err := Run(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("work"); err != nil {
		t.Fatal(err)
	}

	// Switch the active profile the moment the guard runs.
	overrideVar(t, &boundProfileLookup, func(orgID, cloudURL, exclude string) (string, error) {
		if err := profile.SetActive("other"); err != nil {
			t.Fatal(err)
		}
		return profileBoundToWorkspace(orgID, cloudURL, exclude)
	})

	rerun := h.options("kt_same", server)
	var wrote string
	rerun.OnProfileResolved = func(name string) { wrote = name }
	err := Run(context.Background(), rerun)

	// The invariant is that the write never lands on a profile the guard did not
	// clear. Refusing satisfies it more strongly than writing to "work" would,
	// and refusing is what the target snapshot now does — but "other" must never
	// be the target either way.
	if wrote == "other" {
		t.Errorf("setup targeted %q, which the guard never cleared", wrote)
	}
	if err == nil {
		t.Fatal("Run() = nil, want a refusal after the active pointer moved")
	}
	if !strings.Contains(err.Error(), "while setup was running") {
		t.Fatalf("error = %v, want it to name the concurrent change", err)
	}
}

// Resolving the target once is not enough on its own: `profile rename` moves
// the directory the resolved paths name, so writing afterwards would recreate a
// profile under the name the user just renamed away. Refuse instead.
func TestSetupRefusesWhenTheTargetIsRenamedMidRun(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_same")
	first := h.options("kt_same", server)
	first.Profile = "work"
	if err := Run(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("work"); err != nil {
		t.Fatal(err)
	}

	// Rename the target the moment the guard runs — after resolution, before the
	// first write.
	overrideVar(t, &boundProfileLookup, func(orgID, cloudURL, exclude string) (string, error) {
		// Renaming AFTER the real lookup, so the guard sees the world as it was
		// and the run proceeds to the write it must now refuse.
		duplicate, err := profileBoundToWorkspace(orgID, cloudURL, exclude)
		if err != nil {
			return "", err
		}
		if renameErr := RenameProfile(context.Background(), "work", "renamed", io.Discard); renameErr != nil {
			t.Fatal(renameErr)
		}
		return duplicate, nil
	})

	err := Run(context.Background(), h.options("kt_same", server))
	if err == nil {
		t.Fatal("Run() = nil, want a refusal after the target moved")
	}
	if !strings.Contains(err.Error(), "while setup was running") {
		t.Fatalf("error = %v, want it to name the concurrent change", err)
	}
	// The refusal must be clean: no profile resurrected under the old name.
	if exists, _ := profile.Exists("work"); exists {
		t.Error("a refused setup recreated the renamed-away profile")
	}
}

// `profile rm` refuses the ACTIVE profile, but an explicitly named target need
// not be active — so removal mid-run is reachable there.
func TestSetupRefusesWhenTheTargetIsRemovedMidRun(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_same")
	first := h.options("kt_same", server)
	first.Profile = "work"
	if err := Run(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	other := h.options("kt_other", multiWorkspacePingServer(t, map[string]string{"kt_other": "org_other"}))
	other.Profile = "other"
	if err := Run(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("other"); err != nil {
		t.Fatal(err)
	}

	overrideVar(t, &boundProfileLookup, func(orgID, cloudURL, exclude string) (string, error) {
		if err := profile.Remove("work"); err != nil {
			t.Fatal(err)
		}
		return profileBoundToWorkspace(orgID, cloudURL, exclude)
	})

	rerun := h.options("kt_same", server)
	rerun.Profile = "work"
	err := Run(context.Background(), rerun)
	if err == nil {
		t.Fatal("Run() = nil, want a refusal after the target was removed")
	}
	if !strings.Contains(err.Error(), "while setup was running") {
		t.Fatalf("error = %v, want it to name the concurrent change", err)
	}
}

// The fix must not blunt the guard: a run that DERIVES its name is creating a
// new profile, so every existing profile stays a candidate duplicate — even
// though this run has an active profile that a plain setup would have excluded.
func TestSetupStillRefusesADuplicateWhenTheNameIsDerived(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_same")
	first := h.options("kt_same", server)
	first.Profile = "work"
	if err := Run(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("work"); err != nil {
		t.Fatal(err)
	}

	added := h.options("kt_same", server)
	added.DeriveProfileName = true
	err := Run(context.Background(), added)
	if err == nil {
		t.Fatal("Run() = nil, want a duplicate-workspace refusal")
	}
	if !strings.Contains(err.Error(), "already set up as profile \"work\"") {
		t.Fatalf("error = %v, want it to name the existing profile", err)
	}
}

// Several workspaces on ONE backend is exactly what workspaces are for — the
// rule is per workspace, not per environment.
func TestSetupAllowsASecondWorkspaceOnTheSameBackend(t *testing.T) {
	h := profileHarness(t)
	backend := multiWorkspacePingServer(t, map[string]string{
		"kt_a": "org_a",
		"kt_b": "org_b",
	})

	a := h.options("kt_a", backend)
	a.Profile = "team-a"
	if err := Run(context.Background(), a); err != nil {
		t.Fatalf("first workspace error = %v", err)
	}
	b := h.options("kt_b", backend)
	b.Profile = "team-b"
	if err := Run(context.Background(), b); err != nil {
		t.Fatalf("a second workspace on the same backend was refused: %v", err)
	}
	for _, name := range []string{"team-a", "team-b"} {
		if exists, _ := profile.Exists(name); !exists {
			t.Errorf("profile %q was not created", name)
		}
	}
}

// A plain setup holding a token for a workspace that already has a profile
// switches to that profile — rotating its token on the way — rather than
// refusing. The refusal only made sense for a NAMED run, where the name given
// and the profile found disagree; here the token names the intent completely.
func TestPlainSetupSwitchesToTheProfileBoundToTheTokensWorkspace(t *testing.T) {
	h := profileHarness(t)
	backend := multiWorkspacePingServer(t, map[string]string{
		"kt_work":   "org_work",
		"kt_work_2": "org_work", // a fresh token for the same workspace
		"kt_other":  "org_other",
	})
	work := h.options("kt_work", backend)
	work.Profile = "work"
	if err := Run(context.Background(), work); err != nil {
		t.Fatal(err)
	}
	other := h.options("kt_other", backend)
	other.Profile = "other"
	if err := Run(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("other"); err != nil {
		t.Fatal(err)
	}

	if err := Run(context.Background(), h.options("kt_work_2", backend)); err != nil {
		t.Fatalf("plain setup with an already-bound workspace's token was refused: %v", err)
	}
	if got := h.keychain["kontext-install-token.work"]; got != "kt_work_2" {
		t.Errorf("work's stored token = %q, want the fresh token", got)
	}
	if active, err := profile.ActiveName(); err != nil || active != "work" {
		t.Errorf("active profile = %q (err %v), want the switch to \"work\"", active, err)
	}
	// The profile that WAS active kept its own binding and token.
	if got := h.keychain["kontext-install-token.other"]; got != "kt_other" {
		t.Errorf("other's stored token = %q, want it untouched", got)
	}
	if names, _ := profile.List(); len(names) != 2 {
		t.Errorf("profiles = %v, want no third profile", names)
	}
}

// A plain setup holding a token for a workspace nothing is bound to must not
// write it over the active profile — that would silently destroy a working
// workspace's binding and its keychain token. It becomes an addition instead,
// exactly as if `kontext profile add` had been typed, and switches to it.
func TestPlainSetupAddsAProfileForANewWorkspace(t *testing.T) {
	h := profileHarness(t)
	backend := multiWorkspacePingServer(t, map[string]string{
		"kt_work": "org_work",
		"kt_new":  "org_new",
	})
	work := h.options("kt_work", backend)
	work.Profile = "work"
	if err := Run(context.Background(), work); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("work"); err != nil {
		t.Fatal(err)
	}

	if err := Run(context.Background(), h.options("kt_new", backend)); err != nil {
		t.Fatalf("plain setup with a new workspace's token failed: %v", err)
	}
	// The previously active profile kept its token and its binding.
	if got := h.keychain["kontext-install-token.work"]; got != "kt_work" {
		t.Errorf("work's stored token = %q, want it untouched", got)
	}
	workspace, err := readWorkspace("work")
	if err != nil {
		t.Fatal(err)
	}
	if workspace.OrganizationID != "org_work" {
		t.Errorf("work's workspace = %q, want its binding untouched", workspace.OrganizationID)
	}
	// The new workspace landed in a new profile, now active.
	active, err := profile.ActiveName()
	if err != nil {
		t.Fatal(err)
	}
	if active == "work" {
		t.Fatal("active profile is still \"work\"; want a switch to the added profile")
	}
	added, err := readWorkspace(active)
	if err != nil {
		t.Fatal(err)
	}
	if added.OrganizationID != "org_new" {
		t.Errorf("added profile's workspace = %q, want org_new", added.OrganizationID)
	}
}

// The same protection across backends: an active local-dev profile must
// survive a plain setup run with a production token, rather than being
// rewritten to point at production under its local name.
func TestPlainSetupLeavesTheActiveProfileWhenTheBackendDiffers(t *testing.T) {
	h := profileHarness(t)
	localBackend := pingServer(t, "kt_local")
	local := h.options("kt_local", localBackend)
	local.Profile = "localdev"
	if err := Run(context.Background(), local); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("localdev"); err != nil {
		t.Fatal(err)
	}

	otherBackend := multiWorkspacePingServer(t, map[string]string{"kt_prod": "org_prod"})
	if err := Run(context.Background(), h.options("kt_prod", otherBackend)); err != nil {
		t.Fatalf("plain setup against a different backend failed: %v", err)
	}
	configPath, err := profile.ManagedConfigPath("localdev")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := managedconfig.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Config.CloudURL != localBackend.URL {
		t.Errorf("localdev's backend = %q, want it still pointing at %q", loaded.Config.CloudURL, localBackend.URL)
	}
	if active, _ := profile.ActiveName(); active == "localdev" {
		t.Error("active profile is still \"localdev\"; want a switch to the added profile")
	}
}

// A machine that has never used profiles keeps its pre-profile behavior
// exactly: the legacy slot has no recorded binding to compare, so a plain
// re-run rewrites it in place — even for a different workspace — and no
// profile machinery appears.
func TestPlainSetupOnALegacyMachineStillRewritesInPlace(t *testing.T) {
	h := profileHarness(t)
	backend := multiWorkspacePingServer(t, map[string]string{
		"kt_a": "org_a",
		"kt_b": "org_b",
	})
	if err := Run(context.Background(), h.options("kt_a", backend)); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), h.options("kt_b", backend)); err != nil {
		t.Fatalf("legacy re-run with a different workspace's token was refused: %v", err)
	}
	if got := h.keychain[KeychainItemName]; got != "kt_b" {
		t.Errorf("legacy stored token = %q, want the in-place rewrite", got)
	}
	if names, _ := profile.List(); len(names) != 0 {
		t.Errorf("profiles = %v, want none on a legacy machine", names)
	}
}

// multiWorkspacePingServer maps each token to its own organization, so one
// backend can serve several workspaces.
func multiWorkspacePingServer(t *testing.T, tokenToOrg map[string]string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authorization-ledger/ping" {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		org, ok := tokenToOrg[token]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"organization_id":%q,"organization_name":%q}`, org, org)
	}))
	t.Cleanup(server.Close)
	return server
}

// A renamed profile keeps its token under its FORMER name. If its config then
// becomes unreadable, that name is unrecoverable — so uninstall must say a token
// may remain rather than reporting complete cleanup over an orphan nothing
// points at any more.
func TestUninstallWarnsWhenAProfileConfigIsUnreadable(t *testing.T) {
	h := profileHarness(t)
	opts := h.options("kt_stg", pingServer(t, "kt_stg"))
	opts.Profile = "staging"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RenameProfile(context.Background(), "staging", "stg", &out); err != nil {
		t.Fatal(err)
	}
	// Its token is at ...token.staging while the directory is now "stg".
	configPath, err := profile.ManagedConfigPath("stg")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{ corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	warning := h.errOut.String()
	if !strings.Contains(warning, "stg") || !strings.Contains(warning, "token references are unknown") {
		t.Errorf("uninstall did not warn about the unreadable profile:\n%s", warning)
	}
	if !strings.Contains(warning, "kontext-install-token") {
		t.Errorf("warning does not say what to look for:\n%s", warning)
	}
}

// A readable config must NOT produce the warning — it would train people to
// ignore it.
func TestUninstallIsQuietWhenEveryConfigIsReadable(t *testing.T) {
	h := profileHarness(t)
	opts := h.options("kt_stg", pingServer(t, "kt_stg"))
	opts.Profile = "staging"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.errOut.String(), "token references are unknown") {
		t.Errorf("warned about a readable config:\n%s", h.errOut.String())
	}
}

// The socket path is shared across installations, so a foreign daemon — an
// enterprise leftover, or one started by hand — answers it. Treating that as our
// agent reports a healthy install while the intended one stays stopped.
//
// This is not hypothetical: an orphaned enterprise daemon held this socket on a
// real machine, with its own config already deleted.
func TestUseActiveProfileRestartsWhenAForeignDaemonHoldsTheSocket(t *testing.T) {
	h := switchHarness(t)
	// The socket answers (dialSocket succeeds) but no daemon is serving THIS
	// profile's database, which is what daemonLive distinguishes.
	overrideVar(t, &dialSocket, func(string, time.Duration) error { return nil })
	overrideVar(t, &daemonLive, func(string, string) bool { return false })
	callsBefore := len(h.calls)
	var out, errOut bytes.Buffer

	if err := Activate(context.Background(), "prod", &out, &errOut); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	var restarted bool
	for _, call := range h.calls[callsBefore:] {
		if call.name == "launchctl" && len(call.args) > 0 && call.args[0] == "bootstrap" {
			restarted = true
		}
	}
	if !restarted {
		t.Error("a foreign listener was mistaken for our agent; nothing was restarted")
	}
	if strings.Contains(out.String(), "is running") {
		t.Errorf("reported a running agent over a foreign daemon:\n%s", out.String())
	}
}
