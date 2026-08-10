package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

// Workspace is the cached identity of the workspace a profile is bound to. It
// exists so a listing can name the workspace rather than a hostname; nothing
// reads it to make a decision.
type Workspace struct {
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name,omitempty"`
}

// Label renders the workspace the way setup prints it.
func (w Workspace) Label() string {
	switch {
	case w.OrganizationID == "" && w.OrganizationName == "":
		return ""
	case w.OrganizationName == "":
		return w.OrganizationID
	default:
		return fmt.Sprintf("%s (%s)", w.OrganizationName, w.OrganizationID)
	}
}

func writeWorkspace(name string, workspace Workspace) error {
	path, err := profile.WorkspacePath(name)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(workspace, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func readWorkspace(name string) (Workspace, error) {
	path, err := profile.WorkspacePath(name)
	if err != nil {
		return Workspace{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Workspace{}, err
	}
	var workspace Workspace
	if err := json.Unmarshal(data, &workspace); err != nil {
		return Workspace{}, err
	}
	return workspace, nil
}

// ProfileStatus is one profile's listing entry.
//
// Deliberately absent: whether the install token is READABLE. Resolving it
// touches the login keychain, and this listing is what a polling menu bar app
// calls — repeatedly prodding the keychain from a background process is how you
// earn an authorization prompt loop. `kontext doctor` checks the active
// profile's token, once, when a human asks.
type ProfileStatus struct {
	Name     string `json:"name"`
	Active   bool   `json:"active"`
	CloudURL string `json:"cloud_url,omitempty"`
	Mode     string `json:"mode,omitempty"`
	// Workspace is the display label, "Name (id)". Kept for callers that want one
	// string, but a UI with limited width should prefer OrganizationName — an id
	// is 36 characters of noise to a human choosing between workspaces.
	Workspace string `json:"workspace,omitempty"`
	// Environment classifies the backend — "production", "staging", "local", or
	// empty for anything else. Consumers group by it instead of each hardcoding
	// the same URLs.
	Environment      string `json:"environment,omitempty"`
	OrganizationName string `json:"organization_name,omitempty"`
	OrganizationID   string `json:"organization_id,omitempty"`
	InstallTokenRef  string `json:"install_token_ref,omitempty"`
	InstallationID   string `json:"installation_id,omitempty"`
	// Error describes why this profile could not be read. A broken profile is
	// reported rather than omitted: silently short listings are how a machine
	// looks healthy while one workspace is unusable.
	Error string `json:"error,omitempty"`
}

// Inventory is the machine-readable view of local profiles — one of the two
// surfaces (with `doctor --json`) that a GUI is expected to build on.
type Inventory struct {
	Active string `json:"active,omitempty"`
	// LegacyInstall reports an unprofiled install still resolving the old
	// paths. It becomes false after migration.
	LegacyInstall bool            `json:"legacy_install"`
	Profiles      []ProfileStatus `json:"profiles"`
}

// LoadInventory gathers every profile's state without touching the keychain or
// the network.
func LoadInventory() (Inventory, error) {
	inventory := Inventory{Profiles: []ProfileStatus{}}

	active, err := profile.ActiveName()
	switch {
	case err == nil:
		inventory.Active = active
	case errors.Is(err, profile.ErrNoActive):
		// Legacy only counts when there is actually a config at the old path;
		// a machine with nothing set up at all is neither legacy nor profiled.
		if legacy := managedconfig.LegacyUserPath(); legacy != "" {
			if _, statErr := os.Lstat(legacy); statErr == nil {
				inventory.LegacyInstall = true
			}
		}
	default:
		return Inventory{}, err
	}

	names, err := profile.List()
	if err != nil {
		return Inventory{}, err
	}
	for _, name := range names {
		inventory.Profiles = append(inventory.Profiles, describeProfile(name, name == inventory.Active))
	}
	return inventory, nil
}

func describeProfile(name string, active bool) ProfileStatus {
	status := ProfileStatus{Name: name, Active: active}

	configPath, err := profile.ManagedConfigPath(name)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	loaded, err := managedconfig.LoadFile(configPath)
	if err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			status.Error = "not set up yet"
		} else {
			status.Error = err.Error()
		}
		return status
	}
	status.CloudURL = loaded.Config.CloudURL
	status.Environment = EnvironmentFor(loaded.Config.CloudURL)
	status.Mode = loaded.Config.Mode
	status.InstallTokenRef = loaded.Config.Credentials.InstallTokenRef.String()

	if workspace, err := readWorkspace(name); err == nil {
		status.Workspace = workspace.Label()
		status.OrganizationName = workspace.OrganizationName
		status.OrganizationID = workspace.OrganizationID
	}
	if identityPath, err := profile.InstallationPath(name); err == nil {
		if state, err := installation.LoadFile(identityPath); err == nil {
			status.InstallationID = state.InstallationID
		}
	}
	return status
}

// WriteJSON emits the inventory for programmatic consumers.
func (i Inventory) WriteJSON(out io.Writer) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(i)
}

// WriteText renders the human listing.
func (i Inventory) WriteText(out io.Writer) error {
	if len(i.Profiles) == 0 {
		if i.LegacyInstall {
			fmt.Fprintln(out, "No profiles yet — this Mac has an install that predates profiles.")
			fmt.Fprintf(out, "Run `kontext profile migrate` to move it into the %q profile.\n", profile.DefaultName)
			return nil
		}
		fmt.Fprintln(out, "No profiles yet. Run `kontext profile add <name> --cloud-url <url>` to create one.")
		return nil
	}

	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "\tNAME\tWORKSPACE\tBACKEND\tMODE")
	// Every row carries the same cell count or tabwriter cannot align the
	// columns; a broken profile's detail goes below the table rather than
	// stretching the WORKSPACE column to the width of an error message.
	var broken []ProfileStatus
	for _, p := range i.Profiles {
		marker := " "
		if p.Active {
			marker = "*"
		}
		if p.Error != "" {
			broken = append(broken, p)
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", marker, p.Name, "(unusable)", "-", "-")
			continue
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", marker, p.Name, orDash(p.Workspace), orDash(p.CloudURL), orDash(p.Mode))
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	for _, p := range broken {
		fmt.Fprintf(out, "\n%s: %s\n", p.Name, p.Error)
		fmt.Fprintf(out, "  Run `kontext profile add %s --cloud-url <url>` to finish setting it up, or `kontext profile rm %s` to discard it.\n", p.Name, p.Name)
	}
	if i.Active == "" {
		fmt.Fprintln(out, "\nNo profile is active. Run `kontext profile use <name>`.")
	}
	return nil
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// profileBoundToWorkspace returns the name of a profile already bound to
// organizationID on cloudURL, or "" when none is.
//
// Scoped to one backend on purpose: the same organization id appearing on
// staging and on production is two different workspaces that happen to share an
// identifier, and refusing the second would be wrong.
//
// `exclude` is the profile being written, so re-running setup for an existing
// profile — rotating its token — is never mistaken for a duplicate of itself.
func profileBoundToWorkspace(organizationID, cloudURL, exclude string) (string, error) {
	if strings.TrimSpace(organizationID) == "" {
		// Nothing to compare. The legacy env-fallback org reports an empty id, and
		// treating every such install as a duplicate of the others would block
		// setup entirely.
		return "", nil
	}
	names, err := profile.List()
	if err != nil {
		return "", err
	}
	for _, name := range names {
		if name == exclude {
			continue
		}
		workspace, err := readWorkspace(name)
		if err != nil || workspace.OrganizationID != organizationID {
			continue
		}
		configPath, err := profile.ManagedConfigPath(name)
		if err != nil {
			continue
		}
		loaded, err := managedconfig.LoadFile(configPath)
		if err != nil || loaded.Config.CloudURL != cloudURL {
			continue
		}
		return name, nil
	}
	return "", nil
}
