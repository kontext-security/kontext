package codexroute

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/codexproxy"
)

// The reasons Codex is not routed through the proxy, as the daemon reports
// them to the Kontext API, which shows each one with a sentence of its own
// and any other one with the route's state alone.
const (
	// The endpoint's switches are off; compaction's wins.
	ReasonCompactionOff = "compaction_off"
	ReasonCodexProxyOff = "codex_proxy_off"

	ReasonMacOSOnly = "macos_only"

	// The person's ~/.codex/config.toml routes Codex itself, or Kontext
	// cannot change it.
	ReasonUserOpenAIBaseURL      = "user_openai_base_url"
	ReasonUserModelProvider      = "user_model_provider"
	ReasonUserChatGPTBaseURL     = "user_chatgpt_base_url"
	ReasonCodexConfigUnparseable = "codex_config_unparseable"
	ReasonCodexConfigNotEditable = "codex_config_not_editable"
	ReasonCodexConfigPermissions = "codex_config_permissions"

	// A layer of Codex's configuration that an administrator manages routes
	// Codex, or cannot be read.
	ReasonAdminOpenAIBaseURL    = "admin_openai_base_url"
	ReasonAdminModelProvider    = "admin_model_provider"
	ReasonAdminChatGPTBaseURL   = "admin_chatgpt_base_url"
	ReasonAdminConfigUnreadable = "admin_config_unreadable"

	// The proxy's copy of the binary or its files, its job, or the proxy
	// itself failed, or the proxy cannot reach OpenAI.
	ReasonProxyInstallFailed  = "proxy_install_failed"
	ReasonProxyJobNotLoaded   = "proxy_job_not_loaded"
	ReasonProxyNotAnswering   = "proxy_not_answering"
	ReasonUpstreamUnreachable = "upstream_unreachable"

	// What took the line away besides a daemon (see TakeAway): the
	// proxy job, once no daemon held the route (or for
	// ReasonUpstreamUnreachable); Codex's session start hook; and `kontext
	// codex-proxy disable`.
	ReasonDaemonStopped           = "daemon_stopped"
	ReasonProxyDownAtSessionStart = "proxy_down_at_session_start"
	ReasonDisabledLocally         = "disabled_locally"

	// Anything else.
	ReasonRouteError = "route_error"
)

// settingReasons are the reasons for each setting that routes Codex
// somewhere of its own, set by the person and by an administrator.
var settingReasons = map[string]struct{ user, admin string }{
	codexmanaged.SettingOpenAIBaseURL:  {ReasonUserOpenAIBaseURL, ReasonAdminOpenAIBaseURL},
	codexmanaged.SettingModelProvider:  {ReasonUserModelProvider, ReasonAdminModelProvider},
	codexmanaged.SettingChatGPTBaseURL: {ReasonUserChatGPTBaseURL, ReasonAdminChatGPTBaseURL},
}

// configReason is the reason for an error reading or writing
// ~/.codex/config.toml.
func configReason(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return ReasonCodexConfigPermissions
	}
	return ReasonRouteError
}

// addRouteReason is the reason for an error adding the line to
// ~/.codex/config.toml.
func addRouteReason(err error) string {
	if errors.Is(err, codexmanaged.ErrRouteNotEditable) {
		return ReasonCodexConfigNotEditable
	}
	return ReasonCodexConfigUnparseable
}

// Counters are what the proxy job counted since the daemon's last report the
// Kontext API accepted, kept in counters.json for its next one: the job
// counts, and the daemon takes off what it reported (see Reported).
type Counters struct {
	UpstreamFailures int `json:"upstreamFailures"`
	PassThroughs     int `json:"passThroughs"`
	PartsMissing     int `json:"partsMissing"`
	// CodexVersions are the Codex versions of the requests the job carried.
	CodexVersions []string `json:"codexVersions,omitempty"`
}

// maxCount and maxCodexVersions are the most of a counter, and of versions,
// that the Kontext API takes.
const (
	maxCount         = 1_000_000_000
	maxCodexVersions = 8
)

func (r *Router) countersPath() string     { return filepath.Join(r.opts.StateDir, "counters.json") }
func (r *Router) countersLockPath() string { return filepath.Join(r.opts.StateDir, "counters.lock") }

// Count adds what one of the proxy job's requests counted to the counters.
// They have a lock of their own: a daemon may hold the route's for seconds,
// and a request must never wait on it.
func (r *Router) Count(counts codexproxy.Counts) error {
	if r.opts.GOOS != "darwin" || counts == (codexproxy.Counts{}) {
		return nil
	}
	unlock, _, err := lockFile(r.countersLockPath(), true)
	if err != nil {
		return err
	}
	defer unlock()
	counters := r.loadCounters()
	changed := counts.UpstreamFailures+counts.PassThroughs+counts.PartsMissing > 0
	counters.UpstreamFailures = min(counters.UpstreamFailures+counts.UpstreamFailures, maxCount)
	counters.PassThroughs = min(counters.PassThroughs+counts.PassThroughs, maxCount)
	counters.PartsMissing = min(counters.PartsMissing+counts.PartsMissing, maxCount)
	// The first versions since the last report fit; one the daemon reported
	// comes back with the next request of it.
	if version := counts.CodexVersion; version != "" && !slices.Contains(counters.CodexVersions, version) &&
		len(counters.CodexVersions) < maxCodexVersions {
		counters.CodexVersions = append(counters.CodexVersions, version)
		changed = true
	}
	if !changed {
		return nil
	}
	return r.saveCounters(counters)
}

// Counters returns what the proxy job counted since the daemon's last
// accepted report.
func (r *Router) Counters() Counters {
	if r.opts.GOOS != "darwin" {
		return Counters{}
	}
	return r.loadCounters()
}

// Reported takes counters the Kontext API accepted off the job's: what the
// job counted since stays for the next report.
func (r *Router) Reported(sent Counters) error {
	if r.opts.GOOS != "darwin" || sent.UpstreamFailures+sent.PassThroughs+sent.PartsMissing == 0 && len(sent.CodexVersions) == 0 {
		return nil
	}
	unlock, _, err := lockFile(r.countersLockPath(), true)
	if err != nil {
		return err
	}
	defer unlock()
	counters := r.loadCounters()
	counters.UpstreamFailures = max(counters.UpstreamFailures-sent.UpstreamFailures, 0)
	counters.PassThroughs = max(counters.PassThroughs-sent.PassThroughs, 0)
	counters.PartsMissing = max(counters.PartsMissing-sent.PartsMissing, 0)
	counters.CodexVersions = slices.DeleteFunc(counters.CodexVersions, func(version string) bool {
		return slices.Contains(sent.CodexVersions, version)
	})
	return r.saveCounters(counters)
}

// loadCounters reads the counters; one that cannot be read starts again from
// nothing. They come back within what the Kontext API takes, whatever the
// file says, since one report it refuses would hold every later count.
func (r *Router) loadCounters() Counters {
	var counters Counters
	if data, err := os.ReadFile(r.countersPath()); err == nil && json.Unmarshal(data, &counters) != nil {
		return Counters{}
	}
	for _, count := range []*int{&counters.UpstreamFailures, &counters.PassThroughs, &counters.PartsMissing} {
		*count = min(max(*count, 0), maxCount)
	}
	var versions []string
	for _, version := range counters.CodexVersions {
		if codexVersionPattern.MatchString(version) && !slices.Contains(versions, version) && len(versions) < maxCodexVersions {
			versions = append(versions, version)
		}
	}
	counters.CodexVersions = versions
	return counters
}

// codexVersionPattern is a Codex version the Kontext API takes.
var codexVersionPattern = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,32}$`)

func (r *Router) saveCounters(counters Counters) error {
	data, err := json.Marshal(counters)
	if err != nil {
		return err
	}
	return writePrivate(r.opts.StateDir, r.countersPath(), data)
}
