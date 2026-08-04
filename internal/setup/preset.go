package setup

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

// StagingCloudURL is the staging backend. It is not a secret — it appears in
// this repository's public docs — and having it here means `kontext profile add
// staging` does not require anyone to remember or retype it.
const StagingCloudURL = "https://api.staging.kontext.security"

// LocalCloudURL is the API port the backend's own dev setup uses (apps/api
// defaults to PORT=4000). It is only a starting point: --cloud-url still wins.
const LocalCloudURL = "http://localhost:4000"

// Preset is a known environment's connection settings.
type Preset struct {
	CloudURL string
	// AllowHTTPLoopback is set for local presets, where plaintext to a loopback
	// host is the point rather than an accident.
	AllowHTTPLoopback bool
	// Description is shown when a preset is applied, so an inferred URL is never
	// silently assumed.
	Description string
}

// presets maps profile names to environments. The aliases are deliberate: people
// reach for "prod" and "production", "local" and "localdev", and having one of
// them silently fall through to the production default would be a nasty way to
// find out which spelling was blessed.
var presets = map[string]Preset{
	"prod":       {CloudURL: DefaultCloudURL, Description: "production"},
	"production": {CloudURL: DefaultCloudURL, Description: "production"},
	"staging":    {CloudURL: StagingCloudURL, Description: "staging"},
	"stg":        {CloudURL: StagingCloudURL, Description: "staging"},
	"local":      {CloudURL: LocalCloudURL, AllowHTTPLoopback: true, Description: "local development"},
	"localdev":   {CloudURL: LocalCloudURL, AllowHTTPLoopback: true, Description: "local development"},
	"dev":        {CloudURL: LocalCloudURL, AllowHTTPLoopback: true, Description: "local development"},
}

// LookupPreset returns the known environment for a profile name.
//
// Matching is by name alone. That is the whole ergonomic idea — `kontext profile
// add staging` should not also require the URL — and it is safe because a preset
// only ever supplies a DEFAULT: an explicit --cloud-url always wins, and the URL
// that gets written is printed either way.
func LookupPreset(name string) (Preset, bool) {
	preset, ok := presets[strings.ToLower(strings.TrimSpace(name))]
	return preset, ok
}

// validatePresetURL checks a preset against the same rules setup applies, so a
// preset can never supply a value that our own validation would then reject.
func validatePresetURL(preset Preset) error {
	return managedconfig.ValidateCloudURL(preset.CloudURL, preset.AllowHTTPLoopback)
}

// Environment names, as reported to consumers. Grouping a profile list by
// environment is a display concern, but the mapping from URL to environment is
// knowledge the CLI already owns — so it answers the question rather than making
// every consumer hardcode the same three URLs.
const (
	EnvironmentProduction = "production"
	EnvironmentStaging    = "staging"
	EnvironmentLocal      = "local"
)

// EnvironmentFor classifies a backend URL, returning "" when it matches none of
// the known environments — a self-hosted or one-off endpoint is legitimate and
// should be shown as itself rather than forced into a bucket.
func EnvironmentFor(cloudURL string) string {
	switch strings.TrimSpace(cloudURL) {
	case "":
		return ""
	case DefaultCloudURL:
		return EnvironmentProduction
	case StagingCloudURL:
		return EnvironmentStaging
	}
	if parsed, err := url.Parse(cloudURL); err == nil {
		host := parsed.Hostname()
		if strings.EqualFold(host, "localhost") {
			return EnvironmentLocal
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return EnvironmentLocal
		}
	}
	return ""
}

// PresetNames lists the recognized names, for help text.
func PresetNames() []string {
	// Grouped by environment rather than sorted, so the aliases read as aliases.
	return []string{"prod", "production", "staging", "stg", "local", "localdev", "dev"}
}

// environmentSlug is the short form used in a derived profile name.
func environmentSlug(cloudURL string) string {
	switch EnvironmentFor(cloudURL) {
	case EnvironmentProduction:
		return "prod"
	case EnvironmentStaging:
		return "staging"
	case EnvironmentLocal:
		return "local"
	default:
		return "workspace"
	}
}

// slugify reduces a workspace name to something profile.ValidateName accepts:
// lowercase, alphanumerics and single hyphens, bounded in length.
func slugify(value string) string {
	var b strings.Builder
	lastHyphen := true // leading hyphens are invalid, so start as if one was written
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastHyphen = false
		default:
			if !lastHyphen {
				b.WriteRune('-')
				lastHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// DeriveProfileName picks a name for a workspace that was just identified, so a
// caller never has to invent one.
//
// The environment alone when it is free ("staging"), otherwise qualified by the
// workspace ("staging-acme-corp"), otherwise by its id. The name is only a
// handle — `profile use <name>` and a directory — so short and recognizable
// beats unique-by-construction, and each candidate is checked for existence
// anyway.
func DeriveProfileName(cloudURL, organizationName, organizationID string) (string, error) {
	base := environmentSlug(cloudURL)
	candidates := []string{base}
	if slug := slugify(organizationName); slug != "" {
		candidates = append(candidates, truncateName(base+"-"+slug))
	}
	if slug := slugify(organizationID); slug != "" {
		candidates = append(candidates, truncateName(base+"-"+slug))
	}
	for _, candidate := range candidates {
		if profile.ValidateName(candidate) != nil {
			continue
		}
		exists, err := profile.Exists(candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	// Everything recognizable is taken. Numbered suffixes are the last resort
	// rather than the first, so ordinary cases keep readable names.
	for i := 2; i < 100; i++ {
		candidate := truncateName(fmt.Sprintf("%s-%d", base, i))
		exists, err := profile.Exists(candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not derive an unused profile name for %s", cloudURL)
}

// truncateName keeps a candidate inside the 32-character limit without leaving a
// trailing hyphen behind.
func truncateName(value string) string {
	const max = 32
	if len(value) <= max {
		return value
	}
	return strings.TrimRight(value[:max], "-")
}
