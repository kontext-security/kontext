package setup

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

// writeKeychainToken stores the raw token as a login-keychain generic
// password, symmetric with the daemon's read path
// (`security find-generic-password -s <service> -w`). The write happens in
// two phases:
//
//  1. delete every existing item with our service name — find-generic-password
//     matches by service only, so a stale item (different account, previous
//     org) could otherwise win the read;
//  2. add the new item, feeding the command through `security -i` STDIN so
//     the token never appears in the process argument list.
//
// go-keyring is deliberately NOT used: its darwin Set() stores
// "go-keyring-base64:<encoded>" which the daemon's raw read would return
// verbatim.
func writeKeychainToken(ctx context.Context, item, token string) error {
	if err := deleteKeychainTokens(ctx, item); err != nil {
		return err
	}
	command := fmt.Sprintf(
		"add-generic-password -U -s %s -a %s -w %s\n",
		item, keychainAccount, securityQuote(token),
	)
	if out, err := execCommand(ctx, command, "security", "-i"); err != nil {
		return fmt.Errorf("store install token in keychain: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

// maxKeychainDeletions is a runaway guard, not an expected count — the loop
// normally ends on the first "not found" (0 or 1 items).
const maxKeychainDeletions = 32

// deleteKeychainTokens removes ALL items with the given service name (delete
// only removes one match per invocation). Only the explicit "not found" outcome
// ends the loop as success — a locked keychain or denied access must surface,
// otherwise uninstall would report the token removed while it still exists
// (and a rotation could proceed on top of a stale item).
func deleteKeychainTokens(ctx context.Context, item string) error {
	if item == "" {
		return errors.New("keychain item name must not be empty")
	}
	for attempt := 0; attempt < maxKeychainDeletions; attempt++ {
		out, err := execCommand(ctx, "", "security", "delete-generic-password", "-s", item)
		if err == nil {
			continue // one item deleted; loop for more
		}
		if isSecurityNotFound(out) {
			return nil // no (more) matching items
		}
		return fmt.Errorf("delete keychain item %s: %w (%s)", item, err, strings.TrimSpace(out))
	}
	return fmt.Errorf("more than %d keychain items named %s; clean them up in Keychain Access and retry", maxKeychainDeletions, item)
}

// deleteAllInstallTokens removes the legacy item and every profile's item.
// Uninstall must not leave a workspace token behind in the keychain just
// because that profile was not the active one.
// Returns the items deleted, plus the names of any profiles whose config could
// not be read — for those, the token reference is unknown and one may survive
// under a name nothing records any more.
func deleteAllInstallTokens(ctx context.Context) (deleted []string, unreadable []string, err error) {
	seen := map[string]bool{}
	var items []string
	add := func(item string) {
		if item == "" || seen[item] {
			return
		}
		seen[item] = true
		items = append(items, item)
	}

	add(profile.LegacyKeychainItemName())
	names, err := profile.List()
	if err != nil {
		return nil, nil, err
	}
	for _, name := range names {
		// keychainItemsForProfile reads the ref each profile's config actually
		// names, not just the name-derived convention. A renamed or migrated
		// profile references an item whose name does not match its directory, and
		// deriving from the name alone would leave that workspace's token in the
		// keychain while reporting every token removed.
		profileItems, configReadable := keychainItemsForProfile(name)
		for _, item := range profileItems {
			add(item)
		}
		if !configReadable {
			unreadable = append(unreadable, name)
		}
	}
	for _, item := range items {
		if err := deleteKeychainTokens(ctx, item); err != nil {
			return nil, nil, err
		}
	}
	return items, unreadable, nil
}

func isSecurityNotFound(output string) bool {
	normalized := strings.ToLower(output)
	return strings.Contains(normalized, "could not be found") ||
		strings.Contains(normalized, "not found") ||
		strings.Contains(normalized, "specified item could not be found")
}

// securityQuote wraps a value for the `security -i` command parser, which
// accepts double-quoted strings with backslash escapes.
func securityQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
