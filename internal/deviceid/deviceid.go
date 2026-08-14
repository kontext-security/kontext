// Package deviceid derives the stable device reconciliation key reported to
// the hosted API alongside the random installation identity.
//
// The installation id (internal/installation) is deliberately random and dies
// with its file: removing a profile or wiping Application Support mints a
// fresh one, and the hosted inventory shows a duplicate endpoint whose stale
// twin never disappears. The device key closes that gap without giving up the
// properties the random id exists for. It is HMAC-SHA256 over the Mac's
// IOPlatformUUID, keyed with the workspace's organization id:
//
//   - Stable where it matters: the same Mac re-enrolled in the same workspace
//     derives the same key, so the hosted side can reconcile a fresh
//     installation id with the stale instance it replaces.
//   - Unlinkable where it must be: two workspaces derive different keys for
//     one Mac, and the raw hardware identifier never leaves the machine.
//   - A hint, never a credential: the endpoint reports the value about
//     itself, so the hosted side may use it to fold inventory rows — never to
//     authenticate, and never to destroy a superseded instance's history.
package deviceid

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Test seam (repo convention, cf. setup's execCommand): PlatformUUID goes
// through this so tests never depend on this machine's ioreg.
var runCommand = func(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

var platformUUIDPattern = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"`)

// PlatformUUID reads this Mac's IOPlatformUUID. It is readable without
// privileges, survives OS reinstalls, and changes only with a logic-board
// repair — which is exactly when a machine should read as a new device. The
// absolute ioreg path matters: under launchd the daemon runs with a minimal
// PATH.
func PlatformUUID(ctx context.Context) (string, error) {
	out, err := runCommand(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return "", fmt.Errorf("read IOPlatformUUID: %w", err)
	}
	match := platformUUIDPattern.FindStringSubmatch(out)
	if match == nil {
		return "", errors.New("IOPlatformUUID not present in ioreg output")
	}
	// Uppercase before hashing: the derivation must not depend on how a
	// particular macOS build happens to case the value.
	return strings.ToUpper(match[1]), nil
}

// Key derives the reconciliation key for one Mac in one workspace. The
// organization id is the HMAC key, so the raw platform UUID is never sent and
// two workspaces cannot correlate the same machine by comparing values.
//
// Both inputs are required: an unsalted or unkeyed digest would be linkable
// across workspaces, which is the property the per-profile installation
// identity deliberately refuses to give up.
func Key(platformUUID, organizationID string) (string, error) {
	uuid := strings.ToUpper(strings.TrimSpace(platformUUID))
	org := strings.TrimSpace(organizationID)
	if uuid == "" || org == "" {
		return "", errors.New("device key requires both a platform UUID and an organization id")
	}
	mac := hmac.New(sha256.New, []byte(org))
	mac.Write([]byte(uuid))
	return "dk_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
