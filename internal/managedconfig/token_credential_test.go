package managedconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/credstore"
)

// A credential ref names an entry in the signed-in user's Windows credential
// store. It parses like the other sources, and resolving it says why when
// there is nothing to read: no store on this OS, no store in this session,
// or no such entry.
func TestCredentialTokenRef(t *testing.T) {
	ref, err := ParseTokenRef("credential:kontext-install-token")
	if err != nil {
		t.Fatalf("ParseTokenRef = %v", err)
	}
	if ref.Source != "credential" || ref.Name != "kontext-install-token" || ref.String() != "credential:kontext-install-token" {
		t.Fatalf("ref = %+v", ref)
	}

	missing := TokenRef{Source: "credential", Name: fmt.Sprintf("kontext-test-missing-%d-%d", os.Getpid(), time.Now().UnixNano())}
	_, err = ResolveInstallToken(context.Background(), missing)
	if !errors.Is(err, credstore.ErrUnsupported) && !errors.Is(err, credstore.ErrNoLogonSession) && !errors.Is(err, credstore.ErrNotFound) {
		t.Fatalf("ResolveInstallToken(missing) = %v, want it to name the store's answer", err)
	}
}

// With a store at hand, the token written for the user is the one resolved.
func TestCredentialTokenRefResolvesTheStoredToken(t *testing.T) {
	name := fmt.Sprintf("kontext-test-token-%d-%d", os.Getpid(), time.Now().UnixNano())
	if err := credstore.Write(name, "  the-token\n"); err != nil {
		if errors.Is(err, credstore.ErrUnsupported) || errors.Is(err, credstore.ErrNoLogonSession) {
			t.Skipf("no credential store here: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = credstore.Delete(name) })
	got, err := ResolveInstallToken(context.Background(), TokenRef{Source: "credential", Name: name})
	if err != nil || got != "the-token" {
		t.Fatalf("ResolveInstallToken = %q, %v, want the stored token without its whitespace", got, err)
	}
}
