//go:build windows

package credstore

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// needStore skips a test in a session Windows gives no credential store,
// such as an SSH session signed in with a key or a service's session.
func needStore(t *testing.T) {
	t.Helper()
	if _, err := Read("kontext-test-probe"); errors.Is(err, ErrNoLogonSession) {
		t.Skip("this session has no Windows credential store; run in a desktop session of the user")
	}
}

// A secret written for the signed-in user is read back, replaced, and gone
// after a delete. The name is this test run's own, and is removed again.
func TestSecretRoundTrip(t *testing.T) {
	needStore(t)
	name := fmt.Sprintf("kontext-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { _ = Delete(name) })

	if _, err := Read(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read before a write = %v, want ErrNotFound", err)
	}
	if err := Write(name, "first-secret"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, err := Read(name); err != nil || got != "first-secret" {
		t.Fatalf("Read = %q, %v", got, err)
	}
	if err := Write(name, "second-secret"); err != nil {
		t.Fatalf("Write over an existing secret: %v", err)
	}
	if got, err := Read(name); err != nil || got != "second-secret" {
		t.Fatalf("Read after a second write = %q, %v", got, err)
	}
	if err := Delete(name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Read(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read after a delete = %v, want ErrNotFound", err)
	}
	if err := Delete(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete of nothing = %v, want ErrNotFound", err)
	}
}

func TestWriteRefusesWhatTheStoreCannotHold(t *testing.T) {
	needStore(t)
	name := fmt.Sprintf("kontext-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { _ = Delete(name) })
	if err := Write(name, ""); err == nil {
		t.Error("Write of an empty secret = nil, want an error")
	}
	if err := Write(name, strings.Repeat("x", maxSecretBytes+1)); err == nil {
		t.Error("Write of a secret that is too long = nil, want an error")
	}
	if _, err := Read(name); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read after refused writes = %v, want ErrNotFound", err)
	}
}

// A session without a store says so in a way a caller can act on.
func TestNoLogonSessionIsNamed(t *testing.T) {
	err := storeError("read", "x", errorNoSuchLogonSession)
	if !errors.Is(err, ErrNoLogonSession) {
		t.Fatalf("storeError(1312) = %v, want ErrNoLogonSession", err)
	}
	if err := storeError("read", "x", errorNotFound); !errors.Is(err, ErrNotFound) {
		t.Fatalf("storeError(1168) = %v, want ErrNotFound", err)
	}
}
