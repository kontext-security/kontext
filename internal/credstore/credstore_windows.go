//go:build windows

package credstore

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredRead   = advapi32.NewProc("CredReadW")
	procCredWrite  = advapi32.NewProc("CredWriteW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric = 1
	// Kept for this user on this machine; not roamed to other machines.
	credPersistLocalMachine = 2
	errorNotFound           = syscall.Errno(1168)
	errorNoSuchLogonSession = syscall.Errno(1312)
)

// credential is CREDENTIALW.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// Read returns the secret stored under name.
func Read(name string) (string, error) {
	target, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var found *credential
	if ok, _, callErr := procCredRead.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&found))); ok == 0 {
		return "", storeError("read", name, callErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(found)))
	if found.CredentialBlobSize == 0 || found.CredentialBlob == nil {
		return "", nil
	}
	secret := string(unsafe.Slice(found.CredentialBlob, found.CredentialBlobSize))
	if strings.ContainsRune(secret, 0) {
		return "", fmt.Errorf("credential store: read %s: the entry was not written by kontext (it holds NUL bytes, as UTF-16 text does)", name)
	}
	return secret, nil
}

// Write stores secret under name, replacing what was there.
func Write(name, secret string) error {
	if secret == "" {
		return errors.New("credential store: the secret is empty")
	}
	if len(secret) > maxSecretBytes {
		return fmt.Errorf("credential store: the secret is %d bytes, more than the %d a credential holds", len(secret), maxSecretBytes)
	}
	target, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	blob := []byte(secret)
	entry := credential{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(blob)),
		CredentialBlob:     &blob[0],
		Persist:            credPersistLocalMachine,
	}
	if ok, _, callErr := procCredWrite.Call(uintptr(unsafe.Pointer(&entry)), 0); ok == 0 {
		return storeError("write", name, callErr)
	}
	return nil
}

// Delete removes the secret stored under name.
func Delete(name string) error {
	target, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if ok, _, callErr := procCredDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0); ok == 0 {
		return storeError("delete", name, callErr)
	}
	return nil
}

func storeError(op, name string, err error) error {
	if errors.Is(err, errorNotFound) {
		return fmt.Errorf("credential store: %s %s: %w", op, name, ErrNotFound)
	}
	if errors.Is(err, errorNoSuchLogonSession) {
		return fmt.Errorf("credential store: %s %s: %w", op, name, ErrNoLogonSession)
	}
	return fmt.Errorf("credential store: %s %s: %w", op, name, err)
}
