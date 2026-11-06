package fsperm

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// keyCreateLink is KEY_CREATE_LINK, which x/sys/windows/registry does not name.
const keyCreateLink = 0x20

// keyWriteAccess is every right that lets someone change a registry key's values
// or subkeys, or who may. KEY_READ's notify bit shares its value with a file's
// FILE_WRITE_EA, so a key needs its own mask.
const keyWriteAccess = registry.SET_VALUE | registry.CREATE_SUB_KEY | keyCreateLink |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// ReadAdminOnlyRegistryString reads a string value from HKLM in the 64-bit view,
// only if its key is owned by SYSTEM, Administrators or TrustedInstaller and
// nobody else can change it. Values have no access list of their own, so the
// key's decides. Everyone may still read; a per-user process has to.
func ReadAdminOnlyRegistryString(path, name string) (string, error) {
	return readAdminOnlyRegistryString(registry.LOCAL_MACHINE, `HKLM\`, path, name)
}

func readAdminOnlyRegistryString(root registry.Key, rootName, path, name string) (string, error) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|windows.READ_CONTROL|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer key.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	reason, err := notAdminOnly(sd, keyWriteAccess)
	if err != nil {
		return "", err
	}
	if reason != "" {
		return "", &NotAdminOnlyError{Path: rootName + path, Reason: reason}
	}
	value, kind, err := key.GetStringValue(name)
	if err != nil {
		return "", err
	}
	if kind != registry.SZ {
		return "", errors.New(rootName + path + `\` + name + " is not a plain string value")
	}
	return value, nil
}
