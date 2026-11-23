//go:build kontext_browser_dev

package browserhost

// DevExtensionID is the ID of the extension's dev builds, derived from the
// public key in the extension repository's dev-key.json. Anyone can build an
// extension with this ID, so only builds with the kontext_browser_dev tag
// accept it.
const DevExtensionID = "jbfhbfeilekhmfekihompjpmkecgpfgn"

// AllowedExtensionIDs are the store IDs plus the dev ID.
func AllowedExtensionIDs() []string {
	return append(append([]string{}, storeExtensionIDs...), DevExtensionID)
}

var storeExtensionIDs = []string{}
