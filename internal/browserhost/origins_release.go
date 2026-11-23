//go:build !kontext_browser_dev

package browserhost

// AllowedExtensionIDs are the extension IDs this build accepts: the store IDs
// only.
func AllowedExtensionIDs() []string { return storeExtensionIDs }
