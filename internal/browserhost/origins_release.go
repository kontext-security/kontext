//go:build !kontext_browser_dev

package browserhost

// AllowedExtensionIDs are the extension IDs this build accepts: the Chrome
// Web Store and Edge Add-ons IDs, once the listings exist (ENG-1074). Until
// then a release build refuses every caller.
func AllowedExtensionIDs() []string { return storeExtensionIDs }

var storeExtensionIDs = []string{}
