package browserhost

// storeExtensionIDs are the store listings' extension IDs (ENG-1074), which
// every build accepts. Edge installs the Chrome Web Store package, so the
// Chrome ID covers Edge until an Edge Add-ons listing has its own ID.
var storeExtensionIDs = []string{
	"jdakicfhknddbigfcfgfmhoabhgpjega", // Chrome Web Store
}
