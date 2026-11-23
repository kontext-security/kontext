package browserevents

import (
	"encoding/json"
	"strings"

	"github.com/kontext-security/kontext/browser/contract"
)

// catalogApp is one entry of the contract's catalog.
type catalogApp struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Provider string   `json:"provider"`
	Hosts    []string `json:"hosts"`
}

// catalog maps an app id to its entry. A visit must name an app in it, with
// the catalog's own name and provider and one of its hosts, so no field of a
// visit can carry text the extension did not take from the catalog.
var catalog = mustCatalog(contract.CatalogJSON)

func mustCatalog(raw []byte) map[string]catalogApp {
	var apps []catalogApp
	if err := json.Unmarshal(raw, &apps); err != nil {
		panic("browser events: the embedded catalog is not valid: " + err.Error())
	}
	byID := make(map[string]catalogApp, len(apps))
	for _, app := range apps {
		byID[app.ID] = app
	}
	return byID
}

// matchesHost reports whether host is what a visit to the app sends: one of
// its exact hosts, or for a pattern "*.example.com" the name example.com
// itself. A name below a pattern can name a workspace, so it never goes out.
func (a catalogApp) matchesHost(host string) bool {
	for _, pattern := range a.Hosts {
		if host == strings.TrimPrefix(pattern, "*.") {
			return true
		}
	}
	return false
}
