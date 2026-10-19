package toolcatalog

import "strings"

// databricksHostSuffixes are the domains Databricks serves workspaces and
// account consoles under: AWS (PrivateLink is <name>.privatelink.cloud…),
// Azure, GCP (Private Service Connect included), AWS GovCloud and DoD, Azure
// Government and Azure China.
var databricksHostSuffixes = []string{
	".cloud.databricks.com", ".azuredatabricks.net", ".gcp.databricks.com",
	".cloud.databricks.us", ".cloud.databricks.mil", ".databricks.azure.us", ".databricks.azure.cn",
}

// databricksSiteHosts are the <name>.databricks.com hosts that are a cloud's
// apex or serve the website, docs and community, not a workspace API.
var databricksSiteHosts = setOf("cloud", "gcp", "www", "docs", "community", "academy", "customer-academy", "partner-academy", "kb", "help", "status", "ideas", "marketplace", "login", "dbricks", "files")

// IsDatabricksHost reports whether host (lower-case, without port or trailing
// dot) is a Databricks workspace or account API host. A custom workspace
// URL, <name>.databricks.com, counts unless it is one of the website hosts.
func IsDatabricksHost(host string) bool {
	for _, suffix := range databricksHostSuffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	name, ok := strings.CutSuffix(host, ".databricks.com")
	return ok && name != "" && !strings.Contains(name, ".") && !databricksSiteHosts[name]
}
