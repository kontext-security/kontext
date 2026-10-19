package toolcatalog

import "testing"

func TestIsDatabricksHost(t *testing.T) {
	for host, want := range map[string]bool{
		"dbc-1234.cloud.databricks.com":              true,
		"accounts.cloud.databricks.com":              true,
		"acme.privatelink.cloud.databricks.com":      true,
		"adb-123.4.azuredatabricks.net":              true,
		"adb-123.4.privatelink.azuredatabricks.net":  true,
		"accounts.azuredatabricks.net":               true,
		"123.4.gcp.databricks.com":                   true,
		"accounts.gcp.databricks.com":                true,
		"dbc-1.cloud.databricks.us":                  true,
		"dbc-1.cloud.databricks.mil":                 true,
		"adb-1.2.databricks.azure.us":                true,
		"adb-1.2.databricks.azure.cn":                true,
		"acme.databricks.com":                        true,
		"community.cloud.databricks.com":             true,
		"databricks.com":                             false,
		"www.databricks.com":                         false,
		"docs.databricks.com":                        false,
		"community.databricks.com":                   false,
		"cloud.databricks.com":                       false,
		"azuredatabricks.net":                        false,
		"evil-databricks.com":                        false,
		"dbc-1234.cloud.databricks.com.evil.example": false,
		"api.github.com":                             false,
		"notazuredatabricks.net":                     false,
	} {
		if got := IsDatabricksHost(host); got != want {
			t.Errorf("IsDatabricksHost(%q) = %t, want %t", host, got, want)
		}
	}
}
