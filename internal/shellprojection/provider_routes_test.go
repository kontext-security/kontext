package shellprojection

import "testing"

const (
	atlCatalogued = FactAtlassianRouteCatalogued
	atlUnknown    = FactAtlassianRouteUnrecognized
	hsCatalogued  = FactHubSpotRouteCatalogued
	hsUnknown     = FactHubSpotRouteUnrecognized
	jiraWrite     = "jira/write=true"
	jiraDelete    = "jira/delete=true"
	jiraAdmin     = "jira/admin=true"
	confWrite     = "confluence/write=true"
	confAdmin     = "confluence/admin=true"
	hsWrite       = "hubspot/write=true"
	hsDelete      = "hubspot/delete=true"
	hsAdmin       = "hubspot/admin=true"
)

func TestJiraShellCorpus(t *testing.T) {
	runCorpus(t, []corpusCase{
		// REST API on a Cloud site.
		{name: "get issue", command: "curl -sS -u me:token https://acme.atlassian.net/rest/api/3/issue/ENG-1", programs: []string{"curl"}, facts: []string{atlCatalogued}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "jql search over POST is a read", command: `curl -X POST --json '{"jql":"project=ENG"}' https://acme.atlassian.net/rest/api/3/search/jql`, programs: []string{"curl"}, facts: []string{atlCatalogued}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "create issue", command: `curl -d '{"fields":{}}' https://acme.atlassian.net/rest/api/3/issue`, programs: []string{"curl"}, facts: []string{atlCatalogued, jiraWrite}, absentFacts: []string{jiraDelete, jiraAdmin}, complete: true},
		{name: "transition", command: `curl -X POST -d '{}' https://acme.atlassian.net/rest/api/2/issue/ENG-1/transitions`, programs: []string{"curl"}, facts: []string{jiraWrite}, complete: true},
		{name: "delete issue", command: "curl -X DELETE https://acme.atlassian.net/rest/api/3/issue/ENG-1", programs: []string{"curl"}, facts: []string{jiraWrite, jiraDelete}, absentFacts: []string{jiraAdmin}, complete: true},
		{name: "delete project is admin and delete", command: "curl -X DELETE https://acme.atlassian.net/rest/api/3/project/ENG", programs: []string{"curl"}, facts: []string{jiraWrite, jiraDelete, jiraAdmin}, complete: true},
		{name: "project role change is admin", command: `curl -X POST -d '{}' https://acme.atlassian.net/rest/api/3/project/ENG/role/10002`, programs: []string{"curl"}, facts: []string{jiraAdmin}, complete: true},
		{name: "workflow change is admin", command: `curl -X PUT -d '{}' https://acme.atlassian.net/rest/api/3/workflows/update`, programs: []string{"curl"}, facts: []string{jiraAdmin}, complete: true},
		{name: "permission check is a read", command: `curl -X POST -d '{}' https://acme.atlassian.net/rest/api/3/permissions/check`, programs: []string{"curl"}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "agile sprint write", command: `curl -X POST -d '{}' https://acme.atlassian.net/rest/agile/1.0/sprint`, programs: []string{"curl"}, facts: []string{jiraWrite}, complete: true},
		{name: "oauth gateway", command: `curl -X PUT -d '{}' https://api.atlassian.com/ex/jira/1111-2222/rest/api/3/issue/ENG-1`, programs: []string{"curl"}, facts: []string{atlCatalogued, jiraWrite}, complete: true},
		{name: "gateway outside jira and confluence", command: `curl -X POST -d '{}' https://api.atlassian.com/admin/v1/orgs/1/users`, programs: []string{"curl"}, facts: []string{atlUnknown, incomplete}, complete: false},
		{name: "body from file is unrecognized", command: "curl -X POST -d @issue.json https://acme.atlassian.net/rest/api/3/issue", programs: []string{"curl"}, facts: []string{atlUnknown, jiraWrite, incomplete}, complete: false},
		{name: "confluence page update", command: `curl -X PUT -d '{}' https://acme.atlassian.net/wiki/api/v2/pages/1`, programs: []string{"curl"}, facts: []string{confWrite}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "confluence restriction is admin", command: `curl -X PUT -d '{}' https://acme.atlassian.net/wiki/rest/api/content/1/restriction`, programs: []string{"curl"}, facts: []string{confWrite, confAdmin}, complete: true},
		// Atlassian CLI.
		{name: "acli view", command: "acli jira workitem view ENG-1", programs: []string{"acli"}, facts: []string{atlCatalogued, "acli/command=jira/workitem/view"}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "acli search", command: `acli jira workitem search --jql "project = ENG"`, programs: []string{"acli"}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "acli create", command: `acli jira workitem create --summary "view" --project ENG`, programs: []string{"acli"}, facts: []string{atlCatalogued, jiraWrite}, complete: true},
		{name: "acli comment create", command: `acli jira workitem comment create --key ENG-1 --body hi`, programs: []string{"acli"}, facts: []string{jiraWrite}, complete: true},
		{name: "acli delete", command: "acli jira workitem delete --key ENG-1 --yes", programs: []string{"acli"}, facts: []string{jiraWrite, jiraDelete}, absentFacts: []string{jiraAdmin}, complete: true},
		{name: "acli project create is admin", command: "acli jira project create --key NEW", programs: []string{"acli"}, facts: []string{jiraWrite, jiraAdmin}, complete: true},
		{name: "acli auth is local", command: "acli jira auth login --web", programs: []string{"acli"}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "acli unknown verb fails closed", command: "acli jira workitem frobnicate ENG-1", programs: []string{"acli"}, facts: []string{atlUnknown, jiraWrite, incomplete}, complete: false},
		{name: "acli confluence write", command: "acli confluence page create --space ENG", programs: []string{"acli"}, facts: []string{confWrite}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "acli through sh -c", command: `sh -c "acli jira workitem delete --key ENG-1"`, programs: []string{"acli"}, facts: []string{jiraDelete}, complete: true},
		// Community jira CLIs.
		{name: "jira-cli list", command: "jira issue list -p ENG", programs: []string{"jira"}, facts: []string{atlCatalogued}, absentFacts: []string{jiraWrite}, complete: true},
		{name: "jira-cli move", command: `jira issue move ENG-1 "In Progress"`, programs: []string{"jira"}, facts: []string{jiraWrite}, complete: true},
		{name: "jira-cli delete", command: "jira issue delete ENG-1", programs: []string{"jira"}, facts: []string{jiraDelete}, complete: true},
		{name: "go-jira top-level verb", command: "jira transition Done ENG-1", programs: []string{"jira"}, facts: []string{jiraWrite}, complete: true},
		{name: "jira dynamic argument", command: "jira issue $ACTION ENG-1", programs: []string{"jira"}, facts: []string{atlUnknown, jiraWrite, incomplete}, complete: false},
	})
}

func TestHubSpotShellCorpus(t *testing.T) {
	runCorpus(t, []corpusCase{
		{name: "get contact", command: "curl -H 'Authorization: Bearer x' https://api.hubapi.com/crm/v3/objects/contacts/1", programs: []string{"curl"}, facts: []string{hsCatalogued}, absentFacts: []string{hsWrite}, complete: true},
		{name: "search is a read", command: `curl -X POST --json '{}' https://api.hubapi.com/crm/v3/objects/contacts/search`, programs: []string{"curl"}, absentFacts: []string{hsWrite}, complete: true},
		{name: "batch read is a read", command: `curl -d '{}' https://api.hubapi.com/crm/v3/objects/deals/batch/read`, programs: []string{"curl"}, absentFacts: []string{hsWrite}, complete: true},
		{name: "update contact", command: `curl -X PATCH -d '{}' https://api.hubapi.com/crm/v3/objects/contacts/1`, programs: []string{"curl"}, facts: []string{hsCatalogued, hsWrite}, absentFacts: []string{hsDelete, hsAdmin}, complete: true},
		{name: "archive is a delete", command: `curl -d '{}' https://api.hubapi.com/crm/v3/objects/contacts/batch/archive`, programs: []string{"curl"}, facts: []string{hsWrite, hsDelete}, complete: true},
		{name: "gdpr delete", command: `curl -d '{}' https://api.hubapi.com/crm/v3/objects/contacts/gdpr-delete`, programs: []string{"curl"}, facts: []string{hsDelete}, complete: true},
		{name: "property change is admin", command: `curl -d '{}' https://api.hubapi.com/crm/v3/properties/contacts`, programs: []string{"curl"}, facts: []string{hsWrite, hsAdmin}, complete: true},
		{name: "pipeline delete", command: "curl -X DELETE https://api.hubapi.com/crm/v3/pipelines/deals/1", programs: []string{"curl"}, facts: []string{hsDelete, hsAdmin}, complete: true},
		{name: "eu host", command: `curl -X POST -d '{}' https://api-eu1.hubapi.com/crm/v3/objects/companies`, programs: []string{"curl"}, facts: []string{hsWrite}, complete: true},
		{name: "upload from file", command: "curl -X POST --data-binary @contacts.json https://api.hubapi.com/crm/v3/objects/contacts/batch/create", programs: []string{"curl"}, facts: []string{hsUnknown, hsWrite, incomplete}, complete: false},
		{name: "hs list", command: "hs project list-builds", programs: []string{"hs"}, facts: []string{hsCatalogued}, absentFacts: []string{hsWrite}, complete: true},
		{name: "hs deploy", command: "hs project deploy --build 3", programs: []string{"hs"}, facts: []string{hsWrite}, absentFacts: []string{hsAdmin}, complete: true},
		{name: "hs upload", command: "hs upload ./theme remote/theme", programs: []string{"hs"}, facts: []string{hsWrite}, complete: true},
		{name: "hs secret add is admin", command: "hs secrets add API_KEY", programs: []string{"hs"}, facts: []string{hsWrite, hsAdmin}, complete: true},
		{name: "hs sandbox delete", command: "hs sandbox delete --account dev", programs: []string{"hs"}, facts: []string{hsDelete, hsAdmin}, complete: true},
		{name: "hs unknown", command: "hs newthing go", programs: []string{"hs"}, facts: []string{hsUnknown, hsWrite, incomplete}, complete: false},
	})
}

// Provider routes never trip the GitHub guard, and GitHub routes never
// carry provider facts.
func TestProviderRoutesStaySeparate(t *testing.T) {
	runCorpus(t, []corpusCase{
		{name: "jira is not github", command: "curl -X DELETE https://acme.atlassian.net/rest/api/3/issue/ENG-1", programs: []string{"curl"}, absentFacts: []string{write, unrecognized, catalogued}, complete: true},
		{name: "github is not jira", command: "gh pr merge 1", programs: []string{"gh"}, absentFacts: []string{jiraWrite, hsWrite, atlCatalogued}, complete: true},
		{name: "other host", command: "curl -X POST -d '{}' https://example.com/rest/api/3/issue", programs: []string{"curl"}, absentFacts: []string{jiraWrite, atlCatalogued}, complete: true},
	})
}
