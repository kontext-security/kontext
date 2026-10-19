package toolcatalog

import (
	"reflect"
	"testing"
)

func TestDatabricksRoute(t *testing.T) {
	tests := []struct {
		name, method, path string
		operation, client  string
		product, access    string
		adminFields        []string
	}{
		{"path parameter", "GET", "/api/2.1/unity-catalog/tables/main.default.trips", "catalog.Tables.Get", "workspace", "data", "read", nil},
		{"literal beats parameter", "GET", "/api/2.1/unity-catalog/tables/main.default.trips/exists", "catalog.Tables.Exists", "workspace", "data", "read", nil},
		{"two parameters", "GET", "/api/2.0/sql/statements/01ef/result/chunks/3", "sql.StatementExecution.GetStatementResultChunkN", "workspace", "sql", "read", nil},
		{"multi-segment parameter", "PUT", "/api/2.0/fs/files/Volumes/main/default/raw/a.csv", "files.Files.Upload", "workspace", "data", "write", nil},
		{"POST read", "POST", "/api/2.1/clusters/events", "compute.Clusters.Events", "workspace", "compute", "read", nil},
		{"POST delete", "post", "/api/2.1/clusters/delete", "compute.Clusters.Delete", "workspace", "compute", "delete", nil},
		{"running SQL", "POST", "/api/2.0/sql/statements", "sql.StatementExecution.ExecuteStatement", "workspace", "sql", "write", nil},
		{"warehouse is compute", "DELETE", "/api/2.0/sql/warehouses/abc123", "sql.Warehouses.Delete", "workspace", "compute", "delete", nil},
		{"warehouse permissions", "PUT", "/api/2.0/permissions/warehouses/abc123", "sql.Warehouses.SetPermissions", "workspace", "admin", "admin", []string{"access_control_list"}},
		{"owner in body", "PATCH", "/api/2.1/unity-catalog/catalogs/main", "catalog.Catalogs.Update", "workspace", "data", "admin", []string{"owner"}},
		{"secret read", "GET", "/api/2.0/secrets/get?scope=prod&key=token", "workspace.Secrets.GetSecret", "workspace", "secrets", "read", nil},
		{"publishing with embedded credentials", "POST", "/api/2.0/lakeview/dashboards/01ef/published", "dashboards.Lakeview.Publish", "workspace", "workspace", "admin", []string{"embed_credentials"}},
		{"apps deploy over REST", "POST", "/api/2.0/apps/my-app/deployments", "apps.Apps.Deploy", "workspace", "execution", "write", nil},
		{"recipient with its activation URL", "GET", "/api/2.1/unity-catalog/recipients/acme", "sharing.Recipients.Get", "workspace", "secrets", "read", nil},
		{"installations carry bearer tokens", "GET", "/api/2.1/marketplace-consumer/installations", "marketplace.ConsumerInstallations.List", "workspace", "secrets", "read", nil},
		{"system schema", "PUT", "/api/2.1/unity-catalog/metastores/abc/systemschemas/access", "catalog.SystemSchemas.Enable", "workspace", "admin", "admin", nil},
		{"native Postgres login", "PATCH", "/api/2.0/database/instances/main", "database.Database.UpdateDatabaseInstance", "workspace", "data", "admin", []string{"enable_pg_native_login"}},
		{"pending policy enforcement", "POST", "/api/2.0/policies/clusters:cancelPendingClusterEnforcement", "compute.PolicyComplianceForClusters.CancelPendingClusterEnforcement", "workspace", "compute", "admin", nil},
		{"one-time credential download", "GET", "/api/2.1/unity-catalog/public/data_sharing_activation/abc", "sharing.RecipientActivation.RetrieveToken", "workspace", "secrets", "write", nil},
		{"AI Gateway guardrails", "PUT", "/api/2.0/serving-endpoints/chat/ai-gateway", "serving.ServingEndpoints.PutAiGateway", "workspace", "ai", "admin", nil},
		{"inference table capture", "PUT", "/api/2.0/serving-endpoints/chat/config", "serving.ServingEndpoints.UpdateConfig", "workspace", "ai", "admin", []string{"auto_capture_config", "served_entities.external_model.amazon_bedrock_config.instance_profile_arn", "served_entities.instance_profile_arn", "served_models.instance_profile_arn"}},
		{"installing a library", "POST", "/api/2.0/libraries/install", "compute.Libraries.Install", "workspace", "execution", "write", nil},
		{"external location with fallback", "POST", "/api/2.1/unity-catalog/external-locations", "catalog.ExternalLocations.Create", "workspace", "data", "admin", nil},
		{"repo update can discard work", "PATCH", "/api/2.0/repos/42", "workspace.Repos.Update", "workspace", "workspace", "delete", nil},
		{"running a job", "POST", "/api/2.2/jobs/run-now", "jobs.Jobs.RunNow", "workspace", "execution", "write", nil},
		{"another API version", "POST", "/api/2.1/jobs/run-now", "jobs.Jobs.RunNow", "workspace", "execution", "write", nil},
		{"trailing slash", "GET", "/api/2.1/unity-catalog/catalogs/", "catalog.Catalogs.List", "workspace", "data", "read", nil},
		{"workspace SCIM", "DELETE", "/api/2.0/preview/scim/v2/Users/42", "iam.Users.Delete", "workspace", "admin", "admin", nil},
		{"account SCIM", "DELETE", "/api/2.0/accounts/0d1a/scim/v2/Users/42", "iam.AccountUsers.Delete", "account", "admin", "admin", nil},
		{"literal fallback beats a same-version catch-all", "GET", "/api/2.1/apps", "apps.Apps.List", "workspace", "workloads", "read", nil},
		{"credential validation is not a read", "POST", "/api/2.1/unity-catalog/validate-storage-credentials", "catalog.StorageCredentials.Validate", "workspace", "data", "write", nil},
		{"removing rows is a delete", "POST", "/api/2.0/ai-search/main.default.idx:removeData", "aisearch.AiSearch.RemoveData", "workspace", "ai", "delete", nil},
		{"workspace warehouse security config", "PUT", "/api/2.0/sql/config/warehouses", "sql.Warehouses.SetWorkspaceWarehouseConfig", "workspace", "compute", "admin", []string{"instance_profile_arn"}},
		{"secret ACL removal", "POST", "/api/2.0/secrets/acls/delete", "workspace.Secrets.DeleteAcl", "workspace", "secrets", "admin", nil},
		{"secret scope with a manage principal", "POST", "/api/2.0/secrets/scopes/create", "workspace.Secrets.CreateScope", "workspace", "secrets", "admin", []string{"initial_manage_principal"}},
		{"account provisioning", "POST", "/api/2.0/accounts/0d1a/workspaces", "provisioning.Workspaces.Create", "account", "admin", "admin", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := DatabricksRoute(test.method, test.path)
			if !ok {
				t.Fatalf("DatabricksRoute(%s %s) not found", test.method, test.path)
			}
			// Several SDK services share a SCIM route; any of them is the same call.
			if got.Operation != test.operation && got.Path != routePath(t, test.operation) {
				t.Errorf("operation = %s, want %s", got.Operation, test.operation)
			}
			if got.Client != test.client || got.Product != test.product || got.Access != test.access || !reflect.DeepEqual(got.AdminFields, test.adminFields) {
				t.Errorf("got %s %s/%s %v, want %s %s/%s %v", got.Client, got.Product, got.Access, got.AdminFields, test.client, test.product, test.access, test.adminFields)
			}
		})
	}
}

func routePath(t *testing.T, operation string) string {
	t.Helper()
	for _, routes := range databricks().routes {
		for _, route := range routes {
			if route.operation.Operation == operation {
				return route.operation.Path
			}
		}
	}
	t.Fatalf("no route for %s", operation)
	return ""
}

func TestDatabricksRouteNotFound(t *testing.T) {
	for _, test := range []struct{ method, path string }{
		{"GET", "/api/2.0/not-a-service/things"},
		{"POST", "/api/2.1/clusters/explode"},
		{"PATCH", "/api/2.1/clusters/list"},
		{"GET", "/api/2.1/unity-catalog/tables/a/b/c/d"},
		{"GET", ""},
		// Templates that start with a parameter would claim any path.
		{"DELETE", "/api/2.0/anything"},
		{"GET", "/api/2.1/not-a-service"},
		{"POST", "/api/2.0/not-a-service/start"},
	} {
		if got, ok := DatabricksRoute(test.method, test.path); ok {
			t.Errorf("DatabricksRoute(%s %s) = %s, want not found", test.method, test.path, got.Operation)
		}
	}
}

func TestDatabricksCommand(t *testing.T) {
	for _, test := range []struct {
		group, verb, operation, client, product, access string
	}{
		{"clusters", "delete", "compute.Clusters.Delete", "workspace", "compute", "delete"},
		{"clusters", "events", "compute.Clusters.Events", "workspace", "compute", "read"},
		{"catalogs", "update", "catalog.Catalogs.Update", "workspace", "data", "admin"},
		{"jobs", "run-now", "jobs.Jobs.RunNow", "workspace", "execution", "write"},
		{"jobs", "create", "jobs.Jobs.Create", "workspace", "workloads", "admin"},
		{"pipelines", "start-update", "pipelines.Pipelines.StartUpdate", "workspace", "execution", "write"},
		// Without an app name, apps deploy deploys the bundle.
		{"apps", "deploy", "cli.apps.deploy", "", "execution", "admin"},
		{"secrets", "get-secret", "workspace.Secrets.GetSecret", "workspace", "secrets", "read"},
		{"settings default-namespace", "get", "settings.DefaultNamespace.Get", "workspace", "admin", "read"},
		{"groups", "delete", "iam.Groups.Delete", "workspace", "admin", "admin"},
		{"account groups", "delete", "iam.AccountGroups.Delete", "account", "admin", "admin"},
		{"account  groups ", " list", "iam.AccountGroups.List", "account", "admin", "read"},
		{"apps", "start", "apps.Apps.Start", "workspace", "execution", "write"},
		{"ai-search", "remove-data", "aisearch.AiSearch.RemoveData", "workspace", "ai", "delete"},
		{"postgres", "update-role", "postgres.Postgres.UpdateRole", "workspace", "data", "admin"},
		{"postgres", "create-role", "postgres.Postgres.CreateRole", "workspace", "data", "admin"},
		{"secrets", "delete-acl", "workspace.Secrets.DeleteAcl", "workspace", "secrets", "admin"},
		{"warehouses", "set-workspace-warehouse-config", "sql.Warehouses.SetWorkspaceWarehouseConfig", "workspace", "compute", "admin"},
		{"storage-credentials", "validate", "catalog.StorageCredentials.Validate", "workspace", "data", "write"},
		// Reachable by command although its template is a catch-all.
		{"sandbox", "get-sandbox", "sandbox.Sandbox.GetSandbox", "workspace", "execution", "read"},
		{"postgres", "update-database", "postgres.Postgres.UpdateDatabase", "workspace", "data", "admin"},
		{"git-credentials", "delete", "workspace.GitCredentials.Delete", "workspace", "secrets", "admin"},
		{"clean-room-auto-approval-rules", "create", "cleanrooms.CleanRoomAutoApprovalRules.Create", "workspace", "data", "admin"},
		{"clean-room-assets", "create-clean-room-asset-review", "cleanrooms.CleanRoomAssets.CreateCleanRoomAssetReview", "workspace", "data", "admin"},
		{"model-registry", "test-registry-webhook", "ml.ModelRegistry.TestRegistryWebhook", "workspace", "execution", "write"},
		{"genie", "start-conversation", "dashboards.Genie.StartConversation", "workspace", "sql", "write"},
		{"genie", "create-message", "dashboards.Genie.CreateMessage", "workspace", "sql", "write"},
		{"ai-gateway", "create-mcp-service-user-mapped-credential", "catalog.AiGateway.CreateMcpServiceUserMappedCredential", "workspace", "secrets", "write"},
		{"cluster-policies", "edit", "compute.ClusterPolicies.Edit", "workspace", "compute", "admin"},
		{"provider-exchange-filters", "create", "marketplace.ProviderExchangeFilters.Create", "workspace", "data", "admin"},
		{"provider-exchange-filters", "delete", "marketplace.ProviderExchangeFilters.Delete", "workspace", "data", "admin"},
		{"recipients", "rotate-token", "sharing.Recipients.RotateToken", "workspace", "secrets", "admin"},
		{"serving-endpoints", "http-request", "serving.ServingEndpoints.HttpRequest", "workspace", "execution", "admin"},
		{"agent-kit", "pop-session-item", "agentkit.AgentKit.PopSessionItem", "workspace", "ai", "delete"},
		{"shares", "list", "sharing.Shares.ListShares", "workspace", "data", "read"},
		{"provider-listings", "create", "marketplace.ProviderListings.Create", "workspace", "data", "admin"},
		{"provider-personalization-requests", "update", "marketplace.ProviderPersonalizationRequests.Update", "workspace", "data", "admin"},
		{"serving-endpoints", "update-config", "serving.ServingEndpoints.UpdateConfig", "workspace", "ai", "admin"},
		{"serving-endpoints", "patch-telemetry-config", "serving.ServingEndpoints.PatchTelemetryConfig", "workspace", "ai", "admin"},
		{"serving-endpoints", "create", "serving.ServingEndpoints.Create", "workspace", "ai", "admin"},
		{"entity-tag-assignments", "create", "catalog.EntityTagAssignments.Create", "workspace", "data", "admin"},
		{"provider-exchanges", "update", "marketplace.ProviderExchanges.Update", "workspace", "data", "admin"},
		{"pipelines", "clone", "pipelines.Pipelines.Clone", "workspace", "execution", "admin"},
		{"storage-credentials", "create", "catalog.StorageCredentials.Create", "workspace", "data", "admin"},
		{"warehouses", "create-default-warehouse-override", "sql.Warehouses.CreateDefaultWarehouseOverride", "workspace", "compute", "admin"},
		{"external-locations", "create", "catalog.ExternalLocations.Create", "workspace", "data", "admin"},
		{"data-classification", "update-catalog-config", "dataclassification.DataClassification.UpdateCatalogConfig", "workspace", "data", "admin"},
		{"ai-gateway", "create-model-provider-service", "catalog.AiGateway.CreateModelProviderService", "workspace", "secrets", "admin"},
		// effective_owner is computed by the server.
		{"ai-gateway", "update-skill", "catalog.AiGateway.UpdateSkill", "workspace", "ai", "write"},
		{"ai-gateway", "update-mcp-service", "catalog.AiGateway.UpdateMcpService", "workspace", "ai", "admin"},
		{"ai-gateway", "update-model-service", "catalog.AiGateway.UpdateModelService", "workspace", "ai", "admin"},
		{"serving-endpoints", "put", "serving.ServingEndpoints.Put", "workspace", "ai", "admin"},
		{"postgres", "update-branch", "postgres.Postgres.UpdateBranch", "workspace", "data", "admin"},
		{"instance-pools", "create", "compute.InstancePools.Create", "workspace", "compute", "admin"},
		{"repos", "update", "workspace.Repos.Update", "workspace", "workspace", "delete"},
		{"connections", "create", "catalog.Connections.Create", "workspace", "secrets", "write"},
		{"providers", "create", "sharing.Providers.Create", "workspace", "secrets", "write"},
		{"providers", "update", "sharing.Providers.Update", "workspace", "secrets", "admin"},
		{"libraries", "install", "compute.Libraries.Install", "workspace", "execution", "write"},
		{"serving-endpoints", "put-ai-gateway", "serving.ServingEndpoints.PutAiGateway", "workspace", "ai", "admin"},
		{"provider-exchanges", "add-listing-to-exchange", "marketplace.ProviderExchanges.AddListingToExchange", "workspace", "data", "admin"},
		{"recipient-activation", "retrieve-token", "sharing.RecipientActivation.RetrieveToken", "workspace", "secrets", "write"},
		{"shares", "share-permissions", "sharing.Shares.SharePermissions", "workspace", "admin", "read"},
		{"database", "update-database-instance", "database.Database.UpdateDatabaseInstance", "workspace", "data", "admin"},
		{"postgres", "update-data-api", "postgres.Postgres.UpdateDataApi", "workspace", "data", "admin"},
		{"policy-compliance-for-clusters", "cancel-pending-cluster-enforcement", "compute.PolicyComplianceForClusters.CancelPendingClusterEnforcement", "workspace", "compute", "admin"},
		{"system-schemas", "enable", "catalog.SystemSchemas.Enable", "workspace", "admin", "admin"},
		{"system-schemas", "disable", "catalog.SystemSchemas.Disable", "workspace", "admin", "admin"},
		{"environments", "update-default-workspace-base-environment", "environments.Environments.UpdateDefaultWorkspaceBaseEnvironment", "workspace", "admin", "admin"},
		{"consumer-installations", "list", "marketplace.ConsumerInstallations.List", "workspace", "secrets", "read"},
		{"recipients", "get", "sharing.Recipients.Get", "workspace", "secrets", "read"},
		{"model-registry", "create-webhook", "ml.ModelRegistry.CreateWebhook", "workspace", "ai", "admin"},
		// Without an app name, apps delete destroys the bundle.
		{"apps", "delete", "cli.apps.delete", "", "workloads", "admin"},
		// bundle deploy applies permissions blocks; destroy can drop Postgres roles.
		{"bundle", "destroy", "cli.bundle.destroy", "", "workloads", "admin"},
		{"bundle", "deploy", "cli.bundle.deploy", "", "execution", "admin"},
		{"account endpoints", "delete-endpoint", "networking.Endpoints.DeleteEndpoint", "account", "admin", "admin"},
		{"service-principal-secrets-proxy", "create", "oauth2.ServicePrincipalSecretsProxy.Create", "workspace", "secrets", "admin"},
		{"token-management", "delete", "settings.TokenManagement.Delete", "workspace", "secrets", "admin"},
		{"lakeview", "publish", "dashboards.Lakeview.Publish", "workspace", "workspace", "admin"},
		{"genie", "generate-download-full-query-result", "dashboards.Genie.GenerateDownloadFullQueryResult", "workspace", "sql", "write"},
		{"bundle", "run", "cli.bundle.run", "", "execution", "write"},
	} {
		got, ok := DatabricksCommand(test.group, test.verb)
		if !ok {
			t.Errorf("DatabricksCommand(%q, %q) not found", test.group, test.verb)
			continue
		}
		if got.Operation != test.operation || got.Client != test.client || got.Product != test.product || got.Access != test.access {
			t.Errorf("DatabricksCommand(%q, %q) = %s %s %s/%s, want %s %s %s/%s", test.group, test.verb, got.Operation, got.Client, got.Product, got.Access, test.operation, test.client, test.product, test.access)
		}
	}
	for _, test := range [][2]string{{"clusters", "explode"}, {"workspace", "export-dir"}, {"delete", ""}, {"", ""}} {
		if got, ok := DatabricksCommand(test[0], test[1]); ok {
			t.Errorf("DatabricksCommand(%q, %q) = %s, want not found", test[0], test[1], got.Operation)
		}
	}
}

// Overlap rules on a synthetic table: the most literal template wins, then
// the requested version, then the strictest tier; equally strict
// candidates in different products are not found.
func TestDatabricksRouteOverlaps(t *testing.T) {
	index := newDatabricksIndex(databricksTable{Routes: []DatabricksOperation{
		{Operation: "v20.Get", Method: "GET", Path: "/api/2.0/things/{id}", Product: "data", Access: AccessRead},
		{Operation: "v21.Get", Method: "GET", Path: "/api/2.1/things/{id}", Product: "compute", Access: AccessRead},
		{Operation: "literal.Get", Method: "GET", Path: "/api/2.0/things/special", Product: "ai", Access: AccessRead},
		{Operation: "a.Update", Method: "PATCH", Path: "/api/2.0/items/{name}", Product: "ai", Access: AccessWrite},
		{Operation: "b.Update", Method: "PATCH", Path: "/api/2.0/items/{name}", Product: "ai", Access: AccessAdmin},
		{Operation: "c.Delete", Method: "DELETE", Path: "/api/2.0/items/{name}", Product: "ai", Access: AccessDelete},
		{Operation: "d.Delete", Method: "DELETE", Path: "/api/2.0/items/{name}", Product: "data", Access: AccessDelete},
		{Operation: "catchall.Get", Method: "GET", Path: "/api/2.0/{name}", Product: "ai", Access: AccessRead},
	}})
	for _, test := range []struct{ method, path, want string }{
		{"GET", "/api/2.1/things/7", "v21.Get"},
		{"GET", "/api/2.0/things/7", "v20.Get"},
		// 2.0 and 2.1 match equally and disagree on product.
		{"GET", "/api/2.2/things/7", ""},
		{"GET", "/api/2.1/things/special", "literal.Get"},
		{"PATCH", "/api/2.0/items/x", "b.Update"},
		{"DELETE", "/api/2.0/items/x", ""},
		{"GET", "/api/2.0/anything", ""},
	} {
		got, ok := index.route(test.method, test.path)
		if got.Operation != test.want || ok != (test.want != "") {
			t.Errorf("route(%s %s) = %q, %v; want %q", test.method, test.path, got.Operation, ok, test.want)
		}
	}
}

// The strictest candidate wins whatever order the candidates come in.
func TestDatabricksRouteOverlapOrder(t *testing.T) {
	candidates := []DatabricksOperation{
		{Operation: "ai.Write", Method: "POST", Path: "/api/2.0/x/{id}", Product: "ai", Access: AccessWrite},
		{Operation: "data.Write", Method: "POST", Path: "/api/2.0/x/{id}", Product: "data", Access: AccessWrite},
		{Operation: "ai.Admin", Method: "POST", Path: "/api/2.0/x/{id}", Product: "ai", Access: AccessAdmin},
	}
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		var routes []DatabricksOperation
		for _, i := range order {
			routes = append(routes, candidates[i])
		}
		got, ok := newDatabricksIndex(databricksTable{Routes: routes}).route("POST", "/api/2.0/x/1")
		if !ok || got.Operation != "ai.Admin" {
			t.Errorf("order %v: got %q, %v; want ai.Admin", order, got.Operation, ok)
		}
	}
}

// The generator's tier rules, checked over the whole embedded table.
func TestDatabricksTableTiers(t *testing.T) {
	table := databricks()
	if len(table.commands) < 1000 {
		t.Fatalf("only %d commands embedded", len(table.commands))
	}
	for method, routes := range table.routes {
		for _, route := range routes {
			op := route.operation
			switch {
			case op.Operation == "sharing.RecipientActivation.RetrieveToken":
				// Retrieving the credential uses up the one-time link.
				if op.Access != AccessWrite {
					t.Errorf("%s is %s, want write", op.Operation, op.Access)
				}
			case (method == "GET" || method == "HEAD") && op.Access != AccessRead:
				t.Errorf("%s %s (%s) is %s, want read", method, op.Path, op.Operation, op.Access)
			case method != "GET" && method != "HEAD" && method != "POST" && op.Access == AccessRead:
				t.Errorf("%s %s (%s) is read", method, op.Path, op.Operation)
			case len(op.AdminFields) > 0 && op.Access != AccessAdmin:
				t.Errorf("%s %s (%s) carries %v but is %s", method, op.Path, op.Operation, op.AdminFields, op.Access)
			case op.Product == "admin" && op.Access != AccessRead && op.Access != AccessAdmin:
				t.Errorf("%s %s (%s) is an admin product at %s", method, op.Path, op.Operation, op.Access)
			}
		}
	}
}
