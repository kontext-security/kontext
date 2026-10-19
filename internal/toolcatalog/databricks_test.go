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
		{"running a job", "POST", "/api/2.2/jobs/run-now", "jobs.Jobs.RunNow", "workspace", "execution", "write", nil},
		{"another API version", "POST", "/api/2.1/jobs/run-now", "jobs.Jobs.RunNow", "workspace", "execution", "write", nil},
		{"trailing slash", "GET", "/api/2.1/unity-catalog/catalogs/", "catalog.Catalogs.List", "workspace", "data", "read", nil},
		{"workspace SCIM", "DELETE", "/api/2.0/preview/scim/v2/Users/42", "iam.Users.Delete", "workspace", "admin", "admin", nil},
		{"account SCIM", "DELETE", "/api/2.0/accounts/0d1a/scim/v2/Users/42", "iam.AccountUsers.Delete", "account", "admin", "admin", nil},
		{"literal fallback beats a same-version catch-all", "GET", "/api/2.1/apps", "apps.Apps.List", "workspace", "workloads", "read", nil},
		{"credential validation is not a read", "POST", "/api/2.1/unity-catalog/validate-storage-credentials", "catalog.StorageCredentials.Validate", "workspace", "data", "write", nil},
		{"removing rows is a delete", "POST", "/api/2.0/ai-search/main.default.idx:removeData", "aisearch.AiSearch.RemoveData", "workspace", "ai", "delete", nil},
		{"workspace warehouse security config", "PUT", "/api/2.0/sql/config/warehouses", "sql.Warehouses.SetWorkspaceWarehouseConfig", "workspace", "compute", "admin", nil},
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
		{"apps", "deploy", "apps.Apps.Deploy", "workspace", "execution", "write"},
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
		// bundle deploy applies permissions blocks.
		{"bundle", "deploy", "cli.bundle.deploy", "", "execution", "admin"},
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
