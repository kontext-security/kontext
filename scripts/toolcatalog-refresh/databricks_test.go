package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func databricksFixtures() (cli, sdk sourceTree) {
	sdk = sourceTree{
		"workspace_client.go": []byte(`package databricks

import (
	"github.com/databricks/databricks-sdk-go/service/apps"
	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/files"
	"github.com/databricks/databricks-sdk-go/service/settings"
	"github.com/databricks/databricks-sdk-go/service/sharing"
)

func NewWorkspaceClient() *WorkspaceClient {
	commandExecution := compute.NewCommandExecution(databricksClient)
	return &WorkspaceClient{
		Apps:             apps.NewApps(databricksClient),
		Clusters:         compute.NewClusters(databricksClient),
		CommandExecution: commandExecution,
		Files:            files.NewFiles(databricksClient),
		Settings:         settings.NewSettings(databricksClient),
		Shares:           sharing.NewShares(databricksClient),
	}
}
`),
		"account_client.go": []byte(`package databricks

import (
	"github.com/databricks/databricks-sdk-go/service/iam"
	"github.com/databricks/databricks-sdk-go/service/networking"
)

func NewAccountClient() *AccountClient {
	return &AccountClient{
		Endpoints: networking.NewEndpoints(apiClient),
		Groups:    iam.NewAccountGroups(apiClient),
	}
}
`),
		"service/compute/impl.go": []byte(`package compute

import (
	"context"
	"fmt"
	"net/http"
)

type clustersImpl struct{ client *client.DatabricksClient }

func (a *clustersImpl) Delete(ctx context.Context, request DeleteCluster) error {
	path := "/api/2.1/clusters/delete"
	err := a.client.Do(ctx, http.MethodPost, path, headers, queryParams, request, nil)
	return err
}

func (a *clustersImpl) Events(ctx context.Context, request GetEvents) (*GetEventsResponse, error) {
	path := "/api/2.1/clusters/events"
	err := a.client.Do(ctx, http.MethodPost, path, headers, queryParams, request, &out)
	return &out, err
}

func (a *clustersImpl) GetDetails(ctx context.Context, request GetEvents) (*GetEventsResponse, error) {
	path := "/api/2.1/clusters/get-details"
	err := a.client.Do(ctx, http.MethodPost, path, headers, queryParams, request, &out)
	return &out, err
}

func (a *clustersImpl) List(ctx context.Context, request ListClustersRequest) listing.Iterator[ClusterDetails] {
	return a.internalList(ctx, request)
}

func (a *clustersImpl) internalList(ctx context.Context, request ListClustersRequest) (*ListClustersResponse, error) {
	path := "/api/2.1/clusters/list"
	err := a.client.Do(ctx, http.MethodGet, path, headers, queryParams, request, &out)
	return &out, err
}

func (a *clustersImpl) ChangeOwner(ctx context.Context, request ChangeClusterOwner) error {
	path := "/api/2.1/clusters/change-owner"
	err := a.client.Do(ctx, http.MethodPost, path, headers, queryParams, request, nil)
	return err
}

func (a *clustersImpl) Edit(ctx context.Context, request EditRequest) error {
	path := "/api/2.1/clusters/edit"
	err := a.client.Do(ctx, http.MethodPost, path, headers, queryParams, request, nil)
	return err
}

func (a *clustersImpl) GetPermissions(ctx context.Context, request GetClusterPermissionsRequest) (*ClusterPermissions, error) {
	path := fmt.Sprintf("/api/2.0/permissions/clusters/%v", request.ClusterId)
	err := a.client.Do(ctx, http.MethodGet, path, headers, queryParams, request, &out)
	return &out, err
}

type commandExecutionImpl struct{ client *client.DatabricksClient }

func (a *commandExecutionImpl) Execute(ctx context.Context, request Command) (*Created, error) {
	path := "/api/1.2/commands/execute"
	err := a.client.Do(ctx, http.MethodPost, path, headers, queryParams, request, &out)
	return &out, err
}
`),
		"service/compute/model.go": []byte(`package compute

import "github.com/databricks/databricks-sdk-go/service/iam"

type DeleteCluster struct {
	ClusterId string ` + "`json:\"cluster_id\"`" + `
}

type ChangeClusterOwner struct {
	ClusterId string ` + "`json:\"cluster_id\"`" + `
	OwnerFields
}

type OwnerFields struct {
	OwnerUsername string ` + "`json:\"owner_username\"`" + `
	State         State
}

type State string

type GetEvents struct {
	ClusterId string ` + "`json:\"cluster_id\"`" + `
}

type ListClustersRequest struct {
	PageToken string ` + "`json:\"-\" url:\"page_token,omitempty\"`" + `
}

type GetClusterPermissionsRequest struct {
	ClusterId string ` + "`json:\"-\" url:\"-\"`" + `
}

type Command struct {
	Command string ` + "`json:\"command,omitempty\"`" + `
}

type EditRequest = EditCluster

type EditCluster struct {
	ClusterId string       ` + "`json:\"cluster_id\"`" + `
	Spec      *ClusterSpec ` + "`json:\"spec,omitempty\"`" + `
	Internal  string       ` + "`json:\"-\" url:\"internal\"`" + `
	Rules     Rules        ` + "`json:\"rules,omitempty\"`" + `
}

type Rules []Rule

type Rule struct {
	Owner string ` + "`json:\"owner,omitempty\"`" + `
}

type ClusterSpec struct {
	Acl  []iam.AccessControlRequest ` + "`json:\"access_control_list,omitempty\"`" + `
	Next *ClusterSpec               ` + "`json:\"next,omitempty\"`" + `
}
`),
		"service/iam/model.go": []byte(`package iam

type DeleteAccountGroupRequest struct {
	Id string ` + "`json:\"-\" url:\"-\"`" + `
}

type AccessControlRequest struct {
	UserName string ` + "`json:\"user_name,omitempty\"`" + `
}
`),
		"service/iam/ext_impl.go": []byte(`package iam

type accountGroupsImpl struct{ client *client.DatabricksClient }

func (a *accountGroupsImpl) Delete(ctx context.Context, request DeleteAccountGroupRequest) error {
	path := fmt.Sprintf("/api/2.0/accounts/%v/scim/v2/Groups/%v", a.client.ConfiguredAccountID(), request.Id)
	err := a.client.Do(ctx, http.MethodDelete, path, headers, queryParams, request, nil)
	return err
}
`),
		"service/files/impl.go": []byte(`package files

type filesImpl struct{ client *client.DatabricksClient }

func (a *filesImpl) Upload(ctx context.Context, request UploadRequest) error {
	path := fmt.Sprintf("/api/2.0/fs/files%v", httpclient.EncodeMultiSegmentPathParameter(request.FilePath))
	err := a.client.Do(ctx, http.MethodPut, path, headers, queryParams, request.Contents, nil)
	return err
}

func (a *filesImpl) DataPlane(ctx context.Context) error {
	return a.client.ApiClient().Do(ctx, http.MethodPost, url)
}
`),
		// SharesAPI.List in ext_api.go wraps ListShares; the CLI calls List.
		"service/sharing/impl.go": []byte(`package sharing

type ListSharesRequest struct{}

type sharesImpl struct{ client *client.DatabricksClient }

func (a *sharesImpl) internalListShares(ctx context.Context, request ListSharesRequest) (*ListProviderSharesResponse, error) {
	path := "/api/2.1/unity-catalog/shares"
	err := a.client.Do(ctx, http.MethodGet, path, headers, queryParams, request, &out)
	return &out, err
}
`),
		"service/apps/impl.go": []byte(`package apps

type CreateAppDeploymentRequest struct {
	AppName string ` + "`json:\"-\" url:\"-\"`" + `
}

type appsImpl struct{ client *client.DatabricksClient }

func (a *appsImpl) Deploy(ctx context.Context, request CreateAppDeploymentRequest) (*AppDeployment, error) {
	path := fmt.Sprintf("/api/2.0/apps/%v/deployments", request.AppName)
	err := a.client.Do(ctx, http.MethodPost, path, headers, queryParams, request, &out)
	return &out, err
}
`),
		// An account service whose path does not carry the account ID.
		"service/networking/impl.go": []byte(`package networking

type GetEndpointRequest struct {
	Name string ` + "`json:\"-\" url:\"-\"`" + `
}

type endpointsImpl struct{ client *client.DatabricksClient }

func (a *endpointsImpl) GetEndpoint(ctx context.Context, request GetEndpointRequest) (*Endpoint, error) {
	path := fmt.Sprintf("/api/networking/v1/%v", request.Name)
	err := a.client.Do(ctx, http.MethodGet, path, headers, queryParams, request, &out)
	return &out, err
}
`),
		"service/files/model.go": []byte(`package files

import "io"

type UploadRequest struct {
	Contents io.ReadCloser ` + "`json:\"-\"`" + `
	FilePath string        ` + "`json:\"-\" url:\"-\"`" + `
}
`),
		"service/settings/impl.go": []byte(`package settings

type defaultNamespaceImpl struct{ client *client.DatabricksClient }

type GetDefaultNamespaceSettingRequest struct{}

func (a *defaultNamespaceImpl) Get(ctx context.Context, request GetDefaultNamespaceSettingRequest) (*DefaultNamespaceSetting, error) {
	path := "/api/2.0/settings/types/default_namespace_ws/names/default"
	err := a.client.Do(ctx, http.MethodGet, path, headers, queryParams, request, &out)
	return &out, err
}
`),
	}
	cli = sourceTree{
		"go.mod": []byte("module github.com/databricks/cli\n\nrequire (\n\tgithub.com/databricks/databricks-sdk-go v0.188.0 // Apache-2.0\n)\n"),
		"cmd/workspace/cmd.go": []byte(`package workspace

import (
	apps "github.com/databricks/cli/cmd/workspace/apps"
	clusters "github.com/databricks/cli/cmd/workspace/clusters"
	settings "github.com/databricks/cli/cmd/workspace/settings"
	shares "github.com/databricks/cli/cmd/workspace/shares"
)

func All() []*cobra.Command {
	var out []*cobra.Command
	out = append(out, apps.New())
	out = append(out, clusters.New())
	out = append(out, settings.New())
	out = append(out, shares.New())
	return out
}
`),
		// The CLI overloads apps deploy with a bundle deploy; the hand entry
		// takes the command over.
		"cmd/workspace/apps/apps.go": []byte(`package apps

func New() *cobra.Command {
	return &cobra.Command{Use: "apps"}
}

func newDeploy() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "deploy APP_NAME"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		_, err := w.Apps.Deploy(ctx, deployReq)
		return err
	}
	return cmd
}
`),
		"cmd/workspace/clusters/clusters.go": []byte(`package clusters

func New() *cobra.Command {
	cmd := &cobra.Command{Use: "clusters", Short: "Clusters"}
	cmd.AddCommand(newDelete())
	return cmd
}

func newDelete() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "delete CLUSTER_ID"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		names, err := w.Clusters.ClusterDetailsClusterNameToClusterIdMap(ctx, compute.ListClustersRequest{})
		_, err = w.Clusters.Delete(ctx, deleteReq)
		return err
	}
	return cmd
}

func newList() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "list"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		response := w.Clusters.List(ctx, listReq)
		return cmdio.RenderIterator(ctx, response)
	}
	return cmd
}

// A mutation followed by a status read keeps the mutation's tier.
func newEditAndList() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "edit-and-list"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		err := w.Clusters.Edit(ctx, editReq)
		response := w.Clusters.List(ctx, listReq)
		return cmdio.RenderIterator(ctx, response)
	}
	return cmd
}

// An unknown call next to a known read leaves the command unclassified.
func newUnknownField() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "unknown-field"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		err := w.NewService.Delete(ctx, req)
		response := w.Clusters.List(ctx, listReq)
		return cmdio.RenderIterator(ctx, response)
	}
	return cmd
}

func newHalf() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "half"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		err := w.Clusters.Mystery(ctx, req)
		response := w.Clusters.List(ctx, listReq)
		return cmdio.RenderIterator(ctx, response)
	}
	return cmd
}

func newExplode() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "explode"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		return w.Clusters.ExplodeAll(ctx)
	}
	return cmd
}
`),
		"cmd/workspace/clusters/overrides.go": []byte(`package clusters

func newChangeOwner() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "change-owner CLUSTER_ID OWNER_USERNAME"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		return w.Clusters.ChangeOwner(ctx, req)
	}
	return cmd
}

func newExecute() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "execute"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		_, err := w.CommandExecution.Execute(ctx, req)
		return err
	}
	return cmd
}
`),
		"cmd/workspace/shares/overrides.go": []byte(`package shares

func New() *cobra.Command {
	return &cobra.Command{Use: "shares"}
}

func newList() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "list"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		response := w.Shares.List(ctx, listReq)
		return cmdio.RenderIterator(ctx, response)
	}
	return cmd
}
`),
		"cmd/workspace/settings/settings.go": []byte(`package settings

import default_namespace "github.com/databricks/cli/cmd/workspace/default-namespace"

func New() *cobra.Command {
	cmd := &cobra.Command{Use: "settings"}
	cmd.AddCommand(default_namespace.New())
	return cmd
}
`),
		"cmd/workspace/default-namespace/default-namespace.go": []byte(`package default_namespace

func New() *cobra.Command {
	return &cobra.Command{Use: "default-namespace"}
}

func newGet() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "get"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		w := cmdctx.WorkspaceClient(ctx)
		response, err := w.Settings.DefaultNamespace().Get(ctx, getReq)
		return cmdio.Render(ctx, response)
	}
	return cmd
}
`),
		"cmd/account/cmd.go": []byte(`package account

import groups "github.com/databricks/cli/cmd/account/groups"

func New() *cobra.Command {
	cmd := &cobra.Command{Use: "account"}
	cmd.AddCommand(groups.New())
	return cmd
}
`),
		"cmd/account/groups/groups.go": []byte(`package groups

func New() *cobra.Command {
	return &cobra.Command{Use: "groups"}
}

func newDelete() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "delete ID"
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		a := cmdctx.AccountClient(ctx)
		return a.Groups.Delete(ctx, deleteReq)
	}
	return cmd
}
`),
	}
	return cli, sdk
}

func TestBuildDatabricksTable(t *testing.T) {
	cli, sdk := databricksFixtures()
	table, report, err := buildDatabricksTable(cli, sdk, "v1.21.0", "v0.188.0")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]databricksEntry{}
	for _, entry := range table.Routes {
		got[entry.Operation] = entry
	}
	want := map[string]databricksEntry{
		"compute.Clusters.Delete":          {Operation: "compute.Clusters.Delete", Client: "workspace", Method: "POST", Path: "/api/2.1/clusters/delete", Commands: []string{"clusters delete"}, Product: "compute", Access: "delete"},
		"compute.Clusters.Events":          {Operation: "compute.Clusters.Events", Client: "workspace", Method: "POST", Path: "/api/2.1/clusters/events", Product: "compute", Access: "read"},
		"compute.Clusters.GetDetails":      {Operation: "compute.Clusters.GetDetails", Client: "workspace", Method: "POST", Path: "/api/2.1/clusters/get-details", Product: "compute", Access: "write"},
		"compute.Clusters.List":            {Operation: "compute.Clusters.List", Client: "workspace", Method: "GET", Path: "/api/2.1/clusters/list", Commands: []string{"clusters list"}, Product: "compute", Access: "read"},
		"compute.Clusters.ChangeOwner":     {Operation: "compute.Clusters.ChangeOwner", Client: "workspace", Method: "POST", Path: "/api/2.1/clusters/change-owner", Commands: []string{"clusters change-owner"}, Product: "compute", Access: "admin", AdminFields: []string{"owner_username"}},
		"compute.Clusters.Edit":            {Operation: "compute.Clusters.Edit", Client: "workspace", Method: "POST", Path: "/api/2.1/clusters/edit", Commands: []string{"clusters edit-and-list"}, Product: "compute", Access: "admin", AdminFields: []string{"spec.access_control_list", "rules.owner"}},
		"compute.Clusters.GetPermissions":  {Operation: "compute.Clusters.GetPermissions", Client: "workspace", Method: "GET", Path: "/api/2.0/permissions/clusters/{cluster_id}", Product: "admin", Access: "read"},
		"compute.CommandExecution.Execute": {Operation: "compute.CommandExecution.Execute", Client: "workspace", Method: "POST", Path: "/api/1.2/commands/execute", Commands: []string{"clusters execute"}, Product: "execution", Access: "write"},
		"iam.AccountGroups.Delete":         {Operation: "iam.AccountGroups.Delete", Client: "account", Method: "DELETE", Path: "/api/2.0/accounts/{account_id}/scim/v2/Groups/{id}", Commands: []string{"account groups delete"}, Product: "admin", Access: "admin"},
		"sharing.Shares.ListShares":        {Operation: "sharing.Shares.ListShares", Client: "workspace", Method: "GET", Path: "/api/2.1/unity-catalog/shares", Commands: []string{"shares list"}, Product: "data", Access: "read"},
		"networking.Endpoints.GetEndpoint": {Operation: "networking.Endpoints.GetEndpoint", Client: "account", Method: "GET", Path: "/api/networking/v1/{name}", Product: "admin", Access: "read"},
		"files.Files.Upload":               {Operation: "files.Files.Upload", Client: "workspace", Method: "PUT", Path: "/api/2.0/fs/files{file_path+}", Product: "data", Access: "write"},
		"settings.DefaultNamespace.Get":    {Operation: "settings.DefaultNamespace.Get", Client: "workspace", Method: "GET", Path: "/api/2.0/settings/types/default_namespace_ws/names/default", Commands: []string{"settings default-namespace get"}, Product: "admin", Access: "read"},
		"apps.Apps.Deploy":                 {Operation: "apps.Apps.Deploy", Client: "workspace", Method: "POST", Path: "/api/2.0/apps/{app_name}/deployments", Product: "execution", Access: "write"},
	}
	for _, hand := range databricksHandCommands {
		want[hand.Operation] = hand
	}
	if !reflect.DeepEqual(got, want) {
		for key := range want {
			if !reflect.DeepEqual(got[key], want[key]) {
				t.Errorf("%s:\n got %+v\nwant %+v", key, got[key], want[key])
			}
		}
		for key := range got {
			if _, ok := want[key]; !ok {
				t.Errorf("unexpected %s", key)
			}
		}
	}
	text := strings.Join(report, "\n")
	for _, line := range []string{
		"| execution | 5 |",
		"`POST /api/2.1/clusters/events` compute.Clusters.Events ()",
		"`POST /api/2.1/clusters/edit` compute.Clusters.Edit (clusters edit-and-list): spec.access_control_list, rules.owner",
		"`clusters edit-and-list` calls compute.Clusters.Edit, compute.Clusters.List; kept compute.Clusters.Edit",
		"## POST routes whose path suggests a read (still write until reviewed) (1)",
		"`clusters explode` (w.Clusters.ExplodeAll)",
		"`clusters half` (w.Clusters.Mystery)",
		"`clusters unknown-field` (w.NewService.Delete)",
	} {
		if !strings.Contains(text, line) {
			t.Errorf("report lacks %q:\n%s", line, text)
		}
	}
}

// An owner field on an allowlisted POST read wins over the allowlist.
func TestBuildDatabricksTableAdminBeatsPostRead(t *testing.T) {
	cli, sdk := databricksFixtures()
	model := string(sdk["service/compute/model.go"])
	sdk["service/compute/model.go"] = []byte(strings.Replace(model, "type GetEvents struct {\n", "type GetEvents struct {\n\tOwner string `json:\"owner\"`\n", 1))
	table, _, err := buildDatabricksTable(cli, sdk, "v1.21.0", "v0.188.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range table.Routes {
		if entry.Operation == "compute.Clusters.Events" && (entry.Access != "admin" || !reflect.DeepEqual(entry.AdminFields, []string{"owner"})) {
			t.Fatalf("Events = %s %v, want admin [owner]", entry.Access, entry.AdminFields)
		}
	}
}

func TestBuildDatabricksTableIsDeterministic(t *testing.T) {
	cli, sdk := databricksFixtures()
	var previous []byte
	for range 5 {
		table, _, err := buildDatabricksTable(cli, sdk, "v1.21.0", "v0.188.0")
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeDatabricksTable(table)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && !bytes.Equal(previous, encoded) {
			t.Fatal("regenerating the table changed it")
		}
		previous = encoded
	}
}

func TestBuildDatabricksTableFailsOnUnmappedService(t *testing.T) {
	cli, sdk := databricksFixtures()
	sdk["service/brandnew/impl.go"] = []byte(`package brandnew

type thingsImpl struct{}

type CreateThing struct{}

func (a *thingsImpl) Create(ctx context.Context, request CreateThing) error {
	path := "/api/2.0/things"
	return a.client.Do(ctx, http.MethodPost, path, headers, queryParams, request, nil)
}
`)
	if _, _, err := buildDatabricksTable(cli, sdk, "v1.21.0", "v0.188.0"); err == nil || !strings.Contains(err.Error(), "brandnew.Things") {
		t.Fatalf("err = %v, want the unmapped service named", err)
	}
}

func TestBuildDatabricksTableRejectsUnparsableRoutes(t *testing.T) {
	for name, body := range map[string]string{
		"non-%v verb":      `path := fmt.Sprintf("/api/2.0/things/%s", request.Id)`,
		"unknown argument": `path := fmt.Sprintf("/api/2.0/things/%v", someID())`,
		"computed path":    `path := base + "/things"`,
	} {
		t.Run(name, func(t *testing.T) {
			cli, sdk := databricksFixtures()
			sdk["service/compute/impl.go"] = []byte(`package compute

type clustersImpl struct{}

type GetCluster struct{}

func (a *clustersImpl) Get(ctx context.Context, request GetCluster) error {
	` + body + `
	return a.client.Do(ctx, http.MethodGet, path, headers, queryParams, request, nil)
}
`)
			if _, _, err := buildDatabricksTable(cli, sdk, "v1.21.0", "v0.188.0"); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// A body type the SDK source does not declare would hide its fields (an
// owner, an ACL), so it fails generation instead of passing as a write.
func TestBuildDatabricksTableRejectsUnresolvedBodies(t *testing.T) {
	for name, model := range map[string]string{
		"missing type":   "type DeleteCluster struct{}\ntype GetEvents struct{}\ntype ListClustersRequest struct{}\ntype GetClusterPermissionsRequest struct{}\ntype Command struct{}\ntype EditRequest = EditCluster\ntype EditCluster struct{}\n",
		"missing nested": strings.Replace(string(databricksFixtureModel()), "Spec      *ClusterSpec", "Spec      *Unknown", 1),
	} {
		t.Run(name, func(t *testing.T) {
			cli, sdk := databricksFixtures()
			sdk["service/compute/model.go"] = []byte("package compute\n\n" + strings.TrimPrefix(model, "package compute\n"))
			if _, _, err := buildDatabricksTable(cli, sdk, "v1.21.0", "v0.188.0"); err == nil || !strings.Contains(err.Error(), "not declared") {
				t.Fatalf("err = %v, want an undeclared type", err)
			}
		})
	}
}

func databricksFixtureModel() []byte {
	_, sdk := databricksFixtures()
	return sdk["service/compute/model.go"]
}

func TestGoModRequire(t *testing.T) {
	cli, _ := databricksFixtures()
	if got, err := goModRequire(cli["go.mod"], databricksSDKModule); err != nil || got != "v0.188.0" {
		t.Fatalf("goModRequire = %q, %v", got, err)
	}
	if _, err := goModRequire([]byte("require github.com/databricks/databricks-sdk-go v0.0.0-2025-abcdef\n"), databricksSDKModule); err == nil {
		t.Fatal("want an error for a pseudo-version")
	}
	if _, err := goModRequire([]byte("module x\n"), databricksSDKModule); err == nil {
		t.Fatal("want an error when the SDK is missing")
	}
}

func TestSnakeCase(t *testing.T) {
	for name, want := range map[string]string{"ClusterPolicyId": "cluster_policy_id", "Id": "id", "WorkspaceID": "workspace_id", "FullNameArg": "full_name_arg", "Version": "version"} {
		if got := snakeCase(name); got != want {
			t.Errorf("snakeCase(%q) = %q, want %q", name, got, want)
		}
	}
}
