package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/installation"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/profile"
)

func TestWhoami(t *testing.T) {
	for _, tc := range []struct {
		name, email string
		status      int
		asJSON      bool
		mdm         bool
		wantError   string
	}{
		{name: "managed workspace", status: 200, mdm: true},
		{name: "personal", email: "person@example.com", status: 200},
		{name: "workspace", status: 200},
		{name: "personal JSON", email: "person@example.com", status: 200, asJSON: true},
		{name: "workspace JSON", status: 200, asJSON: true},
		{name: "unauthorized", status: 401, wantError: "install token was rejected — it may be revoked or mistyped; create a new one in the dashboard under Settings → API keys"},
		{name: "forbidden", status: 403, wantError: "install token was rejected — it may be revoked or mistyped; create a new one in the dashboard under Settings → API keys"},
		{name: "bound elsewhere", status: 409, wantError: "this setup command was already used on another Mac; copy a fresh one from Get started in the dashboard"},
		{name: "expired", status: 410, wantError: "this setup command has expired; copy a fresh one from Get started in the dashboard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv(profile.EnvRoot, "")
			if _, err := profile.Create("work"); err != nil {
				t.Fatal(err)
			}
			if err := profile.SetActive("work"); err != nil {
				t.Fatal(err)
			}
			identityPath, err := profile.ActiveInstallationPath()
			if err != nil {
				t.Fatal(err)
			}
			identity, err := installation.EnsureFile(identityPath)
			if err != nil {
				t.Fatal(err)
			}
			identityBefore, err := os.ReadFile(identityPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(installation.EnvPath, identityPath)
			t.Setenv("WHOAMI_TEST_TOKEN", "test-key")
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/v1/authorization-ledger/ping" || r.URL.Query().Get("installation_id") != identity.InstallationID || r.Header.Get("Authorization") != "Bearer test-key" {
					t.Errorf("unexpected ping: %s", r.URL)
				}
				w.WriteHeader(tc.status)
				if tc.status == 200 {
					json.NewEncoder(w).Encode(map[string]any{"organization_id": "org_test", "organization_name": "Test Workspace", "user_email": tc.email})
				}
			}))
			defer server.Close()
			configPath, err := profile.ActiveManagedConfigPath()
			if err != nil {
				t.Fatal(err)
			}
			// Keep config resolution independent of any real MDM installation on the test host.
			t.Setenv(managedconfig.EnvPath, configPath)
			cfg := managedconfig.Config{Version: managedconfig.Version, CloudURL: server.URL, AllowHTTPLoopback: true, Mode: managedconfig.ModeRemote, Agent: managedconfig.Agent, Credentials: managedconfig.Credentials{InstallTokenRef: managedconfig.TokenRef{Source: "env", Name: "WHOAMI_TEST_TOKEN"}}}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if tc.mdm {
				t.Setenv("KONTEXT_INSTALL_TOKEN", "")
				cfg.Credentials.InstallTokenRef = managedconfig.TokenRef{Source: "env", Name: "KONTEXT_INSTALL_TOKEN"}
				previousLoad, previousFile := whoamiLoadConfig, whoamiInstallTokenFile
				whoamiLoadConfig = func() (managedconfig.LoadedConfig, error) {
					return managedconfig.LoadedConfig{Config: cfg, Path: configPath, Scope: managedconfig.ScopeSystem}, nil
				}
				whoamiInstallTokenFile = filepath.Join(t.TempDir(), "install-token")
				t.Cleanup(func() { whoamiLoadConfig, whoamiInstallTokenFile = previousLoad, previousFile })
				if err := os.WriteFile(whoamiInstallTokenFile, []byte("test-key\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := newRootCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			args := []string{"whoami"}
			if tc.asJSON {
				args = append(args, "--json")
			}
			cmd.SetArgs(args)
			err = cmd.Execute()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error = %v, want %s", err, tc.wantError)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if tc.asJSON {
					var got map[string]any
					if err := json.Unmarshal(out.Bytes(), &got); err != nil {
						t.Fatal(err)
					}
					var person any
					if tc.email != "" {
						person = tc.email
					}
					if len(got) != 3 || got["workspace"] != "Test Workspace" || got["organization_id"] != "org_test" || got["person"] != person {
						t.Fatalf("JSON = %s", out.String())
					}
				} else {
					person := tc.email
					if person == "" {
						person = "none (workspace key)"
					}
					if want := "workspace: Test Workspace\nperson: " + person + "\n"; out.String() != want {
						t.Fatalf("output = %q, want %q", out.String(), want)
					}
				}
			}
			if calls != 1 {
				t.Fatalf("ping calls = %d", calls)
			}
			identityAfter, _ := os.ReadFile(identityPath)
			configAfter, _ := os.ReadFile(configPath)
			if !bytes.Equal(identityBefore, identityAfter) || !bytes.Equal(raw, configAfter) {
				t.Fatal("whoami changed local identity or config")
			}
		})
	}
}
