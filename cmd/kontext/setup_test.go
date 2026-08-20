package main

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/setup"
)

func TestSetupCmdFlags(t *testing.T) {
	t.Setenv("KONTEXT_API_URL", "")
	cmd := setupCmd()

	token := cmd.Flags().Lookup("token")
	if token == nil || token.DefValue != "" {
		t.Fatalf("--token flag = %v", token)
	}

	cloudURL := cmd.Flags().Lookup("cloud-url")
	if cloudURL == nil {
		t.Fatal("setup command missing --cloud-url flag")
	}
	if cloudURL.DefValue != setup.DefaultCloudURL {
		t.Fatalf("--cloud-url default = %q, want %q", cloudURL.DefValue, setup.DefaultCloudURL)
	}
	if !cloudURL.Hidden {
		t.Fatal("--cloud-url must be hidden (staging/dev override only)")
	}

	uninstall := cmd.Flags().Lookup("uninstall")
	if uninstall == nil || uninstall.DefValue != "false" {
		t.Fatalf("--uninstall flag = %v", uninstall)
	}
}

func TestSetupCmdCloudURLDefaultsFromEnvironment(t *testing.T) {
	const stagingURL = "https://api.staging.kontext.security"
	t.Setenv("KONTEXT_API_URL", stagingURL)

	cloudURL := setupCmd().Flags().Lookup("cloud-url")
	if cloudURL == nil {
		t.Fatal("setup command missing --cloud-url flag")
	}
	if cloudURL.DefValue != stagingURL {
		t.Fatalf("--cloud-url default = %q, want %q", cloudURL.DefValue, stagingURL)
	}
}

func TestSetupCmdRegistered(t *testing.T) {
	// setup must be a visible top-level command — it is the self-serve
	// onboarding entrypoint printed in the dashboard.
	cmd := setupCmd()
	if cmd.Hidden {
		t.Fatal("setup command must not be hidden")
	}
	if cmd.Use != "setup" {
		t.Fatalf("Use = %q", cmd.Use)
	}
	if !strings.Contains(cmd.Long, "hooks for supported local agents") {
		t.Fatalf("setup long help is not agent-oriented:\n%s", cmd.Long)
	}
}

func TestSetupCmdSilencesUsageForRuntimeErrors(t *testing.T) {
	cmd := setupCmd()
	if !cmd.SilenceUsage {
		t.Fatal("setup runtime errors should not print command usage")
	}
	if !cmd.SilenceErrors {
		t.Fatal("setup runtime errors should be printed once by main")
	}
}
