package managedobserve

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
)

func TestAuthorityHolderStartupAndSwitch(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"permissions":{"defaultMode":"bypassPermissions"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	inv := agentinventory.Inventory{Agents: []agentinventory.Agent{{ID: "claude_code", ConfigPath: "~/.claude"}}}
	enabled := true
	holder := &authorityHolder{enabled: func() bool { return enabled }}
	if _, ok := holder.Fact(); ok {
		t.Fatal("scan before startup")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		holder.run(ctx, &agentInventoryHolder{inventory: inv, present: true}, ready)
	}()
	<-ready
	cancel()
	<-done
	first, ok := holder.Fact()
	if !ok || len(first.Agents) != 1 || first.Hash == "" || first.Coverage.SkippedFiles != 0 || first.Agents[0].Permissions.DefaultMode == nil {
		t.Fatalf("startup report=%+v", first)
	}
	enabled = false
	if _, ok := holder.Fact(); ok {
		t.Fatal("disabled report")
	}
	enabled = true
	if _, ok := holder.Fact(); ok {
		t.Fatal("re-enable reused old scan before hourly tick")
	}
	holder.refresh(context.Background(), inv)
	if _, ok := holder.Fact(); !ok {
		t.Fatal("hourly refresh did not resume")
	}
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "off")
	holder.refresh(context.Background(), inv)
	if _, ok := holder.Fact(); ok {
		t.Fatal("local opt-out report")
	}
}

func TestAuthorityHolderScansOnPolicyRecovery(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "")
	var enabled atomic.Bool
	available := make(chan struct{}, 1)
	holder := &authorityHolder{enabled: enabled.Load, available: available}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); holder.run(ctx, &agentInventoryHolder{}, ready) }()
	<-ready
	if _, ok := holder.Fact(); ok {
		t.Fatal("scanned offline")
	}
	enabled.Store(true)
	available <- struct{}{}
	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := holder.Fact(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recovery waited for hourly tick")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}
