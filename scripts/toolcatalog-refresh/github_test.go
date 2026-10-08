package main

import (
	"reflect"
	"testing"
)

func TestGitHubProduct(t *testing.T) {
	for name, want := range map[string]string{
		"actions_run_trigger":       "actions",
		"get_latest_release":        "releases",
		"list_tags":                 "releases",
		"merge_pull_request":        "pull_requests",
		"update_issue_state":        "issues",
		"create_repository_ruleset": "repository",
		"get_repository_tree":       "code",
		"push_files":                "code",
		"get_me":                    "users",
	} {
		if got := githubProduct(name); got != want {
			t.Errorf("githubProduct(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestMergeVariantsHoldsAToolToEveryVariant(t *testing.T) {
	merged := mergeVariants([]githubVariant{
		{required: []string{"owner", "repo"}, properties: map[string]string{"owner": "string", "repo": "string"}, hint: "read", canonical: "a"},
		{required: []string{"owner"}, properties: map[string]string{"owner": "string", "reason": "string"}, hint: "", canonical: "b"},
	})
	if !reflect.DeepEqual(merged.required, []string{"owner"}) {
		t.Errorf("required = %v, want only fields every variant requires", merged.required)
	}
	if len(merged.properties) != 3 {
		t.Errorf("properties = %v, want every variant's fields", merged.properties)
	}
	if merged.hint != "write" {
		t.Errorf("hint = %q, want write: a variant without annotations vouches for nothing", merged.hint)
	}
	single := mergeVariants([]githubVariant{{properties: map[string]string{}, hint: "", canonical: "c"}})
	if single.hint != "" {
		t.Errorf("single variant hint = %q, want empty", single.hint)
	}
}

func TestMarkRemovedReportsEachRemovalOnce(t *testing.T) {
	tools := []githubTool{{Name: "get_me"}, {Name: "old_tool"}}
	upstream := map[string]githubSnapshot{"get_me": {}}

	if got := markRemoved(tools, upstream); len(got) != 1 || got[0] != "`old_tool`" {
		t.Fatalf("first run removed = %v, want [`old_tool`]", got)
	}
	if !tools[1].Removed || tools[0].Removed {
		t.Fatalf("Removed flags = %v, %v; want false, true", tools[0].Removed, tools[1].Removed)
	}
	if got := markRemoved(tools, upstream); len(got) != 0 {
		t.Fatalf("second run removed = %v, want none", got)
	}
}
