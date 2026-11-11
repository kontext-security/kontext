package impactfeatures

import (
	"strings"
	"testing"
)

func TestSyntaxEvidence(t *testing.T) {
	cases := []struct {
		command, key string
		present      bool
	}{
		{"true # btrfs subvolume delete /home", "command=btrfs", false},
		{"printf '%s' 'rm -rf /etc'", "command=rm", false},
		{"false && rm -rf /etc", "context_command=and_rhs|rm", true},
		{"f() { rm -rf /etc; }", "context_command=definition|rm", true},
		{"echo \"$(rm -rf /etc)\"", "context_command=substitution|rm", true},
		{"bash -c 'rm -rf /etc'", "context_command=literal_script|rm", true},
		{"f() { bash -c 'rm -rf /etc'; }", "context_command=definition|rm", true},
		{"bash -c \"$PAYLOAD\"", "dynamic_script", true},
		{"cat <<'EOF'\n$(rm -rf /etc)\nEOF\n", "command=rm", false},
		{"cat <<EOF\n$(rm -rf /etc)\nEOF\n", "command=rm", true},
		{"ls --help > /etc/fstab", "redir_target_shape=absolute_path", true},
	}
	for _, c := range cases {
		r := Extract(c.command)
		if r.Status != "parsed" {
			t.Fatalf("parse %q: %s", c.command, r.Status)
		}
		if (r.Structure[c.key] > 0) != c.present {
			t.Errorf("%q key %s = %v", c.command, c.key, r.Structure[c.key])
		}
	}
}

func TestLimitsAndParseErrors(t *testing.T) {
	if r := Extract("if then"); r.Status != "syntax_error_text_only" || len(r.Characters) == 0 || r.Structure["parse_success"] != 0 {
		t.Fatal("syntax failure lost explicit status/text fallback", r.Status)
	}
	if r := Extract(strings.Repeat("x", MaxCommandBytes+1)); r.Status != "limit_exceeded" || len(r.Characters) != 0 {
		t.Fatal("oversize was partially scored")
	}
	r := Extract(strings.Repeat("( ", 300) + "echo ok" + strings.Repeat(" )", 300))
	if r.Status != "limit_exceeded" {
		t.Fatal("depth budget missing", r.Status)
	}
}

func TestTextAndCase(t *testing.T) {
	r := Extract("printf 'İstanbul 😀'\ntrue")
	if r.Status != "parsed" || r.Tokens["printf 'İstanbul"] != 0 || r.Tokens["printf 'istanbul"] == 0 {
		t.Fatal("shared Go Unicode lowercase/token contract", r.Tokens)
	}
	a := Extract("x -R /tmp/a")
	b := Extract("x -r /tmp/a")
	if a.Structure["cmd_option=x|-R"] == 0 || b.Structure["cmd_option=x|-r"] == 0 {
		t.Fatal("case-sensitive structure flags collapsed")
	}
}
