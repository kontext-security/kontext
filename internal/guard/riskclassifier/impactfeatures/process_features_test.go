package impactfeatures

import "testing"

func TestProcessFactContexts(t *testing.T) {
	cases := []struct {
		command, key string
		want         bool
	}{
		{"pkill -x daemon-zeta", "process/executed/utility=pkill", true},
		{"pkill -x daemonabcdefghijkl", "process/executed/pattern=linux_comm_literal_over15", true},
		{"pkill -f daemonabcdefghijkl", "process/executed/pattern=linux_comm_literal_over15", false},
		{"kill --signal=0 4811", "process/executed/purpose=probe", true},
		{"pkill -fx '^worker.*'", "process/executed/match=full_command", true},
		{"kill -- -1", "process/executed/pid_scope=cohort", true},
		{"pkill -0 -x daemon-zeta", "process/executed/purpose=probe", true},
		{"pgrep -f 'worker.*queue'", "process/executed/purpose=inspect", true},
		{"pidwait -x cargo", "process/executed/purpose=wait", true},
		{"pkill -KILL -u builder", "process/executed/selector=user", true},
		{"pkill -USR1 -x daemon", "process/executed/selector=real_user", false},
		{"pkill -u \"$ACCOUNT\"", "process/executed/selector_value=dynamic", true},
		{"pkill -f '^/opt/worker.*'", "process/executed/pattern=any_span", true},
		{"kill -9 -- -1", "process/executed/pid_scope=cohort", true},
		{"sudo -u builder env -u DEBUG command pkill -x daemon-zeta", "process/executed/utility=pkill", true},
		{"command -v pkill", "process/executed/utility=pkill", false},
		{"sudo -l pkill -x daemon-zeta", "process/executed/utility=pkill", false},
		{"printf '%s' 'pkill -x daemon-zeta'", "process/executed/utility=pkill", false},
		{"f(){ pkill -x daemon-zeta; }; declare -f f", "process/definition/utility=pkill", true},
		{"false && pkill -x daemon-zeta", "process/unreachable/utility=pkill", true},
		{"true || pkill -x daemon-zeta", "process/executed/utility=pkill", false},
		{"[[ 1 -eq 2 ]] && pkill -x daemon-zeta", "process/unreachable/utility=pkill", true},
		{"if ((0)); then pkill -x daemon-zeta; fi", "process/unreachable/utility=pkill", true},
		{"if true; then echo ok; else pkill -x daemon-zeta; fi", "process/unreachable/utility=pkill", true},
		{"while false; do pkill -x daemon-zeta; done", "process/unreachable/utility=pkill", true},
		{"bash -n -c 'pkill -x daemon-zeta'", "process/syntax_only/utility=pkill", true},
		{"bash -n +n -c 'pkill -x daemon-zeta'", "process/executed/utility=pkill", true},
		{"bash -o noexec -c 'pkill -x daemon-zeta'", "process/syntax_only/utility=pkill", true},
		{"bash -ni -c 'pkill -x daemon-zeta'", "process/executed/utility=pkill", true},
		{"bash -n -c \"$(pkill -x daemon-zeta)\"", "process/executed/utility=pkill", true},
		{"bash -n -c 'echo ok' > \"$(pkill -x daemon-zeta)\"", "process/executed/utility=pkill", true},
		{"bash -n <<'EOF'\npkill -x daemon-zeta\nEOF\n", "process/syntax_only/utility=pkill", true},
		{"bash <<'EOF'\npkill -x daemon-zeta\nEOF\n", "process/executed/utility=pkill", true},
		{"bash script.sh <<'EOF'\npkill -x daemon-zeta\nEOF\n", "process/executed/utility=pkill", false},
		{"bash -n <<EOF\n$(pkill -x daemon-zeta)\nEOF\n", "process/executed/utility=pkill", true},
		{"eval 'pkill -x daemon-zeta'", "process/executed/utility=pkill", true},
	}
	for _, c := range cases {
		r := Extract(c.command)
		if r.Status != "parsed" {
			t.Fatalf("parse %q: %s", c.command, r.Status)
		}
		if got := r.Structure[c.key] > 0; got != c.want {
			t.Errorf("%q key %s = %v, want %v", c.command, c.key, got, c.want)
		}
	}
}

func TestGuardEvidenceIsConservative(t *testing.T) {
	for _, command := range []string{
		"[[ 0 ]] && pkill -x daemon-zeta",
		"[[ 1==2 ]] && pkill -x daemon-zeta",
		"[[ 10 < 2 ]] && pkill -x daemon-zeta",
		"[[ -0 == 0 ]] || pkill -x daemon-zeta",
		"test -0 == 0 || pkill -x daemon-zeta",
		"((08)) || pkill -x daemon-zeta",
		"true > /does/not/exist || pkill -x daemon-zeta",
		"true(){ return 1; }; true || pkill -x daemon-zeta",
		"false(){ return 0; }; false && pkill -x daemon-zeta",
	} {
		f := Extract(command)
		if f.Structure["process/unreachable/utility=pkill"] > 0 {
			t.Errorf("false unreachable evidence for %q", command)
		}
	}
}
