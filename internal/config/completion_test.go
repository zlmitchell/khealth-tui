package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testFlagSet mirrors what Load registers closely enough to complete
// against. Complete() reads whatever FlagSet it is given, so these tests
// need no copy of the real flag list; TestCompleteKnownFlagNamesExist uses
// the one Load registers.
func testFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("khealth", flag.ContinueOnError)
	fs.Bool("no-ssh", false, "")
	fs.Bool("accept-new-host-keys", true, "")
	fs.String("become", "", "")
	fs.String("ssh-address", "", "")
	fs.String("kubeconfig", "", "")
	fs.String("export-dir", "", "")
	fs.String("context", "", "")
	return fs
}

func got(fs *flag.FlagSet, words ...string) []string {
	return Complete(fs, len(words), words)
}

func TestCompleteFlags(t *testing.T) {
	fs := testFlagSet()

	// a bool is offered bare, a value flag with the = that carries its value
	for _, c := range []struct{ cur, want string }{
		{"--no-s", "--no-ssh"},
		{"--beco", "--become="},
		{"--accept", "--accept-new-host-keys"},
	} {
		out := got(fs, c.cur)
		if len(out) != 1 || out[0] != c.want {
			t.Errorf("complete %q = %v, want [%s]", c.cur, out, c.want)
		}
	}
	// a bool must not be offered with =, or bash would complete a value
	// the flag package accepts only as -flag=x
	for _, s := range got(fs, "--no-s") {
		if strings.HasSuffix(s, "=") {
			t.Errorf("bool flag offered as %q", s)
		}
	}
}

func TestCompleteValues(t *testing.T) {
	fs := testFlagSet()

	// value after a space
	out := got(fs, "--become", "d")
	if strings.Join(out, ",") != "dzdo,doas" {
		t.Errorf("--become d = %v", out)
	}
	// the same value inline, which keeps the --flag= prefix on each candidate
	out = got(fs, "--become=d")
	if strings.Join(out, ",") != "--become=dzdo,--become=doas" {
		t.Errorf("--become=d = %v", out)
	}
	// booleans complete true/false only after =
	if out = got(fs, "--accept-new-host-keys="); strings.Join(out, ",") != "--accept-new-host-keys=true,--accept-new-host-keys=false" {
		t.Errorf("bool = %v", out)
	}
	// ... and never as a following word: -no-ssh true is not valid syntax,
	// so the word after it is a positional (a host), not a value
	for _, s := range got(fs, "--no-ssh", "tr") {
		if s == "true" {
			t.Errorf("bool completed a separate-word value: %v", s)
		}
	}
	// paths are handed back to the shell
	if out = got(fs, "--kubeconfig", ""); len(out) != 1 || out[0] != FilesSentinel {
		t.Errorf("--kubeconfig = %q, want the files sentinel", out)
	}
	if out = got(fs, "--export-dir", ""); len(out) != 1 || out[0] != DirsSentinel {
		t.Errorf("--export-dir = %q, want the dirs sentinel", out)
	}
	if out = got(fs, "--kubeconfig=/et"); len(out) != 1 || out[0] != FilesSentinel {
		t.Errorf("--kubeconfig=/et = %q, want the files sentinel", out)
	}
}

func TestCompleteContextsAndHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	t.Setenv("KUBECONFIG", "")
	// HOME does not hide the machine-wide known_hosts, and CI runners ship
	// one; point it at nothing so the assertions below are about the
	// fixtures only
	defer func(p string) { systemKnownHosts = p }(systemKnownHosts)
	systemKnownHosts = filepath.Join(home, "no-such-system-known-hosts")

	// a kubeconfig whose cluster and user names must NOT be offered
	kube := filepath.Join(home, ".kube")
	if err := os.MkdirAll(kube, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `apiVersion: v1
clusters:
- cluster: {server: https://1.2.3.4:6443}
  name: a-cluster
contexts:
- context: {cluster: a-cluster, user: a-user}
  name: prod
- context: {cluster: a-cluster, user: a-user}
  name: staging
users:
- name: a-user
`
	if err := os.WriteFile(filepath.Join(kube, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// the same host twice (one line per key type) and a multi-alias line:
	// both must collapse. The hashed entry cannot be read back.
	kh := "10.0.0.1 ssh-rsa AAAA\n10.0.0.1 ssh-ed25519 BBBB\ncp-1,10.0.0.2 ssh-rsa CCCC\n|1|hashed|= ssh-rsa DDDD\n"
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(kh), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := testFlagSet()
	if out := got(fs, "--context", ""); strings.Join(out, ",") != "prod,staging" {
		t.Errorf("contexts = %v, want [prod staging] (no cluster/user names)", out)
	}

	out := got(fs, "")
	if strings.Join(out, ",") != "10.0.0.1,10.0.0.2,cp-1" {
		t.Errorf("hosts = %v", out)
	}
	// the user@ part is kept, and only the host is matched
	if out = got(fs, "root@10.0.0.2"); strings.Join(out, ",") != "root@10.0.0.2" {
		t.Errorf("user@host = %v", out)
	}
	if out = got(fs, "root@"); strings.Join(out, ",") != "root@10.0.0.1,root@10.0.0.2,root@cp-1" {
		t.Errorf("user@ = %v", out)
	}
}

// Complete is handed the FlagSet Load itself parses with, so the offered
// flags cannot drift from the real ones - there is no second list. What
// this file does name by hand is which flags take a path or a fixed set of
// values, and those names can go stale when a flag is renamed.
func TestCompleteKnownFlagNamesExist(t *testing.T) {
	if _, err := Load([]string{}); err != nil {
		t.Fatal(err)
	}
	fs := loadedFlagSet
	if fs == nil {
		t.Fatal("Load did not record its FlagSet")
	}
	for _, m := range []map[string][]string{flagValues} {
		for name := range m {
			if fs.Lookup(name) == nil {
				t.Errorf("flagValues names -%s, which is not a flag", name)
			}
		}
	}
	for _, m := range []map[string]bool{pathFlags, dirFlags} {
		for name := range m {
			if fs.Lookup(name) == nil {
				t.Errorf("path/dir completion names -%s, which is not a flag", name)
			}
		}
	}
	// and the real flags do come through, including the new ones
	out := Complete(fs, 1, []string{"-"})
	if len(out) < 30 {
		t.Fatalf("only %d flags offered from the real FlagSet", len(out))
	}
	seen := map[string]bool{}
	for _, s := range out {
		seen[strings.TrimRight(strings.TrimLeft(s, "-"), "=")] = true
	}
	for _, name := range []string{"ssh-user", "become", "accept-new-host-keys", "completions", "install-completions"} {
		if !seen[name] {
			t.Errorf("flag -%s is not offered by completion", name)
		}
	}
}
