package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate keeps Load away from the developer's real config files and
// environment: a fresh HOME / XDG_CONFIG_HOME, an empty working directory
// and none of the KHT_* variables.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData"))
	t.Setenv("KHT_SSH_PASSWORD", "")
	t.Setenv("KHT_BECOME_PASSWORD", "")
	t.Setenv("USER", "")
	t.Setenv("USERNAME", "")
	t.Chdir(t.TempDir())
	return home
}

func TestLoadDefaults(t *testing.T) {
	isolate(t)
	cfg, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	def := Default()
	if cfg.Refresh != def.Refresh || cfg.HeavyEvery != 6 || !cfg.SSH.Enabled || cfg.SSH.Port != 22 || cfg.SSH.Become != "auto" || !cfg.SSH.Nice || !cfg.SSH.Backoff || cfg.SSH.Concurrency != 8 {
		t.Errorf("defaults not applied: %+v", cfg.SSH)
	}
	if !cfg.Perf.WatchCache || !cfg.Perf.Protobuf || cfg.Perf.DeniedTTL != 10*time.Minute || cfg.Helm.Timeout != 15*time.Second || cfg.Logs.Lines != 400 || cfg.Logs.Since != "-24h" || !cfg.Actions.Enabled || cfg.Thresholds.DiskCritPct != 90 {
		t.Errorf("defaults: %+v", cfg)
	}
	if cfg.SSH.User != "" || cfg.Diag || cfg.Bootstrap.Hosts != nil {
		t.Errorf("unexpected values: user=%q diag=%v bootstrap=%+v", cfg.SSH.User, cfg.Diag, cfg.Bootstrap)
	}
}

func TestLoadFlags(t *testing.T) {
	home := isolate(t)
	args := []string{
		"--kubeconfig", "~/.kube/prod.yaml", "--context", "prod", "-n", "web", "--refresh", "2s",
		"--ssh-user", "ops", "--ssh-key", "~/.ssh/ops", "--ssh-port", "2222", "--ssh-password", "pw", "--ask-pass", "--ssh-address", "Hostname",
		"--bastion", "jump@bastion:22", "--ssh-nodes", " cp-1, cp-2 ,,w-1", "--no-sudo", "--become", "dzdo", "--insecure-host-key",
		"--helm-updates=false", "--read-only", "--diag", "--perf-log", "~/perf.jsonl", "--pprof", "127.0.0.1:6060", "--no-nice", "--no-backoff",
		"--no-watch-cache", "--no-protobuf", "--bootstrap-kubeconfig", "10.0.0.11, 10.0.0.12,", "--bootstrap-out", "~/kc.yaml", "--bootstrap-name", "prod",
	}
	cfg, err := Load(args)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kubeconfig != filepath.Join(home, ".kube", "prod.yaml") || cfg.Context != "prod" || cfg.Namespace != "web" {
		t.Errorf("cluster flags: %q %q %q", cfg.Kubeconfig, cfg.Context, cfg.Namespace)
	}
	if cfg.Refresh != 5*time.Second {
		t.Errorf("refresh floor: %s", cfg.Refresh)
	}
	s := cfg.SSH
	if s.User != "ops" || s.Key != filepath.Join(home, ".ssh", "ops") || s.Port != 2222 || s.Password != "pw" || !s.AskPass || s.Address != "Hostname" || s.Bastion != "jump@bastion:22" {
		t.Errorf("ssh flags: %+v", s)
	}
	if strings.Join(s.Nodes, ",") != "cp-1,cp-2,w-1" {
		t.Errorf("ssh-nodes: %v", s.Nodes)
	}
	// --no-sudo wins over --become
	if s.Sudo || s.Become != "none" || s.StrictHostKey || s.Nice || s.Backoff {
		t.Errorf("ssh toggles: %+v", s)
	}
	if cfg.Helm.CheckUpdates || cfg.Actions.Enabled || !cfg.Diag {
		t.Errorf("helm/actions/diag: %v %v %v", cfg.Helm.CheckUpdates, cfg.Actions.Enabled, cfg.Diag)
	}
	if cfg.Perf.Log != filepath.Join(home, "perf.jsonl") || cfg.Perf.Pprof != "127.0.0.1:6060" || cfg.Perf.WatchCache || cfg.Perf.Protobuf {
		t.Errorf("perf: %+v", cfg.Perf)
	}
	if strings.Join(cfg.Bootstrap.Hosts, ",") != "10.0.0.11,10.0.0.12" || cfg.Bootstrap.Out != filepath.Join(home, "kc.yaml") || cfg.Bootstrap.Name != "prod" {
		t.Errorf("bootstrap: %+v", cfg.Bootstrap)
	}
	// the flag parser's own errors come back
	if _, err := Load([]string{"--no-such-flag"}); err == nil {
		t.Error("unknown flag must fail")
	}
	if _, err := Load([]string{"--refresh", "soon"}); err == nil {
		t.Error("bad duration must fail")
	}
}

func TestLoadConfigFile(t *testing.T) {
	home := isolate(t)
	file := filepath.Join(t.TempDir(), "cfg.yaml")
	_ = os.WriteFile(file, []byte("refresh: 45s\nheavy_every: 0\nssh:\n  user: fileuser\n  become: SUDO \n  concurrency: 0\n  known_hosts: ~/kh\nlogs:\n  lines: -1\n  since: \"\"\nhelm:\n  timeout: 0s\nthresholds:\n  disk_warn_pct: 70\n"), 0o600)
	cfg, err := Load([]string{"--config", file, "--ssh-port", "2200"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Refresh != 45*time.Second || cfg.SSH.User != "fileuser" || cfg.SSH.Port != 2200 || cfg.Thresholds.DiskWarnPct != 70 || cfg.Thresholds.DiskCritPct != 90 {
		t.Errorf("file + flag merge: %+v", cfg)
	}
	// normalization of bad values
	if cfg.HeavyEvery != 1 || cfg.SSH.Become != "sudo" || cfg.SSH.Concurrency != 1 || cfg.Logs.Lines != 400 || cfg.Logs.Since != "-24h" || cfg.Helm.Timeout != 15*time.Second || cfg.SSH.KnownHosts != filepath.Join(home, "kh") {
		t.Errorf("normalized: heavy=%d become=%q conc=%d logs=%+v helm=%s kh=%q", cfg.HeavyEvery, cfg.SSH.Become, cfg.SSH.Concurrency, cfg.Logs, cfg.Helm.Timeout, cfg.SSH.KnownHosts)
	}
	// flags beat the file even for booleans
	cfg, _ = Load([]string{"--config", file, "--no-ssh", "--ssh-user", "flaguser"})
	if cfg.SSH.Enabled || cfg.SSH.User != "flaguser" {
		t.Errorf("flag precedence: %+v", cfg.SSH)
	}
	// an explicit file must exist and parse
	if _, err := Load([]string{"--config", filepath.Join(t.TempDir(), "missing.yaml")}); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("missing explicit file: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(bad, []byte("ssh: [not a map"), 0o600)
	if _, err := Load([]string{"--config", bad}); err == nil || !strings.Contains(err.Error(), "parse config") {
		t.Errorf("unparsable file: %v", err)
	}
	// an invalid become value is rejected
	_ = os.WriteFile(bad, []byte("ssh:\n  become: pkexec\n"), 0o600)
	if _, err := Load([]string{"--config", bad}); err == nil || !strings.Contains(err.Error(), `ssh.become: "pkexec" is not`) {
		t.Errorf("bad become: %v", err)
	}
	for _, b := range []string{"auto", "sudo", "dzdo", "doas", "none"} {
		if cfg, err := Load([]string{"--become", b}); err != nil || cfg.SSH.Become != b {
			t.Errorf("become %s: %v %q", b, err, cfg.SSH.Become)
		}
	}
}

func TestLoadFindsConfigFile(t *testing.T) {
	home := isolate(t)
	// nothing anywhere: defaults
	if cfg, _ := Load(nil); cfg.Refresh != 30*time.Second {
		t.Errorf("no file: %s", cfg.Refresh)
	}
	// the user-level file
	userCfg := filepath.Join(home, ".config", "khealth", "config.yaml")
	_ = os.MkdirAll(filepath.Dir(userCfg), 0o700)
	_ = os.WriteFile(userCfg, []byte("refresh: 50s\n"), 0o600)
	if cfg, err := Load(nil); err != nil || cfg.Refresh != 50*time.Second {
		t.Errorf("user config: %v %s", err, cfg.Refresh)
	}
	// a file in the working directory wins
	_ = os.WriteFile("khealth.yaml", []byte("refresh: 60s\n"), 0o600)
	if cfg, _ := Load(nil); cfg.Refresh != 60*time.Second {
		t.Errorf("khealth.yaml: %s", cfg.Refresh)
	}
	// the pre-1.0 name is still read, after khealth.yaml
	_ = os.Remove("khealth.yaml")
	_ = os.WriteFile("k8s-health-tui.yaml", []byte("refresh: 70s\n"), 0o600)
	if cfg, _ := Load(nil); cfg.Refresh != 70*time.Second {
		t.Errorf("k8s-health-tui.yaml: %s", cfg.Refresh)
	}
	// a directory of that name is not a config file
	_ = os.Remove("k8s-health-tui.yaml")
	_ = os.Mkdir("khealth.yaml", 0o700)
	if got := findConfigFile(); got != userCfg {
		t.Errorf("directory skipped: %q", got)
	}
	// an unreadable implicit file is ignored; an explicit one is not
	if _, err := Load([]string{"--config", filepath.Join(home, "nope.yaml")}); err == nil {
		t.Error("explicit missing file")
	}
}

func TestLoadEnvironment(t *testing.T) {
	isolate(t)
	t.Setenv("KHT_SSH_PASSWORD", "envpw")
	t.Setenv("KHT_BECOME_PASSWORD", "envbecome")
	t.Setenv("USER", "")
	t.Setenv("USERNAME", "winuser")
	cfg, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSH.Password != "envpw" || cfg.SSH.BecomePassword != "envbecome" || cfg.SSH.User != "winuser" {
		t.Errorf("env: %+v", cfg.SSH)
	}
	t.Setenv("USER", "unixuser")
	cfg, _ = Load([]string{"--ssh-password", "flagpw"})
	if cfg.SSH.Password != "flagpw" || cfg.SSH.User != "unixuser" {
		t.Errorf("flag over env / USER first: %+v", cfg.SSH)
	}
}

func TestExpand(t *testing.T) {
	home := isolate(t)
	if expand("~/x") != filepath.Join(home, "x") || expand("/abs") != "/abs" || expand("") != "" || expand("rel/~") != "rel/~" {
		t.Errorf("expand: %q %q", expand("~/x"), expand("rel/~"))
	}
	if expand("~") != home {
		t.Errorf("bare tilde: %q", expand("~"))
	}
}

func TestWriteExampleConfigDefaultPath(t *testing.T) {
	home := isolate(t)
	got, err := WriteExampleConfig("")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := DefaultConfigPath()
	if got != want || !strings.HasPrefix(got, home) {
		t.Errorf("default path: %q want %q", got, want)
	}
	if got2, err := WriteExampleConfig("~/custom/config.yaml"); err != nil || got2 != filepath.Join(home, "custom", "config.yaml") {
		t.Errorf("tilde path: %v %q", err, got2)
	}
}

// The flags that print and exit are exercised in a child process: the test
// binary re-runs itself with KHT_TEST_LOAD_ARGS set and Load must exit 0
// after printing.
func TestExitingFlags(t *testing.T) {
	if args := os.Getenv("KHT_TEST_LOAD_ARGS"); args != "" {
		_, _ = Load(strings.Split(args, " "))
		os.Exit(3) // Load should have exited itself
	}
	isolate(t)
	target := filepath.Join(t.TempDir(), "init.yaml")
	cases := []struct{ args, want string }{
		{"--version", "khealth dev"},
		{"--print-config", "refresh:"},
		{"--init-config --config " + target, "wrote " + target},
	}
	for _, c := range cases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestExitingFlags$")
		cmd.Env = append(os.Environ(), "KHT_TEST_LOAD_ARGS="+c.args)
		out, err := cmd.Output()
		if err != nil || !strings.Contains(string(out), c.want) {
			t.Errorf("%s: err=%v out=%q", c.args, err, out)
		}
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != ExampleConfig {
		t.Errorf("init-config did not write the example: %v", err)
	}
}
