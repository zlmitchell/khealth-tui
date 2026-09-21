package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The embedded example must always parse into Config and mention every
// top-level key, so it cannot drift from the struct.
func TestExampleConfigParses(t *testing.T) {
	cfg := Default()
	if err := yaml.Unmarshal([]byte(ExampleConfig), &cfg); err != nil {
		t.Fatalf("example config does not parse: %v", err)
	}
	for _, key := range []string{"kubeconfig:", "refresh:", "heavy_every:", "ssh:", "become:", "etcd:", "helm:", "logs:", "actions:", "thresholds:"} {
		if !strings.Contains(ExampleConfig, key) {
			t.Errorf("example config lacks %s", key)
		}
	}
	if cfg.SSH.Become != "auto" || cfg.Refresh.Seconds() != 30 {
		t.Errorf("example values not read: become=%q refresh=%s", cfg.SSH.Become, cfg.Refresh)
	}
}

func TestWriteExampleConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "config.yaml")
	got, err := WriteExampleConfig(target)
	if err != nil || got != target {
		t.Fatalf("write: %v %q", err, got)
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != ExampleConfig {
		t.Fatalf("content mismatch: %v", err)
	}
	if _, err := WriteExampleConfig(target); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second write must refuse: %v", err)
	}
	if p, err := DefaultConfigPath(); err != nil || !strings.HasSuffix(filepath.ToSlash(p), "/khealth/config.yaml") {
		t.Errorf("default path: %q %v", p, err)
	}
}

func TestPositionalBootstrapHost(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "khealth.yaml")
	if err := os.WriteFile(empty, []byte("refresh: 30s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load([]string{"--config", empty, "root@10.0.0.143", "--no-ssh", "10.0.0.144", "--bootstrap-out", "/tmp/x.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSH.User != "root" || len(cfg.Bootstrap.Hosts) != 2 || cfg.Bootstrap.Hosts[0] != "10.0.0.143" || cfg.Bootstrap.Hosts[1] != "10.0.0.144" || cfg.SSH.Enabled || cfg.Bootstrap.Out != "/tmp/x.yaml" {
		t.Errorf("user=%q hosts=%v ssh=%v out=%q", cfg.SSH.User, cfg.Bootstrap.Hosts, cfg.SSH.Enabled, cfg.Bootstrap.Out)
	}
	// user@host is an explicit user: it must win over the one remembered in
	// a reused context (see applySSHHint in cmd/khealth)
	if !cfg.Flags["ssh-user"] {
		t.Error("user@host did not mark ssh-user as given")
	}
	cfg, err = Load([]string{"--config", empty, "--bootstrap-kubeconfig", "ubuntu@cp-1,cp-2"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSH.User != "ubuntu" || len(cfg.Bootstrap.Hosts) != 2 || cfg.Bootstrap.Hosts[0] != "cp-1" || !cfg.Flags["ssh-user"] {
		t.Errorf("user=%q hosts=%v flags=%v", cfg.SSH.User, cfg.Bootstrap.Hosts, cfg.Flags)
	}
	// a bare host keeps the default (local login) user and does not claim it was chosen
	cfg, err = Load([]string{"--config", empty, "10.0.0.143"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Flags["ssh-user"] {
		t.Error("bare host marked ssh-user as given")
	}
}
