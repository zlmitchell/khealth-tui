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
	if p, err := DefaultConfigPath(); err != nil || !strings.HasSuffix(filepath.ToSlash(p), "k8s-health-tui/config.yaml") {
		t.Errorf("default path: %q %v", p, err)
	}
}
