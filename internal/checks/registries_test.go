package checks

import (
	"strings"
	"testing"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// On upstream/kubeadm nodes containerd only reads certs.d/<registry>/hosts.toml
// when config.toml names the directory; hosts.toml without config_path is the
// mirror-not-applied case that registries.yaml-vs-certs.d catches on rke2.
func TestContainerdConfigPathFinding(t *testing.T) {
	hosts := []nodeinfo.ConfigFile{
		{Path: "/etc/containerd/certs.d/docker.io/hosts.toml", Content: "server = \"https://docker.io\"\n[host.\"https://harbor.corp\"]\n"},
	}
	cases := []struct {
		name     string
		dist     string
		config   string
		wantWarn bool
	}{
		{"kubeadm unset", "kubeadm", "41:      config_path = \"\"", true},
		{"kubeadm set", "kubeadm", "41:      config_path = \"/etc/containerd/certs.d\"", false},
		{"rke2 generates its own", "rke2", "41:      config_path = \"\"", false},
	}
	for _, tc := range cases {
		in := baseInput()
		in.Snap.Distribution = tc.dist
		in.Nodes["cp-1"] = &nodeinfo.Info{Node: "cp-1", Dist: tc.dist, ContainerdHosts: []string{"docker.io"},
			ContainerdConfig: append(hosts, nodeinfo.ConfigFile{Path: "/etc/containerd/config.toml", Content: tc.config})}
		var got bool
		for _, f := range Evaluate(in) {
			if strings.Contains(f.Message, "config.toml sets no config_path") {
				got = true
				if f.Object != "cp-1" || f.Area != "addons" || !strings.Contains(f.Hint, "restart containerd") {
					t.Errorf("%s: finding fields: %+v", tc.name, f)
				}
			}
		}
		if got != tc.wantWarn {
			t.Errorf("%s: config_path finding = %v, want %v", tc.name, got, tc.wantWarn)
		}
	}
}
