package rescue

import (
	"os/exec"
	"strings"
	"testing"
)

// TestScriptsParse renders every rescue script for each control-plane
// kind and role and has the local POSIX shell parse it (`sh -n`), so a
// quoting slip cannot reach a node. Skipped where there is no sh.
func TestScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on this host")
	}
	entries, err := scripts.ReadDir("scripts")
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"SNAP": "/var/lib/rancher/rke2/server/db/snapshots/etcd-snapshot-x", "S3": "1", "API": "1", "PROMOTE": "1",
		"JOIN": "https://10.0.0.1:9345", "OWNER": "etcd:etcd", "NAME": "cp-2", "PEER": "https://10.0.0.2:2380",
		"IMAGE": "registry.k8s.io/etcd:3.5.15-0", "INITIAL_CLUSTER": "cp-1=https://10.0.0.1:2380,cp-2=https://10.0.0.2:2380",
		"LOG": "/x/cluster-reset.log", "EXIT": "/x/cluster-reset.exit", "DIR": "/var/lib/etcd-backup", "ROLE": "target",
	}
	for _, kind := range []Kind{RKE2, K3s, Kubeadm} {
		p := New(kind, Node{Name: "cp-1", IP: "10.0.0.1"}, nil, vars["SNAP"], false)
		p.Target.Facts.Rescue = "/var/lib/rancher/rke2/server/etcd-rescue-x"
		for _, e := range entries {
			name := strings.TrimSuffix(e.Name(), ".sh")
			if name == "common" {
				continue
			}
			s := p.render(name, p.Target, vars)
			if strings.Contains(s, "__") {
				t.Errorf("%s/%s: unsubstituted placeholder", kind, name)
			}
			cmd := exec.Command(sh, "-n")
			cmd.Stdin = strings.NewReader(s)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s/%s: %v\n%s", kind, name, err, out)
			}
		}
	}
}
