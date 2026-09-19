package k8s

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
)

const ctxSample = "apiVersion: v1\nkind: Config\nclusters:\n- name: lab\n  cluster:\n    server: https://10.0.0.5:6443\ncontexts:\n- name: lab\n  context:\n    cluster: lab\n    user: lab\ncurrent-context: lab\nusers:\n- name: lab\n  user:\n    token: abc\n"

func TestSSHHintRoundTrip(t *testing.T) {
	cfg, err := clientcmd.Load([]byte(ctxSample))
	if err != nil {
		t.Fatal(err)
	}
	SetSSHHint(cfg, "lab", SSHHint{User: "root", Key: "/home/z/.ssh/id_ed25519", Port: 22, Host: "10.0.0.5", Bootstrapped: "2026-09-19T00:00:00Z"})
	out, err := clientcmd.Write(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := clientcmd.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	h := GetSSHHint(back.Contexts["lab"])
	if h.User != "root" || h.Key != "/home/z/.ssh/id_ed25519" || h.Port != 22 || h.Host != "10.0.0.5" || h.Empty() {
		t.Errorf("hint lost through write/load: %+v\n%s", h, out)
	}
	// the file still loads as a normal kubeconfig and Contexts sees the hint
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".kube"), 0o700)
	p := filepath.Join(home, ".kube", "khealth-lab.yaml")
	_ = os.WriteFile(p, out, 0o600)
	if err := CheckKubeconfig(p, ""); err != nil {
		t.Fatalf("kubeconfig with extension does not load: %v", err)
	}
	list := Contexts(filepath.Join(home, "none.yaml"), "")
	if len(list) != 1 || list[0].Name != "lab" || list[0].File != p || list[0].SSH.User != "root" {
		t.Errorf("contexts: %+v", list)
	}
}
