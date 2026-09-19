package distro

import (
	"strings"
	"testing"
)

func TestVocab(t *testing.T) {
	if v := For("rke2"); v.Server != "rke2-server" || v.ConfigFile != "/etc/rancher/rke2/config.yaml" || !strings.Contains(v.CloudProvider("vsphere"), "rancher-vsphere") || !strings.Contains(v.KubeletArg("fail-swap-on=false", "failSwapOn: false"), "kubelet-arg") {
		t.Errorf("rke2: %+v", v)
	}
	if v := For("kubeadm"); v.Server != "kubelet" || v.DataDir != "/var/lib/kubelet" || !strings.Contains(v.CertRenew, "kubeadm certs renew") || !strings.Contains(v.KubeletArg("fail-swap-on=false", "failSwapOn: false"), "failSwapOn: false") || !strings.Contains(v.CloudProvider("aws"), "aws cloud-controller-manager") {
		t.Errorf("kubeadm: %+v", v)
	}
	if v := For("eks"); v.Name != "kubernetes" || v.Label != "eks" || v.Restart(true) != "systemctl restart kubelet" {
		t.Errorf("generic: %+v", v)
	}
	if !IsRancher("k3s") || IsRancher("kubeadm") {
		t.Error("IsRancher")
	}
}
