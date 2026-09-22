package checks

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// A server changed address: config.yaml still pins node-ip to the old one
// and the other servers' server: still points at it.
func TestAddressChangeFindings(t *testing.T) {
	node := func(name string, settings map[string]string, addrs ...string) *nodeinfo.Info {
		return &nodeinfo.Info{Node: name, Dist: "rke2", ControlPlane: true, DataDir: "/var/lib/rancher/rke2", Addrs: addrs, Settings: settings,
			KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Hardening: map[string]string{}}
	}
	k8sNode := func(name, ip string) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}}}
	}
	in := Input{Snap: &k8s.Snapshot{Nodes: []corev1.Node{k8sNode("cp-1", "10.0.0.143"), k8sNode("cp-2", "10.0.0.235"), k8sNode("cp-3", "10.0.0.223")}}, Cfg: config.Default(), Now: time.Now(), SSHEnabled: true,
		Nodes: map[string]*nodeinfo.Info{
			"cp-1": node("cp-1", map[string]string{"node-ip": "10.0.0.143"}, "10.0.0.191", "fd00::1"),
			"cp-2": node("cp-2", map[string]string{"server": "https://10.0.0.143:9345"}, "10.0.0.235"),
			"cp-3": node("cp-3", map[string]string{"server": "https://10.0.0.100:9345"}, "10.0.0.223"), // a VIP
		}}
	fs := Evaluate(in)
	if f := findingWith(fs, SevCrit, "node", "config.yaml pins node-ip: 10.0.0.143 but the node holds 10.0.0.191"); f == nil || f.Object != "cp-1" || !strings.Contains(f.Hint, "set node-ip to 10.0.0.191") {
		t.Errorf("pinned node-ip: %+v", f)
	}
	if f := findingWith(fs, SevWarn, "node", "server: https://10.0.0.143:9345 points at the old address of cp-1, which now holds 10.0.0.191"); f == nil || f.Object != "cp-2" {
		t.Errorf("server: at the old address: %+v", f)
	}
	if f := findingWith(fs, SevInfo, "node", "server: https://10.0.0.100:9345 is no address of a known server node"); f == nil || f.Object != "cp-3" {
		t.Errorf("server: at a VIP: %+v", f)
	}
	// everything in place: nothing to say
	in.Nodes["cp-1"] = node("cp-1", map[string]string{"node-ip": "10.0.0.191"}, "10.0.0.191")
	in.Nodes["cp-2"] = node("cp-2", map[string]string{"server": "https://10.0.0.191:9345"}, "10.0.0.235")
	in.Snap.Nodes[0] = k8sNode("cp-1", "10.0.0.191")
	for _, f := range Evaluate(in) {
		if strings.Contains(f.Message, "node-ip") || strings.Contains(f.Message, "old address") {
			t.Errorf("unexpected: %s", f.Message)
		}
	}
	// a probe without addresses (older output) never second-guesses
	in.Nodes["cp-1"] = node("cp-1", map[string]string{"node-ip": "10.0.0.143"})
	for _, f := range Evaluate(in) {
		if strings.Contains(f.Message, "pins node-ip") {
			t.Errorf("finding without address facts: %s", f.Message)
		}
	}
}
