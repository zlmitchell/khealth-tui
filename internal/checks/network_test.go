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

func netInput(nodes map[string]*nodeinfo.Info) Input {
	now := time.Date(2026, 9, 20, 15, 0, 0, 0, time.UTC)
	snap := &k8s.Snapshot{
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-1"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(-20 * time.Minute))}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-2"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(-30 * time.Hour))}}}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "rke2-canal-abc", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "canal"}}, Spec: corev1.PodSpec{NodeName: "cp-1"},
				Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "kube-flannel", RestartCount: 6, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", FinishedAt: metav1.NewTime(now.Add(-5 * time.Minute))}}}}}},
		},
		Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.0.10"}}},
	}
	return Input{Snap: snap, Nodes: nodes, Cfg: config.Default(), Now: now}
}

func findingsWith(fs []Finding, sub string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Area == "network" && strings.Contains(f.Message, sub) {
			out = append(out, f)
		}
	}
	return out
}

// TestNetworkFindings: the API-side history, the MTU rules and the probe
// combinations each produce the intended finding, and a healthy node none.
func TestNetworkFindings(t *testing.T) {
	link := func(name string, mtu int, state string) nodeinfo.Link {
		return nodeinfo.Link{Name: name, MTU: mtu, State: state}
	}
	cp1 := &nodeinfo.Info{Node: "cp-1", DefaultDev: "eth0", Links: []nodeinfo.Link{link("eth0", 1500, "UP"), link("flannel.1", 1500, "UNKNOWN"), link("cni0", 1450, "UP")},
		CNI: []nodeinfo.CNIConf{{Path: "/etc/cni/net.d/10-canal.conflist", MTU: 1400}}, Flannel: map[string]string{"mtu": "1450"},
		NetProbed: true, NetProbes: []nodeinfo.NetProbe{
			{Kind: "PING", Node: "cp-2", Target: "10.42.2.2", OK: false, Detail: "Destination Host Unreachable"},
			{Kind: "PING", Node: "cp-3", Target: "10.42.3.2", OK: true, Detail: "0.7"},
			{Kind: "DNS", Target: "10.42.3.5", OK: true, Detail: "10.43.0.1"},
			{Kind: "DNS", Target: "10.43.0.10", OK: false, Detail: "timed out"},
			{Kind: "TCP", Target: "10.43.0.1:443", OK: false, Detail: "connect timed out"},
		}}
	cp2 := &nodeinfo.Info{Node: "cp-2", DefaultDev: "eth0", Links: []nodeinfo.Link{link("eth0", 1500, "UP"), link("flannel.1", 1450, "DOWN")},
		NetProbed: true, NetProbes: []nodeinfo.NetProbe{
			{Kind: "PING", Node: "cp-1", Target: "10.42.1.2", OK: false, Detail: "unreachable"},
			{Kind: "PING", Node: "cp-3", Target: "10.42.3.2", OK: false, Detail: "unreachable"},
			{Kind: "DNS", Target: "10.42.3.5", OK: false, Detail: "timed out"},
			{Kind: "TCP", Target: "10.43.0.1:443", OK: true, Detail: "0.001"},
		}}
	fs := Evaluate(netInput(map[string]*nodeinfo.Info{"cp-1": cp1, "cp-2": cp2}))
	want := []struct {
		sub  string
		sev  Severity
		obj  string
		hint string
	}{
		{"network was unavailable until 20m ago", SevInfo, "cp-1", "CNI (re)started"},
		{"CNI pod rke2-canal-abc container kube-flannel restarted 6x, last 5m ago (Error)", SevWarn, "cp-1", "logs rke2-canal-abc -c kube-flannel -p"},
		{"flannel.1 MTU 1500 does not fit the underlay eth0 MTU 1500 minus the 50-byte vxlan", SevCrit, "cp-1", "set the CNI mtu to 1450"},
		{"cni0 MTU 1450 but 10-canal.conflist sets mtu 1400", SevWarn, "cp-1", "restart the CNI agent"},
		{"flannel.1 MTU differs across nodes: 1450 on cp-2; 1500 on cp-1", SevWarn, "cluster", "pin the CNI mtu"},
		{"flannel.1 (vxlan (flannel/canal)) is DOWN", SevCrit, "cp-2", "8472/udp"},
		{"pod-to-pod probe failed to cp-2 (10.42.2.2)", SevCrit, "cp-1", "between these two nodes"},
		{"cluster DNS service does not answer from this node but the CoreDNS pods do", SevCrit, "cp-1", "kube-proxy"},
		{"kubernetes service (ClusterIP) unreachable from this node", SevCrit, "cp-1", "kube-proxy on this node"},
		{"pod-to-pod probe failed to every other node", SevCrit, "cp-2", "8472/udp"},
	}
	for _, w := range want {
		got := findingsWith(fs, w.sub)
		if len(got) != 1 {
			t.Errorf("%q: %d findings", w.sub, len(got))
			for _, f := range fs {
				if f.Area == "network" {
					t.Logf("  have: %s %s %s", f.Severity, f.Object, f.Message)
				}
			}
			continue
		}
		if got[0].Severity != w.sev || got[0].Object != w.obj || !strings.Contains(got[0].Hint, w.hint) {
			t.Errorf("%q: sev=%v obj=%s hint=%q", w.sub, got[0].Severity, got[0].Object, got[0].Hint)
		}
	}
	if n := findingsWith(fs, "network was unavailable"); len(n) != 1 {
		t.Errorf("a transition 30 h ago must not be reported: %d", len(n))
	}
	// cp-2's DNS pod failure is explained by its dead overlay, not reported as a CoreDNS fault
	if n := findingsWith(fs, "CoreDNS pods answer no query"); len(n) != 0 {
		t.Errorf("DNS fault reported although the overlay is down: %v", n)
	}
	// a healthy node: nothing
	ok := &nodeinfo.Info{Node: "cp-3", DefaultDev: "eth0", Links: []nodeinfo.Link{link("eth0", 1500, "UP"), link("flannel.1", 1450, "UNKNOWN")}, NetProbed: true,
		NetProbes: []nodeinfo.NetProbe{{Kind: "PING", Node: "cp-1", Target: "10.42.1.2", OK: true}, {Kind: "DNS", Target: "10.43.0.10", OK: true}, {Kind: "TCP", Target: "10.43.0.1:443", OK: true}}}
	fs = Evaluate(netInput(map[string]*nodeinfo.Info{"cp-3": ok}))
	for _, f := range fs {
		if f.Area == "network" && f.Object == "cp-3" {
			t.Errorf("healthy node got a finding: %s", f.Message)
		}
	}
}
