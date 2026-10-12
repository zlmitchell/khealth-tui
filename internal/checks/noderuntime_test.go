package checks

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

func TestNodeRuntimeGaps(t *testing.T) {
	cases := []struct {
		name   string
		mod    func(*nodeinfo.Info)
		sev    Severity
		substr string
	}{
		{"busy disk", func(ni *nodeinfo.Info) {
			ni.Mounts = []nodeinfo.Mount{{Filesystem: "/dev/mapper/rhel-var", Mountpoint: "/var"}}
			ni.DiskBusy = []nodeinfo.DiskBusy{{Name: "rhel-var", UtilPct: 97, AwaitMs: 12, IOPS: 800}}
		}, SevWarn, "disk rhel-var (/var) busy 97%"},
		{"slow disk", func(ni *nodeinfo.Info) {
			ni.DiskBusy = []nodeinfo.DiskBusy{{Name: "vda", UtilPct: 40, AwaitMs: 120, IOPS: 50}}
		}, SevWarn, "average 120 ms per I/O"},
		{"nic errors", func(ni *nodeinfo.Info) { ni.NICDev, ni.NICGrowth = "eno1", map[string]int64{"rx_crc_errors": 17} }, SevWarn, "rx_crc_errors +17"},
		{"link flap", func(ni *nodeinfo.Info) { ni.NICDev, ni.NICGrowth = "eno1", map[string]int64{"carrier_changes": 2} }, SevWarn, "lost and regained its link 1 time(s)"},
		{"bond slave down", func(ni *nodeinfo.Info) {
			ni.BondSlaves = []nodeinfo.BondSlave{{Bond: "bond0", Slave: "eno2", Status: "down"}}
		}, SevWarn, "bond bond0 slave eno2 is down"},
		{"arp table", func(ni *nodeinfo.Info) { ni.Neigh, ni.GCThresh3 = 900, 1024 }, SevWarn, "ARP table holds 900 entries"},
		{"ipam leak", func(ni *nodeinfo.Info) { ni.IPAMFiles = map[string]int{"cbr0": 120} }, SevWarn, "holds 120 allocations for 0 pods"},
		{"ipam full", func(ni *nodeinfo.Info) { ni.IPAMFiles = map[string]int{"cbr0": 240} }, SevCrit, "240 of 254 pod IPs allocated"},
		{"runtime hung", func(ni *nodeinfo.Info) { ni.RuntimeProbed, ni.RuntimeRC = true, 124 }, SevCrit, "container runtime does not answer"},
		{"leaked sandboxes", func(ni *nodeinfo.Info) { ni.RuntimeProbed, ni.NotReadySandboxes = true, 300 }, SevWarn, "300 NotReady pod sandboxes"},
		{"avc on etcd", func(ni *nodeinfo.Info) {
			ni.Preflight.AVCs = []nodeinfo.AVCDeny{{Count: 4, Last: time.Now().Add(-time.Minute), Comm: "etcd", SType: "container_t", TType: "var_lib_t", Class: "dir"}}
		}, SevCrit, "SELinux denied container/Kubernetes access"},
		{"avc other", func(ni *nodeinfo.Info) {
			ni.Preflight.AVCs = []nodeinfo.AVCDeny{{Count: 1, Comm: "cat", SType: "container_t", TType: "admin_home_t", Class: "file"}}
		}, SevWarn, "cat (container_t -> admin_home_t file) x1"},
	}
	for _, c := range cases {
		if anyMessage(nodeHealthInput("v1.35.8", c.mod), c.sev, c.substr) == nil {
			t.Errorf("%s: missing %s %q", c.name, c.sev, c.substr)
		}
	}
	// AVCs that are not about containers are not reported
	fs := nodeHealthInput("v1.35.8", func(ni *nodeinfo.Info) {
		ni.Preflight.AVCs = []nodeinfo.AVCDeny{{Count: 3, Comm: "httpd", SType: "httpd_t", TType: "user_home_t", Class: "file"}}
	})
	if anyMessage(fs, SevWarn, "SELinux denied") != nil {
		t.Error("a host httpd denial is not a Kubernetes finding")
	}
}

func TestDiskDelta(t *testing.T) {
	prev := nodeinfo.Parse("n1", "h", "===DISK1\n100.0\nvda 1000 500 2000 1000 4000\ndm-0 0 0 10 10 10\ndmname dm-0 rhel-var\n===END\n", time.Now())
	cur := nodeinfo.Parse("n1", "h", "===DISK1\n101.0\nvda 1100 600 2200 1400 4950\ndm-0 0 0 10 10 10\ndmname dm-0 rhel-var\n===END\n", time.Now())
	cur.DeltasFromPrev(prev)
	if len(cur.DiskBusy) != 2 || cur.DiskBusy[0].Name != "vda" || cur.DiskBusy[0].UtilPct != 95 || cur.DiskBusy[0].IOPS != 300 || cur.DiskBusy[1].Name != "rhel-var" {
		t.Errorf("disk delta: %+v", cur.DiskBusy)
	}
	if got := cur.DiskBusy[0].AwaitMs; got < 1.66 || got > 1.67 { // (100+400) ms / 300 I/Os
		t.Errorf("await %v", got)
	}
}

func TestEventGaps(t *testing.T) {
	now := time.Now()
	recent := metav1.NewTime(now.Add(-10 * time.Minute))
	long := metav1.NewTime(now.Add(-20 * time.Minute))
	ev := func(reason, host, msg string) corev1.Event {
		return corev1.Event{Reason: reason, Message: msg, Source: corev1.EventSource{Host: host}, LastTimestamp: recent, InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: host}}
	}
	s := &k8s.Snapshot{
		Events: []corev1.Event{
			ev("ImageGCFailed", "w-1", "failed to garbage collect required amount of images"),
			ev("DNSConfigForming", "w-1", "Nameserver limits were exceeded, some nameservers have been omitted, the applied nameserver line is: 10.0.0.1 10.0.0.2 10.0.0.3"),
			ev("FailedCreatePodSandBox", "w-2", "plugin type=\"host-local\" failed (add): failed to allocate for range 0: no IP addresses available in range set"),
		},
		Nodes:             []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "dead"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown, LastTransitionTime: long}}}}},
		Pods:              []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "pg-0", DeletionTimestamp: &recent}, Spec: corev1.PodSpec{NodeName: "dead"}}},
		VolumeAttachments: []storagev1.VolumeAttachment{{Spec: storagev1.VolumeAttachmentSpec{NodeName: "dead"}, Status: storagev1.VolumeAttachmentStatus{Attached: true}}},
	}
	for i := 0; i < 4; i++ {
		s.Pods = append(s.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "e" + string(rune('a'+i)), CreationTimestamp: recent}, Spec: corev1.PodSpec{NodeName: "w-3"}, Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"}})
	}
	fs := Evaluate(Input{Snap: s, Cfg: config.Default(), Now: now})
	for _, w := range []struct {
		sev    Severity
		substr string
	}{
		{SevWarn, "the kubelet could not free disk space"},
		{SevWarn, "trims the resolver config"},
		{SevCrit, "pod sandboxes fail for lack of IPs"},
		{SevWarn, "4 pods evicted from the node in the last hour"},
		{SevWarn, "1 pod(s) stuck Terminating there and volumes still attached"},
	} {
		if anyMessage(fs, w.sev, w.substr) == nil {
			t.Errorf("missing %s %q", w.sev, w.substr)
		}
	}
}
