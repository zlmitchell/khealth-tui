package checks

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

func nodeHealthInput(kubelet string, mod func(*nodeinfo.Info)) []Finding {
	ni := &nodeinfo.Info{Node: "n1", Dist: "rke2", DataDir: "/var/lib/rancher/rke2", Settings: map[string]string{"cni": "canal"},
		KubeletFlags: map[string]string{}, Sysctl: map[string]string{"net.bridge.bridge-nf-call-iptables": "1", "fs.inotify.max_user_watches": "1048576"}, Hardening: map[string]string{}}
	mod(ni)
	snap := &k8s.Snapshot{Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: kubelet}}}}}
	return Evaluate(Input{Snap: snap, Nodes: map[string]*nodeinfo.Info{"n1": ni}, Cfg: config.Default(), Now: time.Now()})
}

func TestNodeHealthGaps(t *testing.T) {
	cases := []struct {
		name    string
		kubelet string
		mod     func(*nodeinfo.Info)
		sev     Severity
		substr  string
	}{
		{"ro /var", "v1.35.8", func(ni *nodeinfo.Info) { ni.ROMounts = []nodeinfo.ROMount{{Mountpoint: "/var", FSType: "xfs"}} }, SevCrit, "/var (xfs) is mounted read-only"},
		{"ro elsewhere", "v1.35.8", func(ni *nodeinfo.Info) { ni.ROMounts = []nodeinfo.ROMount{{Mountpoint: "/srv/archive", FSType: "ext4"}} }, SevInfo, "/srv/archive (ext4) is mounted read-only"},
		{"conntrack 85%", "v1.35.8", func(ni *nodeinfo.Info) { ni.ConntrackCount, ni.ConntrackMax = 850, 1000 }, SevWarn, "conntrack table 85% full"},
		{"conntrack full", "v1.35.8", func(ni *nodeinfo.Info) { ni.ConntrackCount, ni.ConntrackMax = 999, 1000 }, SevCrit, "conntrack table 99% full"},
		{"cgroup v1 on 1.35", "v1.35.8+rke2r1", func(ni *nodeinfo.Info) { ni.CgroupFS = "tmpfs" }, SevCrit, "since 1.35 the kubelet refuses to start on cgroup v1"},
		{"cgroup v1 on 1.34", "v1.34.3+rke2r1", func(ni *nodeinfo.Info) { ni.CgroupFS = "tmpfs" }, SevWarn, "upgrade blocker"},
		{"cgroup v1 allowed", "v1.35.8+rke2r1", func(ni *nodeinfo.Info) { ni.CgroupFS = "tmpfs"; ni.KubeletFlags["fail-cgroupv1"] = "false" }, SevWarn, "upgrade blocker"},
		{"br_netfilter missing", "v1.35.8", func(ni *nodeinfo.Info) { delete(ni.Sysctl, "net.bridge.bridge-nf-call-iptables") }, SevWarn, "br_netfilter is not loaded"},
		{"loopback resolver", "v1.35.8", func(ni *nodeinfo.Info) { ni.ResolvEtc = []string{"127.0.0.53"} }, SevWarn, "nameserver 127.0.0.53 (a local stub)"},
		{"vmxnet3 offload", "v1.35.8", func(ni *nodeinfo.Info) {
			ni.Offload, ni.UnderlayDriver = map[string]string{"flannel.1": "on"}, "vmxnet3"
		}, SevWarn, "flannel.1 has tx-checksum-ip-generic on over a vmxnet3 NIC"},
	}
	for _, c := range cases {
		if f := anyMessage(nodeHealthInput(c.kubelet, c.mod), c.sev, c.substr); f == nil {
			fs := nodeHealthInput(c.kubelet, c.mod)
			var got []string
			for _, x := range fs {
				got = append(got, x.Severity.String()+" "+x.Message)
			}
			t.Errorf("%s: missing %s %q in\n%s", c.name, c.sev, c.substr, strings.Join(got, "\n"))
		}
	}
	// the resolver the kubelet really uses: systemd-resolved's list is fine
	fs := nodeHealthInput("v1.35.8", func(ni *nodeinfo.Info) {
		ni.ResolvEtc, ni.ResolvResolved = []string{"127.0.0.53"}, []string{"10.0.0.1"}
		ni.KubeletFlags["resolv-conf"] = "/run/systemd/resolve/resolv.conf"
	})
	if f := anyMessage(fs, SevWarn, "a local stub"); f != nil {
		t.Errorf("kubelet already points at resolved's list: %s", f.Message)
	}
	// virtio NIC: offload is not the vmxnet3 bug
	fs = nodeHealthInput("v1.35.8", func(ni *nodeinfo.Info) { ni.Offload, ni.UnderlayDriver = map[string]string{"flannel.1": "on"}, "virtio_net" })
	if f := anyMessage(fs, SevWarn, "tx-checksum"); f != nil {
		t.Errorf("virtio: %s", f.Message)
	}
}

func TestKernelLogFindings(t *testing.T) {
	now := time.Now()
	at := now.Add(-time.Minute).Format("2006-01-02T15:04:05-0700")
	lines := []string{
		at + " n1 kernel: EXT4-fs error (device sdb1): ext4_lookup:1801: inode #2: comm kubelet: deleted inode referenced",
		at + " n1 kernel: INFO: task etcd:4242 blocked for more than 122 seconds.",
		at + " n1 kernel: watchdog: BUG: soft lockup - CPU#3 stuck for 23s! [containerd:999]",
		at + " n1 kernel: ixgbe 0000:01:00.0 eno1: NIC Link is Down",
		at + " n1 kernel: neighbour: arp_cache: neighbor table overflow!",
	}
	in := Input{Snap: &k8s.Snapshot{}, Cfg: config.Default(), Now: now, Logs: map[string]*logs.Summary{"n1": logs.Classify(lines, now)}}
	fs := Evaluate(in)
	for _, w := range []struct {
		sev    Severity
		substr string
	}{
		{SevCrit, "filesystem / block I/O errors"},
		{SevWarn, "tasks blocked in I/O"},
		{SevWarn, "CPU soft lockup"},
		{SevWarn, "network link went down"},
		{SevWarn, "neighbour (ARP) table overflow"},
	} {
		if findingWith(fs, w.sev, "node", w.substr) == nil {
			t.Errorf("missing %s %q", w.sev, w.substr)
		}
	}
}
