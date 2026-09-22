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

func TestSnapshotConfigMapFindings(t *testing.T) {
	etcdNode := func(name string) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"node-role.kubernetes.io/etcd": "true"}}}
	}
	server := func(name string, settings map[string]string) *nodeinfo.Info {
		return &nodeinfo.Info{Node: name, Dist: "rke2", ControlPlane: true, Settings: settings, KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Hardening: map[string]string{}}
	}
	records := func(node string, n int) []k8s.EtcdSnapshotRecord {
		var out []k8s.EtcdSnapshotRecord
		for i := 0; i < n; i++ {
			out = append(out, k8s.EtcdSnapshotRecord{Name: node + "-" + string(rune('a'+i)), Node: node, Status: "successful", Created: time.Now()})
		}
		return out
	}
	base := func() Input {
		snap := &k8s.Snapshot{Nodes: []corev1.Node{etcdNode("cp-1"), etcdNode("cp-2"), etcdNode("cp-3")}}
		return Input{Snap: snap, Cfg: config.Default(), Now: time.Now(), SSHEnabled: true, Nodes: map[string]*nodeinfo.Info{
			"cp-1": server("cp-1", map[string]string{"etcd-snapshot-retention": "20"}), "cp-2": server("cp-2", map[string]string{}), "cp-3": server("cp-3", map[string]string{}),
		}}
	}
	find := func(fs []Finding) *Finding {
		for i := range fs {
			if fs[i].Area == "etcd" && strings.Contains(fs[i].Message, "snapshot records") {
				return &fs[i]
			}
		}
		return nil
	}

	// retention too large: 3 servers x 20 = 60 records at 14 KiB each fills the map
	in := base()
	in.Snap.RKE2Snapshots = append(append(records("cp-1", 20), records("cp-2", 20)...), records("cp-3", 20)...)
	in.Snap.SnapshotCM = &k8s.SnapshotConfigMap{Name: "rke2-etcd-snapshots", Entries: 60, Bytes: 60 * 14 * 1024}
	f := find(Evaluate(in))
	if f == nil || f.Severity != SevWarn || !strings.Contains(f.Message, "the retention is too large for 3 servers") || !strings.Contains(f.Hint, "set etcd-snapshot-retention to 17 or less") {
		t.Errorf("retention too large: %+v", f)
	}
	// 90%: critical
	in.Snap.SnapshotCM.Bytes = 60 * 16 * 1024
	if f := find(Evaluate(in)); f == nil || f.Severity != SevCrit || !strings.Contains(f.Message, "must have at most 1048576 bytes") {
		t.Errorf("nearly full: %+v", f)
	}

	// piling up: a server keeps far more than retention allows, and a
	// removed server's records are still there - reported below 70% too
	in = base()
	in.Nodes["cp-1"].Settings["etcd-snapshot-retention"] = "5"
	in.Snap.RKE2Snapshots = append(append(records("cp-1", 5), records("cp-2", 19)...), records("cp-old", 8)...)
	in.Snap.SnapshotCM = &k8s.SnapshotConfigMap{Name: "rke2-etcd-snapshots", Entries: 32, Bytes: 32 * 6 * 1024}
	f = find(Evaluate(in))
	if f == nil || f.Severity != SevWarn || !strings.Contains(f.Message, "the cleanup is not happening") || !strings.Contains(f.Message, "cp-2 (19, retention allows 5)") || !strings.Contains(f.Message, "cp-old (8)") || !strings.Contains(f.Hint, "rke2 etcd-snapshot prune") {
		t.Errorf("piling up: %+v", f)
	}

	// steady state well under the ceiling: nothing to say
	in = base()
	in.Snap.RKE2Snapshots = append(append(records("cp-1", 5), records("cp-2", 5)...), records("cp-3", 5)...)
	in.Snap.SnapshotCM = &k8s.SnapshotConfigMap{Name: "rke2-etcd-snapshots", Entries: 15, Bytes: 15 * 6 * 1024}
	if f := find(Evaluate(in)); f != nil {
		t.Errorf("healthy map reported: %+v", f)
	}
	// no configmap (records in CRs only): nothing to say
	in.Snap.SnapshotCM = nil
	if f := find(Evaluate(in)); f != nil {
		t.Errorf("no configmap reported: %+v", f)
	}
}
