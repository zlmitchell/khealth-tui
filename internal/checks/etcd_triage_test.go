package checks

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

var now = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

func node(name string, ready bool, ip string) corev1.Node {
	st := corev1.ConditionFalse
	if ready {
		st = corev1.ConditionTrue
	}
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}},
		Status: corev1.NodeStatus{
			Addresses:  []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: st, LastHeartbeatTime: metav1.NewTime(now.Add(-3 * time.Minute))}},
		},
	}
}

func member(id, name, ip string) etcd.Member {
	return etcd.Member{ID: id, Name: name + "-abcd1234", PeerURLs: []string{"https://" + ip + ":2380"}, ClientURLs: []string{"https://" + ip + ":2379"}}
}

func status(id, leader string, term, index uint64) etcd.EndpointStatus {
	return etcd.EndpointStatus{MemberID: id, Leader: leader, RaftTerm: term, RaftIndex: index, Version: "3.5.16"}
}

func baseInput() Input {
	snap := &k8s.Snapshot{Distribution: "rke2", Nodes: []corev1.Node{node("cp-1", true, "10.0.0.1"), node("cp-2", true, "10.0.0.2"), node("cp-3", true, "10.0.0.3")}}
	return Input{Snap: snap, Nodes: map[string]*nodeinfo.Info{}, Etcd: map[string]*etcd.Probe{}, Logs: map[string]*logs.Summary{}, SSHEnabled: true, Cfg: config.Default(), Now: now}
}

func healthyExec() *etcd.Probe {
	return &etcd.Probe{
		EtcdctlVia: "kubectl exec etcd-cp-1",
		Members:    []etcd.Member{member("a1", "cp-1", "10.0.0.1"), member("b2", "cp-2", "10.0.0.2"), member("c3", "cp-3", "10.0.0.3")},
		Statuses:   []etcd.EndpointStatus{status("a1", "a1", 14, 50000), status("b2", "a1", 14, 50000), status("c3", "a1", 14, 50000)},
		EndpointHealth: []etcd.EndpointHealth{
			{Endpoint: "https://10.0.0.1:2379", Healthy: true},
			{Endpoint: "https://10.0.0.2:2379", Healthy: true},
			{Endpoint: "https://10.0.0.3:2379", Healthy: true},
		},
	}
}

func etcdFindings(in Input) []Finding {
	var out []Finding
	for _, f := range Evaluate(in) {
		if f.Area == "etcd" {
			out = append(out, f)
		}
	}
	return out
}

func findObj(fs []Finding, obj string) *Finding {
	for i := range fs {
		if fs[i].Object == obj {
			return &fs[i]
		}
	}
	return nil
}

func joined(f *Finding) string { return f.Message + "\n" + strings.Join(f.Steps, "\n") }

func TestTriageHealthyClusterIsQuiet(t *testing.T) {
	in := baseInput()
	in.EtcdExec = healthyExec()
	for _, f := range etcdFindings(in) {
		if len(f.Steps) > 0 {
			t.Errorf("unexpected triage finding: %s", f.Message)
		}
	}
}

func TestTriageNodeOffline(t *testing.T) {
	in := baseInput()
	in.Snap.Nodes[2] = node("cp-3", false, "10.0.0.3")
	x := healthyExec()
	x.EndpointHealth[2] = etcd.EndpointHealth{Endpoint: "https://10.0.0.3:2379", Healthy: false, Error: "context deadline exceeded"}
	x.Statuses = x.Statuses[:2]
	in.EtcdExec = x
	in.Nodes["cp-3"] = &nodeinfo.Info{Node: "cp-3", Err: errors.New("dial tcp 10.0.0.3:22: i/o timeout")}

	fs := etcdFindings(in)
	f := findObj(fs, "cp-3")
	if f == nil || f.Severity != SevCrit || !strings.HasPrefix(f.Message, "node offline") {
		t.Fatalf("want node offline finding, got %+v", fs)
	}
	txt := joined(f)
	for _, want := range []string{"quorum: 2/3 members healthy (need 2), leader cp-1-abcd1234 term 14", "etcdctl member remove c3", "kubectl delete node cp-3", "kubelet last reported 3m"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "QUORUM LOST") {
		t.Errorf("quorum is intact with 2/3")
	}
	// the generic per-endpoint finding must not duplicate it
	for _, g := range fs {
		if strings.HasPrefix(g.Message, "endpoint unhealthy") {
			t.Errorf("generic finding not suppressed: %s", g.Message)
		}
	}
}

func TestTriageCrashLoopWithClusterIDMismatch(t *testing.T) {
	in := baseInput()
	x := healthyExec()
	x.EndpointHealth[1] = etcd.EndpointHealth{Endpoint: "https://10.0.0.2:2379", Healthy: false, Error: "connection refused"}
	in.EtcdExec = x
	in.Nodes["cp-2"] = &nodeinfo.Info{Node: "cp-2", Services: []nodeinfo.Service{{Name: "rke2-server", Active: "active", Sub: "running"}}}
	in.Logs["cp-2"] = &logs.Summary{ByName: map[string]int{"cluster-id": 3}}
	in.Snap.Pods = []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-cp-2", Namespace: "kube-system", Labels: map[string]string{"component": "etcd"}},
		Spec:       corev1.PodSpec{NodeName: "cp-2", Containers: []corev1.Container{{Name: "etcd"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "etcd", RestartCount: 7,
			State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, FinishedAt: metav1.NewTime(now.Add(-time.Minute))}},
		}}},
	}}

	f := findObj(etcdFindings(in), "cp-2")
	if f == nil || !strings.Contains(f.Message, "etcd container is CrashLoopBackOff (7 restarts)") {
		t.Fatalf("want crash-loop finding, got %+v", f)
	}
	txt := joined(f)
	for _, want := range []string{"cluster ID mismatch", "etcdctl member remove b2", "mv /var/lib/rancher/rke2/server/db/etcd", "systemctl stop rke2-server"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
}

func TestTriageSupervisorDown(t *testing.T) {
	in := baseInput()
	x := healthyExec()
	x.EndpointHealth[0] = etcd.EndpointHealth{Endpoint: "https://10.0.0.1:2379", Healthy: false, Error: "connection refused"}
	in.EtcdExec = x
	in.Nodes["cp-1"] = &nodeinfo.Info{Node: "cp-1", Services: []nodeinfo.Service{{Name: "rke2-server", Active: "failed", Sub: "failed"}}}
	in.Logs["cp-1"] = &logs.Summary{ByName: map[string]int{"disk-full": 2}}
	f := findObj(etcdFindings(in), "cp-1")
	if f == nil || !strings.Contains(f.Message, "rke2-server is failed/failed") {
		t.Fatalf("want supervisor finding, got %+v", f)
	}
	if txt := joined(f); !strings.Contains(txt, "filesystem full") || !strings.Contains(txt, "systemctl restart rke2-server") {
		t.Errorf("steps:\n%s", txt)
	}
}

func TestTriageStaleMemberAndLag(t *testing.T) {
	in := baseInput()
	x := healthyExec()
	x.Members = append(x.Members, member("d4", "old-cp", "10.0.0.9"))
	x.Statuses[2] = status("c3", "a1", 14, 40000) // 10000 behind
	in.EtcdExec = x
	fs := etcdFindings(in)
	if f := findObj(fs, "old-cp-abcd1234"); f == nil || !strings.Contains(f.Hint, "member remove d4") {
		t.Errorf("stale member not reported: %+v", fs)
	}
	if f := findObj(fs, "cp-3"); f == nil || !strings.Contains(f.Message, "10000 raft entries behind") {
		t.Errorf("lag not reported: %+v", fs)
	}
}

// TestTriageClusterDownPicksLastLeader is the power-outage case: the API is
// down, nothing answers etcdctl, and only the on-disk logs say who led last.
func TestTriageClusterDownPicksLastLeader(t *testing.T) {
	in := baseInput()
	in.Snap.Nodes = nil // apiserver unreachable
	in.Snap.Errors = []string{"nodes: dial tcp: connection refused"}
	ev := func(term uint64, leader string, at time.Time) etcd.LeaderEvent {
		return etcd.LeaderEvent{Term: term, Leader: leader, Time: at}
	}
	t0 := now.Add(-2 * time.Hour)
	// cp-2 was leader at term 41, then cp-3 took over at term 42 (cp-1's log missed it: it went down first)
	in.Etcd["cp-1"] = &etcd.Probe{Node: "cp-1", Dist: "rke2", LocalMemberID: "a1", Health: &etcd.Health{Healthy: false, Reason: "connection refused"},
		LeaderEvents: []etcd.LeaderEvent{ev(41, "b2", t0)},
		Raft:         &etcd.RaftOnDisk{SnapTerm: 41, SnapIndex: 90000, WALIndex: 95000, WALLastWrite: now.Add(-90 * time.Minute)}}
	in.Etcd["cp-2"] = &etcd.Probe{Node: "cp-2", Dist: "rke2", LocalMemberID: "b2", Health: &etcd.Health{Healthy: false, Reason: "connection refused"},
		LeaderEvents: []etcd.LeaderEvent{ev(41, "b2", t0), ev(42, "c3", t0.Add(30*time.Minute))},
		Raft:         &etcd.RaftOnDisk{SnapTerm: 42, SnapIndex: 100000, WALIndex: 100000, WALLastWrite: now.Add(-70 * time.Minute)}}
	in.Etcd["cp-3"] = &etcd.Probe{Node: "cp-3", Dist: "rke2", LocalMemberID: "c3", Health: &etcd.Health{Healthy: false, Reason: "connection refused"},
		LeaderEvents: []etcd.LeaderEvent{ev(41, "b2", t0), ev(42, "c3", t0.Add(30*time.Minute))},
		Raft:         &etcd.RaftOnDisk{SnapTerm: 42, SnapIndex: 100000, WALIndex: 100000, WALLastWrite: now.Add(-65 * time.Minute)},
		SnapshotDirs: []etcd.SnapshotDir{{Path: "/var/lib/rancher/rke2/server/db/snapshots", Files: []etcd.SnapshotFile{{Name: "etcd-snapshot-cp-3-1758100000", ModTime: now.Add(-3 * time.Hour)}}}}}
	for i, n := range []string{"cp-1", "cp-2", "cp-3"} {
		in.Nodes[n] = &nodeinfo.Info{Node: n, Host: fmt.Sprintf("10.0.0.%d", i+1), Services: []nodeinfo.Service{{Name: "rke2-server", Active: "active", Sub: "running"}}}
	}

	fs := etcdFindings(in)
	f := findObj(fs, "cluster")
	if f == nil || f.Severity != SevCrit {
		t.Fatalf("want cluster finding, got %+v", fs)
	}
	if !strings.Contains(f.Message, "etcd quorum lost: 0/3 members healthy; last known leader cp-3 (term 42)") {
		t.Errorf("message: %s", f.Message)
	}
	txt := joined(f)
	for _, want := range []string{
		"1. cp-3: leader at term 42",
		"2. cp-2: leader at term 41",
		"3. cp-1: never seen as leader",
		"note: cp-1's log stops at term 41 (it went down before cp-3's last election)",
		"on EVERY other server first (cp-1 (10.0.0.1), cp-2 (10.0.0.2)): systemctl stop rke2-server",
		"Then on cp-3: systemctl stop rke2-server; rke2 server --cluster-reset",
		"take a fresh snapshot: rke2 etcd-snapshot save",
		"rm -rf /var/lib/rancher/rke2/server/db; systemctl start rke2-server",
		"--cluster-reset-restore-path=/var/lib/rancher/rke2/server/db/snapshots/etcd-snapshot-cp-3-1758100000 (on cp-3, 3h",
		"Do NOT run cluster-reset on more than one node",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	// no per-node CRITs without a node-specific cause: the cluster finding covers them
	for _, g := range fs {
		if g.Object != "cluster" && g.Severity == SevCrit {
			t.Errorf("redundant per-node finding: %s", g.Message)
		}
	}
	// order: ranking, stop the others, reset on the target, start target, rejoin the others
	order := []string{"1. cp-3", "on EVERY other server first (", "rke2 server --cluster-reset", "systemctl start rke2-server on cp-3", "rm -rf /var/lib/rancher/rke2/server/db"}
	for i := 1; i < len(order); i++ {
		if strings.Index(txt, order[i-1]) > strings.Index(txt, order[i]) {
			t.Errorf("%q should precede %q:\n%s", order[i-1], order[i], txt)
		}
	}
}

// With a member list but every member down, the ranking still works and the
// stale-member check does not fire for nodes that are merely unreachable.
func TestTriageClusterDownWithMemberList(t *testing.T) {
	in := baseInput()
	x := healthyExec()
	for i := range x.EndpointHealth {
		x.EndpointHealth[i].Healthy = false
		x.EndpointHealth[i].Error = "connection refused"
	}
	x.Statuses = nil
	in.EtcdExec = x
	in.Etcd["cp-2"] = &etcd.Probe{Node: "cp-2", Dist: "rke2", LocalMemberID: "b2", LeaderEvents: []etcd.LeaderEvent{{Term: 9, Leader: "b2", Time: now.Add(-time.Hour)}}}
	fs := etcdFindings(in)
	f := findObj(fs, "cluster")
	if f == nil || !strings.Contains(f.Message, "last known leader cp-2 (term 9)") {
		t.Fatalf("cluster finding: %+v", fs)
	}
	for _, g := range fs {
		if strings.HasPrefix(g.Message, "stale member") {
			t.Errorf("unexpected stale member: %s", g.Message)
		}
	}
}

// kubeadm: static pod under /etc/kubernetes/manifests, recovered with
// --force-new-cluster and explicit member add / initial-cluster-state=existing.
func TestTriageClusterDownKubeadm(t *testing.T) {
	in := baseInput()
	in.Snap.Distribution = "kubeadm"
	x := healthyExec()
	for i := range x.EndpointHealth {
		x.EndpointHealth[i].Healthy = false
		x.EndpointHealth[i].Error = "connection refused"
	}
	x.Statuses = nil
	in.EtcdExec = x
	in.Etcd["cp-1"] = &etcd.Probe{Node: "cp-1", Dist: "kubeadm", DataDir: "/var/lib/etcd", LocalMemberID: "a1", LeaderEvents: []etcd.LeaderEvent{{Term: 7, Leader: "a1", Time: now.Add(-time.Hour)}},
		Sources: []string{"static-pod /etc/kubernetes/manifests/etcd.yaml"}}
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		in.Nodes[n] = &nodeinfo.Info{Node: n, Services: []nodeinfo.Service{{Name: "kubelet", Active: "active", Sub: "running"}}}
	}
	f := findObj(etcdFindings(in), "cluster")
	if f == nil || !strings.Contains(f.Message, "last known leader cp-1 (term 7)") {
		t.Fatalf("cluster finding: %+v", f)
	}
	txt := joined(f)
	order := []string{
		"get every control-plane host powered on and kubelet running",
		"on EVERY other control-plane node first (cp-2 (10.0.0.2), cp-3 (10.0.0.3)): mv /etc/kubernetes/manifests/etcd.yaml /etc/kubernetes/etcd.yaml.off",
		"Then on cp-1: mv /etc/kubernetes/manifests/etcd.yaml /etc/kubernetes/etcd.yaml.off; add '- --force-new-cluster'",
		"remove --force-new-cluster, move it back",
		"etcdctl member add <node> --peer-urls=https://<node ip>:2380",
		"--initial-cluster-state=existing",
		"etcdutl snapshot restore <snapshot file> --data-dir /var/lib/etcd --name cp-1 --initial-cluster cp-1=https://10.0.0.1:2380 --initial-advertise-peer-urls https://10.0.0.1:2380",
		"etcdctl snapshot save",
	}
	for i, want := range order {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		} else if i > 0 && strings.Index(txt, order[i-1]) > strings.Index(txt, want) {
			t.Errorf("%q should precede %q", order[i-1], want)
		}
	}
	if !strings.Contains(txt, "Do NOT run force-new-cluster on more than one node") {
		t.Errorf("guard rail should name the kubeadm operation:\n%s", txt)
	}
	for _, bad := range []string{"rke2", "cluster-reset", "systemctl stop kubelet"} {
		if strings.Contains(txt, bad) {
			t.Errorf("rke2 text leaked into kubeadm steps: %q", bad)
		}
	}
}

// kubeadm single member rebuild after a cluster-id mismatch: no automatic
// rejoin, so member add and initial-cluster-state=existing must be spelled out.
func TestTriageKubeadmRejoin(t *testing.T) {
	in := baseInput()
	in.Snap.Distribution = "kubeadm"
	x := healthyExec()
	x.EndpointHealth[1] = etcd.EndpointHealth{Endpoint: "https://10.0.0.2:2379", Healthy: false, Error: "connection refused"}
	in.EtcdExec = x
	in.Nodes["cp-2"] = &nodeinfo.Info{Node: "cp-2", Services: []nodeinfo.Service{{Name: "kubelet", Active: "active", Sub: "running"}}}
	in.Etcd["cp-2"] = &etcd.Probe{Node: "cp-2", Dist: "kubeadm", DataDir: "/var/lib/etcd"}
	in.Logs["cp-2"] = &logs.Summary{ByName: map[string]int{"cluster-id": 1}}
	f := findObj(etcdFindings(in), "cp-2")
	if f == nil {
		t.Fatal("no finding")
	}
	txt := joined(f)
	for _, want := range []string{
		"etcdctl member remove b2",
		"On cp-2: mv /etc/kubernetes/manifests/etcd.yaml /etc/kubernetes/etcd.yaml.off",
		"mv /var/lib/etcd /var/lib/etcd.bak-",
		"etcdctl member add cp-2 --peer-urls=https://10.0.0.2:2380",
		"set --initial-cluster=<that list> and --initial-cluster-state=existing; then mv /etc/kubernetes/etcd.yaml.off /etc/kubernetes/manifests/etcd.yaml",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "rke2") || strings.Contains(txt, "learner") {
		t.Errorf("rke2 semantics leaked:\n%s", txt)
	}
}

// systemd etcd (kubespray): a failed etcd.service must be reported as the
// service, not as a missing container, and the fix uses systemctl / etcd.env.
func TestTriageSystemdEtcd(t *testing.T) {
	in := baseInput()
	in.Snap.Distribution = "unknown"
	x := healthyExec()
	x.EndpointHealth[2] = etcd.EndpointHealth{Endpoint: "https://10.0.0.3:2379", Healthy: false, Error: "connection refused"}
	in.EtcdExec = x
	in.Nodes["cp-3"] = &nodeinfo.Info{Node: "cp-3", Services: []nodeinfo.Service{{Name: "kubelet", Active: "active", Sub: "running"}, {Name: "etcd", Load: "loaded", Active: "failed", Sub: "failed"}},
		Containers: []nodeinfo.Container{{Name: "kube-apiserver", Pod: "kube-apiserver-cp-3"}}}
	in.Etcd["cp-3"] = &etcd.Probe{Node: "cp-3", Dist: "kubespray", DataDir: "/var/lib/etcd", Sources: []string{"systemd etcd.service (failed)"}}
	f := findObj(etcdFindings(in), "cp-3")
	if f == nil || !strings.Contains(f.Message, "host up but etcd is failed/failed") {
		t.Fatalf("want systemd service finding, got %+v", f)
	}
	if txt := joined(f); !strings.Contains(txt, "journalctl -u etcd -n 200") || !strings.Contains(txt, "systemctl restart etcd") {
		t.Errorf("steps:\n%s", txt)
	}
	// and the cluster-down sequence for this runtime
	for i := range x.EndpointHealth {
		x.EndpointHealth[i].Healthy = false
	}
	x.Statuses = nil
	in.Etcd["cp-3"].LeaderEvents = []etcd.LeaderEvent{{Term: 3, Leader: "c3"}}
	in.Etcd["cp-3"].LocalMemberID = "c3"
	c := findObj(etcdFindings(in), "cluster")
	if c == nil {
		t.Fatal("no cluster finding")
	}
	txt := joined(c)
	for _, want := range []string{"on EVERY other etcd node first", "systemctl stop etcd", "ETCD_FORCE_NEW_CLUSTER=true", "remove ETCD_FORCE_NEW_CLUSTER again", "ETCD_INITIAL_CLUSTER_STATE=existing", "--name cp-3 --initial-cluster cp-3=https://10.0.0.3:2380"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
}
