package checks

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

func anyMessage(fs []Finding, sev Severity, substr string) *Finding {
	for i := range fs {
		if fs[i].Severity == sev && strings.Contains(fs[i].Message, substr) {
			return &fs[i]
		}
	}
	return nil
}

// A learner does not vote: one voter plus a learner (rke2 adding its
// second server) has quorum.
func TestLearnerIsNotAVoter(t *testing.T) {
	in := baseInput()
	in.Snap.Nodes = []corev1.Node{node("cp-1", true, "10.0.0.1"), node("cp-2", true, "10.0.0.2")}
	learner := member("b2", "cp-2", "10.0.0.2")
	learner.IsLearner = true
	in.EtcdExec = &etcd.Probe{EtcdctlVia: "kubectl exec etcd-cp-1",
		Members:  []etcd.Member{member("a1", "cp-1", "10.0.0.1"), learner},
		Statuses: []etcd.EndpointStatus{status("a1", "a1", 4, 9000), status("b2", "a1", 4, 8000)},
		EndpointHealth: []etcd.EndpointHealth{{Endpoint: "https://10.0.0.1:2379", Healthy: true},
			{Endpoint: "https://10.0.0.2:2379", Healthy: false, Error: "rpc error: code = Unavailable desc = rpc not supported for learner"}}}
	fs := etcdFindings(in)
	for _, f := range fs {
		if f.Severity == SevCrit {
			t.Errorf("learner caused a CRIT: %s %s", f.Object, f.Message)
		}
	}
	if anyMessage(fs, SevInfo, "is a learner") == nil {
		t.Error("the learner should be reported as INFO")
	}
	// 3 voters + a learner, one voter down: 2/3 voters is quorum
	in.Snap.Nodes = append(in.Snap.Nodes, node("cp-3", true, "10.0.0.3"), node("cp-4", true, "10.0.0.4"))
	learner = member("d4", "cp-4", "10.0.0.4")
	learner.IsLearner = true
	in.EtcdExec.Members = []etcd.Member{member("a1", "cp-1", "10.0.0.1"), member("b2", "cp-2", "10.0.0.2"), member("c3", "cp-3", "10.0.0.3"), learner}
	in.EtcdExec.Statuses = []etcd.EndpointStatus{status("a1", "a1", 4, 9000), status("b2", "a1", 4, 9000), status("d4", "a1", 4, 8000)}
	in.EtcdExec.EndpointHealth = []etcd.EndpointHealth{{Endpoint: "https://10.0.0.1:2379", Healthy: true}, {Endpoint: "https://10.0.0.2:2379", Healthy: true},
		{Endpoint: "https://10.0.0.3:2379", Healthy: false, Error: "context deadline exceeded"},
		{Endpoint: "https://10.0.0.4:2379", Healthy: false, Error: "rpc not supported for learner"}}
	fs = etcdFindings(in)
	if f := anyMessage(fs, SevCrit, "quorum lost"); f != nil {
		t.Errorf("2 of 3 voters healthy: %s", f.Message)
	}
	if f := findObj(fs, "cp-3"); f == nil || f.Severity != SevCrit {
		t.Errorf("the down voter is still CRIT: %+v", f)
	}
}

// No SSH and no exec permission: nothing is known about the members, so no
// node is "unhealthy".
func TestEtcdNothingKnownNoCrit(t *testing.T) {
	in := baseInput()
	in.SSHEnabled = false
	fs := etcdFindings(in)
	for _, f := range fs {
		if f.Severity == SevCrit {
			t.Errorf("CRIT without any etcd data: %s %s", f.Object, f.Message)
		}
	}
	if anyMessage(fs, SevInfo, "health was not checked") == nil {
		t.Error("say that etcd was not checked")
	}
}

// One member known healthy, the other two unreachable over SSH and no
// member list: unknown is not down.
func TestEtcdPartialKnowledgeNotLost(t *testing.T) {
	in := baseInput()
	in.Etcd["cp-1"] = &etcd.Probe{Node: "cp-1", Dist: "rke2", Health: &etcd.Health{Healthy: true}}
	for _, n := range []string{"cp-2", "cp-3"} {
		in.Nodes[n] = &nodeinfo.Info{Node: n, Err: fmt.Errorf("ssh: unable to authenticate")}
	}
	if f := anyMessage(etcdFindings(in), SevCrit, "quorum lost"); f != nil {
		t.Errorf("1 healthy + 2 unknown reported lost: %s", f.Message)
	}
}

// The node's etcdctl output is carried forward while the exec probe runs:
// its old leader and alarms must not contradict the current cluster view.
func TestEtcdStaleNodeDataIgnoredWithExec(t *testing.T) {
	in := baseInput()
	in.EtcdExec = healthyExec()
	in.Etcd["cp-1"] = &etcd.Probe{Node: "cp-1", Dist: "rke2",
		Statuses: []etcd.EndpointStatus{status("a1", "b2", 13, 40000)}, // leader b2 back then
		Alarms:   []etcd.Alarm{{MemberID: "a1", Type: "NOSPACE"}}}
	fs := etcdFindings(in)
	if f := anyMessage(fs, SevCrit, "disagree on the leader"); f != nil {
		t.Errorf("stale leader: %s", f.Message)
	}
	if f := anyMessage(fs, SevCrit, "alarm NOSPACE"); f != nil {
		t.Errorf("stale alarm: %s", f.Message)
	}
}

func TestCorruptAlarmHint(t *testing.T) {
	in := baseInput()
	in.EtcdExec = healthyExec()
	in.EtcdExec.Alarms = []etcd.Alarm{{MemberID: "b2", Type: "CORRUPT"}}
	f := anyMessage(etcdFindings(in), SevCrit, "alarm CORRUPT")
	if f == nil || !strings.Contains(f.Hint, "hashkv") || strings.HasPrefix(f.Hint, "etcdctl alarm disarm") {
		t.Errorf("CORRUPT must not be disarmed first: %+v", f)
	}
}

// A learner left behind by a failed join: not a voter, not "stale member
// counts toward quorum".
func TestOrphanLearner(t *testing.T) {
	in := baseInput()
	in.Snap.Nodes = []corev1.Node{node("cp-1", true, "10.0.0.1")}
	orphan := member("ff", "khtest", "10.0.0.250")
	orphan.IsLearner = true
	in.EtcdExec = &etcd.Probe{EtcdctlVia: "kubectl exec etcd-cp-1", Members: []etcd.Member{member("a1", "cp-1", "10.0.0.1"), orphan},
		Statuses: []etcd.EndpointStatus{status("a1", "a1", 2, 100)}, EndpointHealth: []etcd.EndpointHealth{{Endpoint: "https://10.0.0.1:2379", Healthy: true}}}
	fs := etcdFindings(in)
	for _, f := range fs {
		if f.Severity == SevCrit {
			t.Errorf("CRIT for an orphan learner: %s", f.Message)
		}
	}
	if anyMessage(fs, SevWarn, "learner member khtest-abcd1234") == nil {
		t.Error("orphan learner not reported")
	}
}

// S3 copies are recorded under node "s3": not a server that left.
func TestSnapshotRecordsOnS3(t *testing.T) {
	in := baseInput()
	in.Snap.SnapshotCM = &k8s.SnapshotConfigMap{Name: "rke2-etcd-snapshots", Entries: 6, Bytes: 6 * 600}
	for i := 0; i < 3; i++ {
		in.Snap.RKE2Snapshots = append(in.Snap.RKE2Snapshots,
			k8s.EtcdSnapshotRecord{Name: fmt.Sprintf("local-%d", i), Node: "cp-1", Status: "successful"},
			k8s.EtcdSnapshotRecord{Name: fmt.Sprintf("s3-%d", i), Node: "s3", S3: true, Status: "successful"})
	}
	for _, f := range Evaluate(in) {
		if strings.Contains(f.Message, "no longer in the cluster") {
			t.Errorf("S3 records taken for a gone server: %s", f.Message)
		}
	}
}

func TestKubeadmExternalEtcd(t *testing.T) {
	in := baseInput()
	in.Snap.Distribution = "kubeadm"
	in.Snap.Nodes = []corev1.Node{node("cp-1", true, "10.0.0.1"), node("cp-2", true, "10.0.0.2")}
	for i := range in.Snap.Nodes {
		delete(in.Snap.Nodes[i].Labels, "node-role.kubernetes.io/etcd")
	}
	in.Snap.Kubeadm = &k8s.KubeadmConfig{ExternalEtcd: true}
	for n := range map[string]bool{"cp-1": true, "cp-2": true} {
		in.Nodes[n] = &nodeinfo.Info{Node: n, Dist: "kubeadm", ControlPlane: true, Containers: []nodeinfo.Container{{Name: "kube-apiserver"}}}
	}
	fs := etcdFindings(in)
	for _, f := range fs {
		if f.Severity != SevInfo {
			t.Errorf("external etcd: %s %s %s", f.Severity, f.Object, f.Message)
		}
	}
	if anyMessage(fs, SevInfo, "etcd is external") == nil {
		t.Error("external etcd not explained")
	}
}
