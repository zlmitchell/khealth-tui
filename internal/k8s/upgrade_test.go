package k8s

import (
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func sucPlan(ns, name, version, channel, latest, hash string, applying []string, conds ...map[string]any) unstructured.Unstructured {
	o := map[string]any{
		"apiVersion": "upgrade.cattle.io/v1", "kind": "Plan",
		"metadata": map[string]any{"name": name, "namespace": ns, "creationTimestamp": "2026-09-20T10:00:00Z"},
		"spec": map[string]any{
			"concurrency":  int64(1),
			"cordon":       true,
			"nodeSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "node-role.kubernetes.io/control-plane", "operator": "In", "values": []any{"true"}}}},
			"upgrade":      map[string]any{"image": "rancher/rke2-upgrade"},
		},
		"status": map[string]any{},
	}
	spec := o["spec"].(map[string]any)
	if version != "" {
		spec["version"] = version
	}
	if channel != "" {
		spec["channel"] = channel
	}
	st := o["status"].(map[string]any)
	if latest != "" {
		st["latestVersion"] = latest
	}
	if hash != "" {
		st["latestHash"] = hash
	}
	if applying != nil {
		a := make([]any, len(applying))
		for i, n := range applying {
			a[i] = n
		}
		st["applying"] = a
	}
	if len(conds) > 0 {
		c := make([]any, len(conds))
		for i, x := range conds {
			c[i] = x
		}
		st["conditions"] = c
	}
	return unstructured.Unstructured{Object: o}
}

func TestParsePlanAndPlanNodes(t *testing.T) {
	p := parsePlan(sucPlan("cattle-system", "rke2-server", "", "https://update.rke2.io/v1-release/channels/stable", "v1.35.9+rke2r1", "abc123", []string{"cp-2"},
		map[string]any{"type": "LatestResolved", "status": "True"},
		map[string]any{"type": "Complete", "status": "False", "reason": "Applying"}))
	if p.Target() != "v1.35.9+rke2r1" || p.Channel == "" || p.Hash != "abc123" || p.Concurrency != 1 || !p.Cordon || p.Drain || p.Image != "rancher/rke2-upgrade" {
		t.Fatalf("plan: %+v", p)
	}
	if len(p.Applying) != 1 || p.Applying[0] != "cp-2" || len(p.Conditions) != 1 || p.Conditions[0].Type != "Complete" || p.Complete {
		t.Errorf("status: %+v", p)
	}
	if p.Selector == nil || len(p.Selector.MatchExpressions) != 1 {
		t.Fatalf("selector: %+v", p.Selector)
	}
	s := &Snapshot{Nodes: []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "plan.upgrade.cattle.io/rke2-server": "abc123"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "cp-2", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "plan.upgrade.cattle.io/rke2-server": "old"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "w-1", Labels: map[string]string{"node-role.kubernetes.io/worker": "true"}}},
	}}
	done, pending := s.PlanNodes(p)
	if len(done) != 1 || done[0] != "cp-1" || len(pending) != 1 || pending[0] != "cp-2" {
		t.Errorf("done=%v pending=%v", done, pending)
	}
	// a plan without a selector applies to every node
	p2 := parsePlan(sucPlan("system-upgrade", "all", "v1.35.9+rke2r1", "", "", "", nil))
	p2.Selector = nil
	if _, pending := s.PlanNodes(p2); len(pending) != 3 {
		t.Errorf("no selector: pending=%v", pending)
	}
}

func TestAttachUpgradeJobs(t *testing.T) {
	started := metav1.NewTime(time.Date(2026, 9, 20, 10, 5, 0, 0, time.UTC))
	s := &Snapshot{
		Upgrade: &UpgradeInfo{Plans: []UpgradePlan{parsePlan(sucPlan("cattle-system", "rke2-server", "v1.35.9+rke2r1", "", "v1.35.9+rke2r1", "abc", nil))}},
		Jobs: []batchv1.Job{
			{ObjectMeta: metav1.ObjectMeta{Name: "apply-rke2-server-on-cp-2-with-abc", Namespace: "cattle-system", Labels: map[string]string{"upgrade.cattle.io/plan": "rke2-server", "upgrade.cattle.io/node": "cp-2", "upgrade.cattle.io/version": "v1.35.9-rke2r1"}},
				Status: batchv1.JobStatus{Active: 1, StartTime: &started}},
			{ObjectMeta: metav1.ObjectMeta{Name: "apply-rke2-server-on-cp-1-with-abc", Namespace: "cattle-system", Labels: map[string]string{"upgrade.cattle.io/plan": "rke2-server", "upgrade.cattle.io/node": "cp-1"}},
				Status: batchv1.JobStatus{Failed: 3, StartTime: &started, Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "default"}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "apply-rke2-server-on-cp-2-with-abc-x", Namespace: "cattle-system", Labels: map[string]string{"job-name": "apply-rke2-server-on-cp-2-with-abc", "upgrade.cattle.io/plan": "rke2-server"}},
				Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{{Name: "cordon", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "Back-off pulling image \"rancher/rke2-upgrade:v1.35.9-rke2r1\""}}}}}},
		},
	}
	s.AttachUpgradeJobs()
	p := s.Upgrade.Plans[0]
	if len(p.Jobs) != 2 {
		t.Fatalf("jobs: %+v", p.Jobs)
	}
	byNode := map[string]UpgradeJob{}
	for _, j := range p.Jobs {
		byNode[j.Node] = j
	}
	if j := byNode["cp-2"]; j.Active != 1 || j.PodState != "ImagePullBackOff" || j.Version != "v1.35.9-rke2r1" || j.Started.IsZero() {
		t.Errorf("cp-2 job: %+v", j)
	}
	if j := byNode["cp-1"]; j.FailedReason != "BackoffLimitExceeded" || j.Failed != 3 || j.PodState != "" {
		t.Errorf("cp-1 job: %+v", j)
	}
}

func TestParseMachinePlan(t *testing.T) {
	plan := []byte(`{"files":[],"instructions":[]}`)
	sec := &corev1.Secret{Data: map[string][]byte{
		"plan":           plan,
		"appliedPlan":    []byte(`{"files":[],"instructions":[{"name":"old"}]}`),
		"probe-statuses": []byte(`{"kubelet":{"healthy":true,"successCount":3},"etcd":{"healthy":false,"failureCount":4}}`),
	}}
	mp := parseMachinePlan(sec)
	if !mp.HasPlan || mp.InSync || mp.Failed || mp.Failing || mp.Failures != 0 {
		t.Errorf("pending plan: %+v", mp)
	}
	if u := mp.UnhealthyProbes(); len(u) != 1 || u[0] != "etcd" {
		t.Errorf("probes: %v", u)
	}
	// in sync: the agent applied exactly the current plan
	sec.Data["appliedPlan"] = plan
	if !parseMachinePlan(sec).InSync {
		t.Error("identical appliedPlan not in sync")
	}
	// failures on an older plan do not count against the current one
	sec.Data["appliedPlan"] = []byte("x")
	sec.Data["failed-checksum"] = []byte("0000")
	sec.Data["failure-count"] = []byte("3")
	if mp := parseMachinePlan(sec); mp.Failed || mp.Failing || mp.Failures != 0 {
		t.Errorf("stale failure counted: %+v", mp)
	}
	// failures on the current plan: below the threshold the agent retries
	sec.Data["failed-checksum"] = []byte(sha256Hex(plan))
	sec.Data["failure-threshold"] = []byte("5")
	if mp := parseMachinePlan(sec); mp.Failed || !mp.Failing || mp.Failures != 3 || mp.Threshold != 5 {
		t.Errorf("retrying: %+v", mp)
	}
	sec.Data["failure-count"] = []byte("5")
	if mp := parseMachinePlan(sec); !mp.Failed || mp.Failing {
		t.Errorf("threshold reached: %+v", mp)
	}
	// -1: never give up
	sec.Data["failure-threshold"] = []byte("-1")
	if mp := parseMachinePlan(sec); mp.Failed || !mp.Failing {
		t.Errorf("threshold -1: %+v", mp)
	}
	// no threshold at all: any failure on the current plan is final
	delete(sec.Data, "failure-threshold")
	sec.Data["failure-count"] = []byte("1")
	if mp := parseMachinePlan(sec); !mp.Failed {
		t.Errorf("no threshold: %+v", mp)
	}
}

func TestUpgradePodState(t *testing.T) {
	if st, _ := upgradePodState(nil); st != "" {
		t.Error("no pods")
	}
	ok := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
	if st, _ := upgradePodState([]*corev1.Pod{ok}); st != "" {
		t.Error("succeeded pod")
	}
	term := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodFailed, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 1}}}}}}
	if st, msg := upgradePodState([]*corev1.Pod{term}); st != "Error" || msg != "exit 1" {
		t.Errorf("terminated: %s %s", st, msg)
	}
	unsched := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "Unschedulable", Message: "node(s) had untolerated taint"}}}}
	if st, _ := upgradePodState([]*corev1.Pod{unsched}); st != "Unschedulable" {
		t.Errorf("unschedulable: %s", st)
	}
}
