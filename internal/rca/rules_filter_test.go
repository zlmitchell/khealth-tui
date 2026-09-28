package rca

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// titleList is the hypotheses' titles as one string.
func titleList(hs []Hypothesis) string { return strings.Join(titles(hs), " | ") }

type snapSource struct{ s *k8s.Snapshot }

func (s snapSource) Snap() *k8s.Snapshot                                  { return s.s }
func (snapSource) Objects(string) []unstructured.Unstructured             { return nil }
func (snapSource) PodLog(string, string, string, bool) ([]string, string) { return nil, "" }
func (snapSource) Node(string) *nodeinfo.Info                             { return nil }

// A node in a container reads the host's kernel log: neither its kernel OOM
// kills nor the kubelet's SystemOOM make "node memory exhausted".
func TestMemoryRuleSkipsContainerizedNodes(t *testing.T) {
	at := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	tl := &Timeline{Entries: []Entry{
		{Time: at, Node: "n1", Kind: "journal", Unit: "kernel", Class: logs.ClassWarn, Pattern: "oom", Text: "Out of memory: Killed process 4242 (java)"},
		{Time: at, Node: "n1", Kind: "event", Unit: "node n1", Class: logs.ClassWarn, Pattern: "SystemOOM", Text: "System OOM encountered"},
	}}
	src := snapSource{&k8s.Snapshot{}}
	if got := titleList(Analyze(src, tl)); !strings.Contains(got, "Node memory exhausted on n1") {
		t.Fatalf("a host node's OOM: %q", got)
	}
	tl.Containerized = map[string]string{"n1": "wsl"}
	if got := titleList(Analyze(src, tl)); strings.Contains(got, "Node memory exhausted") {
		t.Errorf("a container node's OOM: %q", got)
	}
}

// A new cluster's pods wait for the not-ready taint and their sandboxes for
// the CNI: not a cause when all of it cleared inside the bootstrap window.
func TestBootstrapRulesSkipANewCluster(t *testing.T) {
	born := time.Date(2026, 9, 26, 2, 51, 0, 0, time.UTC)
	snap := &k8s.Snapshot{Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "n1", CreationTimestamp: metav1.NewTime(born)}}}}
	sched := Entry{Time: born.Add(3 * time.Minute), Kind: "event", Unit: "pod kube-system/coredns-7d9f8c6b5-aaaaa", Class: logs.ClassWarn, Pattern: "FailedScheduling",
		Text: "0/1 nodes are available: 1 node(s) had untolerated taint {node.kubernetes.io/not-ready: }. preemption: 0/1 nodes are available"}
	sandbox := Entry{Time: born.Add(4 * time.Minute), Node: "n1", Kind: "event", Unit: "pod kube-system/coredns-7d9f8c6b5-aaaaa", Class: logs.ClassWarn, Pattern: "FailedCreatePodSandBox",
		Text: "Failed to create pod sandbox: plugin type=\"calico\" failed (add): stat /var/lib/calico/nodename: no such file or directory"}
	tl := &Timeline{Entries: []Entry{sched, sandbox}}
	if got := titleList(Analyze(snapSource{snap}, tl)); got != "" {
		t.Errorf("bootstrap noise became causes: %q", got)
	}
	// the same still happening an hour later is a cause, early entries included
	late := func(e Entry) Entry { e.Time = e.Time.Add(time.Hour); return e }
	tl.Entries = append(tl.Entries, late(sched), late(sandbox))
	got := titleList(Analyze(snapSource{snap}, tl))
	if !strings.Contains(got, "Pods cannot be scheduled") || !strings.Contains(got, "Pod sandboxes fail (CNI) on n1") {
		t.Errorf("persistent failures: %q", got)
	}
}

// The NodeNotReady events posted on a node's pods carry no node: the etcd
// chain names the nodes from the Node's own entries, or says nothing.
func TestEtcdNotReadyEffectNamesNodes(t *testing.T) {
	at := time.Date(2026, 9, 26, 2, 0, 0, 0, time.UTC)
	var es []Entry
	for i := range 3 {
		es = append(es, Entry{Time: at.Add(time.Duration(i) * time.Second), Node: "cp-1", Kind: "pod", Class: logs.ClassWarn, Pattern: "leader-change", Text: "elected leader"})
	}
	pods := Entry{Time: at.Add(time.Minute), Kind: "event", Unit: "pod kube-system/kube-apiserver-cp-2", Class: logs.ClassWarn, Pattern: "NodeNotReady", Text: "Node is not ready"}
	tl := &Timeline{Entries: append(es, pods)}
	effects := func() string {
		hs := Analyze(snapSource{&k8s.Snapshot{}}, tl)
		if len(hs) == 0 {
			t.Fatal("no etcd hypothesis")
		}
		return strings.Join(hs[0].Effects, " | ")
	}
	if e := effects(); strings.Contains(e, "NotReady") {
		t.Errorf("pod-only NotReady events: %q", e)
	}
	tl.Entries = append(tl.Entries, Entry{Time: at.Add(time.Minute), Node: "cp-2", Kind: "event", Unit: "node cp-2", Class: logs.ClassWarn, Pattern: "NodeNotReady", Text: "Node cp-2 status is now: NodeNotReady"})
	if e := effects(); !strings.Contains(e, "went NotReady from") || !strings.HasSuffix(strings.Split(e, "NotReady from ")[1], ": cp-2") {
		t.Errorf("NotReady effect: %q", e)
	}
}

// kube-proxy's liveness probe fails once before it listens on a node that
// just joined: bootstrap noise for the rule and the incident. The event names
// no node, so the pod's node (not the cluster's older first node) decides.
func TestBootstrapLivenessProbe(t *testing.T) {
	first := time.Date(2026, 9, 26, 2, 0, 0, 0, time.UTC)
	joined := first.Add(time.Hour)
	snap := &k8s.Snapshot{
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "n1", CreationTimestamp: metav1.NewTime(first)}},
			{ObjectMeta: metav1.ObjectMeta{Name: "n2", CreationTimestamp: metav1.NewTime(joined)}},
		},
		Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kube-proxy-n2"}, Spec: corev1.PodSpec{NodeName: "n2"}}},
	}
	probe := func(at time.Time) Entry {
		return Entry{Time: at, Kind: "event", Unit: "pod kube-system/kube-proxy-n2", Class: logs.ClassWarn, Pattern: "Unhealthy",
			Text: `Liveness probe failed: Get "http://localhost:10256/livez": dial tcp [::1]:10256: connect: connection refused`}
	}
	kill := func(at time.Time) Entry {
		return Entry{Time: at, Kind: "event", Unit: "pod kube-system/kube-proxy-n2", Class: logs.ClassWarn, Pattern: "Killing",
			Text: "Container kube-proxy failed liveness probe, will be restarted"}
	}
	tl := &Timeline{Entries: []Entry{probe(joined.Add(10 * time.Second)), kill(joined.Add(40 * time.Second))}}
	if got := titleList(Analyze(snapSource{snap}, tl)); strings.Contains(got, "Liveness") {
		t.Errorf("bootstrap probe failure became a cause: %q", got)
	}
	if p := kinds(Extract(tl, snap))[KindProbe]; len(p) != 0 {
		t.Errorf("bootstrap probe incident: %+v", p)
	}
	// failing again after the window: kept whole, the early failure included
	tl.Entries = append(tl.Entries, probe(joined.Add(time.Hour)), kill(joined.Add(time.Hour+30*time.Second)))
	var h *Hypothesis
	hs := Analyze(snapSource{snap}, tl)
	for i := range hs {
		if strings.HasPrefix(hs[i].Title, "Liveness probe failing: kube-system/kube-proxy-n2") {
			h = &hs[i]
		}
	}
	if h == nil || !h.First.Equal(joined.Add(10*time.Second)) {
		t.Fatalf("persistent probe failure: %q", titleList(hs))
	}
	if p := kinds(Extract(tl, snap))[KindProbe]; len(p) != 1 || p[0].Count != 2 {
		t.Errorf("persistent probe incident: %+v", p)
	}
}

func etcdNodes(born time.Time, names ...string) *k8s.Snapshot {
	s := &k8s.Snapshot{}
	for _, n := range names {
		s.Nodes = append(s.Nodes, corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n, CreationTimestamp: metav1.NewTime(born),
			Labels: map[string]string{"node-role.kubernetes.io/etcd": "true"}}})
	}
	return s
}

func elections(node string, from time.Time, n int) []Entry {
	var es []Entry
	for i := range n {
		es = append(es, Entry{Time: from.Add(time.Duration(i) * time.Second), Node: node, Kind: "pod", Class: logs.ClassWarn, Pattern: "leader-change",
			Text: "raft.node: 8e9e05c52164694d elected leader 8e9e05c52164694d at term 2"})
	}
	return es
}

// One etcd member elects itself at every start: no peer network to blame.
func TestEtcdElectionsSingleMember(t *testing.T) {
	born := time.Date(2026, 9, 28, 2, 17, 0, 0, time.UTC)
	tl := &Timeline{Entries: elections("n1", born.Add(2*time.Hour), 5)}
	if got := titleList(Analyze(snapSource{etcdNodes(born, "n1")}, tl)); strings.Contains(got, "leader elections") {
		t.Errorf("single member: %q", got)
	}
}

// Members electing while a new cluster comes up are bootstrap noise; the
// same elections continuing after the window are a cause, kept whole.
func TestEtcdElectionsBootstrap(t *testing.T) {
	born := time.Date(2026, 9, 28, 2, 17, 0, 0, time.UTC)
	snap := etcdNodes(born, "cp-1", "cp-2", "cp-3")
	tl := &Timeline{Entries: elections("cp-1", born.Add(59*time.Second), 5)}
	if got := titleList(Analyze(snapSource{snap}, tl)); strings.Contains(got, "leader elections") {
		t.Errorf("bootstrap elections: %q", got)
	}
	tl.Entries = append(tl.Entries, elections("cp-2", born.Add(time.Hour), 3)...)
	hs := Analyze(snapSource{snap}, tl)
	if len(hs) == 0 || hs[0].Title != "Repeated etcd leader elections" || !hs[0].First.Equal(born.Add(59*time.Second)) || !strings.HasPrefix(hs[0].Cause, "8 leader changes") {
		t.Errorf("persistent elections: %+v", hs)
	}
}

func ctrPod(name, node string, cs ...corev1.ContainerStatus) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name}, Spec: corev1.PodSpec{NodeName: node}, Status: corev1.PodStatus{ContainerStatuses: cs}}
}

func ended(name, reason string, code int32, at time.Time, restarts int32, crashing bool) corev1.ContainerStatus {
	cs := corev1.ContainerStatus{Name: name, RestartCount: restarts,
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, ExitCode: code, FinishedAt: metav1.NewTime(at)}}}
	if crashing {
		cs.State.Waiting = &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}
	} else {
		cs.State.Running = &corev1.ContainerStateRunning{}
	}
	return cs
}

// A reboot ends every container of the node (Unknown, exit 255) and a few
// more lose a race while it comes back: one cause, not one per container.
// A container still crash-looping after the reboot is its own cause.
func TestNodeRebootIsOneCause(t *testing.T) {
	boot := time.Date(2026, 9, 27, 21, 58, 56, 0, time.UTC)
	snap := &k8s.Snapshot{Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "n1", CreationTimestamp: metav1.NewTime(boot.AddDate(0, -1, 0))}}}, Pods: []corev1.Pod{
		ctrPod("db-0", "n1", ended("db", "Unknown", 255, boot, 3, false)),
		ctrPod("web-0", "n1", ended("web", "Unknown", 255, boot, 3, false), ended("sidecar", "Unknown", 255, boot, 3, false)),
		ctrPod("kcm-n1", "n1", ended("kcm", "Error", 1, boot.Add(30*time.Second), 217, false)),
		ctrPod("broken-0", "n1", ended("app", "Error", 1, boot.Add(3*time.Minute), 40, true)),
	}}
	tl := &Timeline{Entries: []Entry{
		{Time: boot.Add(-5 * time.Second), Node: "n1", Kind: "journal", Unit: "systemd", Class: logs.ClassWarn, Pattern: "unit-restart", Text: "systemd[1]: systemd-journald.service: Scheduled restart job, restart counter is at 1."},
		{Time: boot.Add(time.Hour), Node: "n1", Kind: "journal", Unit: "systemd", Class: logs.ClassWarn, Pattern: "unit-restart", Text: "systemd[1]: dnf-makecache.service: Failed with result 'exit-code'."},
	}}
	hs := Analyze(snapSource{snap}, tl)
	got := titleList(hs)
	if len(hs) == 0 || !strings.HasPrefix(hs[0].Title, "Node n1 restarted at "+clock(boot)+": its containers all stopped at once") {
		t.Fatalf("reboot first: %q", got)
	}
	if e := strings.Join(hs[0].Effects, " | "); !strings.Contains(e, "3 containers ended by it") || !strings.Contains(e, "1 more exited once while the node came back") || !strings.Contains(e, "app/kcm-n1/kcm") {
		t.Errorf("settling effect: %q", e)
	}
	if strings.Count(got, "Container restarting") != 1 || !strings.Contains(got, "Container restarting: app/pod/broken-0/app") {
		t.Errorf("only the crash-looping container is its own cause: %q", got)
	}
	if strings.Contains(got, "systemd-journald") || !strings.Contains(got, "Service dnf-makecache.service failing on n1") {
		t.Errorf("unit restarts: %q", got)
	}
}

// Log-rule titles are the first sentence without its parentheses.
func TestTrustTitle(t *testing.T) {
	at := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	var es []Entry
	for i := range 2 {
		es = append(es, Entry{Time: at.Add(time.Duration(i) * time.Minute), Node: "n1", Kind: "journal", Class: logs.ClassError, Pattern: "kernel-defaults", Text: "invalid kernel flag: vm/overcommit_memory"},
			Entry{Time: at.Add(time.Duration(i) * time.Minute), Node: "n1", Kind: "journal", Class: logs.ClassError, Pattern: "port-in-use", Text: "listen tcp 0.0.0.0:6443: bind: address already in use"})
	}
	got := titleList(Analyze(snapSource{&k8s.Snapshot{}}, &Timeline{Entries: es}))
	for _, want := range []string{"kubelet --protect-kernel-defaults is on but sysctls do not match (n1)", "A required port is taken by another process (n1)"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in %q", want, got)
		}
	}
}
