package rca

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

func kinds(ins []Incident) map[Kind][]Incident {
	out := map[Kind][]Incident{}
	for _, in := range ins {
		out[in.Kind] = append(out[in.Kind], in)
	}
	return out
}

// The node lifecycle controller posts NodeNotReady on each pod of the node
// too: only the Node's own event is a node incident. The node is a day old,
// so the bootstrap window has nothing to do with it.
func TestNotReadyPodEventIsNotANode(t *testing.T) {
	at := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	snap := &k8s.Snapshot{Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", CreationTimestamp: metav1.NewTime(at.Add(-24 * time.Hour))}}}}
	tl := &Timeline{Entries: []Entry{
		{Time: at, Kind: "event", Unit: "pod kube-system/kube-apiserver-cp-1", Pattern: "NodeNotReady", Text: "Node is not ready"},
		{Time: at, Node: "cp-1", Kind: "event", Unit: "node cp-1", Pattern: "NodeNotReady", Text: "Node cp-1 status is now: NodeNotReady"},
	}}
	ins := Extract(tl, snap)
	nr := kinds(ins)[KindNotReady]
	if len(nr) != 1 || nr[0].Node != "cp-1" || nr[0].Object() != "node/cp-1" {
		t.Fatalf("NotReady incidents %+v", nr)
	}
	for _, in := range ins {
		if strings.Contains(in.Object(), "kube-apiserver") {
			t.Errorf("a pod named as a node: %s %s", in.Kind, in.Object())
		}
	}
}

// What a new node produces while it comes up is dropped when it cleared
// inside the bootstrap window; the same kind still going after it is kept.
func TestBootstrapNoise(t *testing.T) {
	born := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	snap := &k8s.Snapshot{Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "n1", CreationTimestamp: metav1.NewTime(born)}}}}
	sched := func(pod string, at time.Time) Entry {
		return Entry{Time: at, Kind: "event", Unit: "pod shop/" + pod, Pattern: "FailedScheduling", Text: "0/1 nodes are available: 1 node(s) had untolerated taint {node.kubernetes.io/not-ready: }"}
	}
	tl := &Timeline{Entries: []Entry{
		sched("early-7d9f8c6b5-aaaaa", born.Add(time.Minute)),
		sched("late-7d9f8c6b5-bbbbb", born.Add(time.Minute)),
		sched("late-7d9f8c6b5-bbbbb", born.Add(time.Hour)),
		{Time: born.Add(2 * time.Minute), Node: "n1", Kind: "event", Unit: "node n1", Pattern: "SystemOOM", Text: "System OOM encountered"},
	}}
	got := kinds(Extract(tl, snap))
	if s := got[KindSchedule]; len(s) != 1 || s[0].Workload != "deploy/late" {
		t.Errorf("schedule incidents %+v", s)
	}
	if len(got[KindNodeOOM]) != 1 {
		t.Errorf("a node OOM is never bootstrap noise: %+v", got[KindNodeOOM])
	}
}

// A node in a container reads the host's kernel log: its OOM kills are
// other containers'.
func TestContainerizedNodeOOM(t *testing.T) {
	at := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	tl := &Timeline{Entries: []Entry{{Time: at, Node: "n1", Kind: "event", Unit: "node n1", Pattern: "SystemOOM", Text: "System OOM encountered"}}}
	if n := len(kinds(Extract(tl, &k8s.Snapshot{}))[KindNodeOOM]); n != 1 {
		t.Fatalf("node OOM on a host: %d incidents", n)
	}
	tl.Containerized = map[string]string{"n1": "docker"}
	if n := len(kinds(Extract(tl, &k8s.Snapshot{}))[KindNodeOOM]); n != 0 {
		t.Errorf("node OOM on a docker node: %d incidents", n)
	}
}
