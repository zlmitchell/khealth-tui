package stig

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// BenchmarkEvaluate measures a full Evaluate (Kubernetes + CIS + rke2 +
// OS STIG named/template rules) over N RHEL 9 nodes - what one recompute
// costs on the operator's machine.
func BenchmarkEvaluate(b *testing.B) {
	for _, n := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			snap := &k8s.Snapshot{Distribution: "rke2", KubeletConfigs: map[string]map[string]any{}}
			nodes := map[string]*nodeinfo.Info{}
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("node-%02d", i)
				ni := hardenedNode()
				ni.Node = name
				nodes[name] = ni
				snap.Nodes = append(snap.Nodes, corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}})
				snap.Pods = append(snap.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-" + name, Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}},
					Spec: corev1.PodSpec{NodeName: name, Containers: []corev1.Container{{Name: "kube-apiserver", Args: []string{"--anonymous-auth=false"}}}}})
				snap.KubeletConfigs[name] = map[string]any{"readOnlyPort": float64(0)}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rs := Evaluate(Input{Snap: snap, Nodes: nodes})
				if len(rs) == 0 {
					b.Fatal("no results")
				}
			}
		})
	}
}
