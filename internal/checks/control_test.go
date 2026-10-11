package checks

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

func TestControlPlumbing(t *testing.T) {
	now := time.Now()
	old := metav1.NewTime(now.Add(-time.Hour))
	s := &k8s.Snapshot{
		ServiceReady: map[string]int{"cattle-system/rancher-webhook": 0, "kube-system/ok": 2},
		Webhooks: []k8s.Webhook{
			{Config: "rancher.cattle.io", Name: "rancher.cattle.io.pods", FailClosed: true, ServiceNS: "cattle-system", ServiceName: "rancher-webhook", Resources: []string{"pods"}},
			{Config: "narrow", Name: "cm.example.com", FailClosed: true, ServiceNS: "x", ServiceName: "gone", Resources: []string{"configmaps"}, SkipsKubeSys: true},
			{Config: "lenient", Name: "l.example.com", ServiceNS: "x", ServiceName: "gone", Resources: []string{"*"}},
			{Config: "healthy", Name: "h.example.com", FailClosed: true, ServiceNS: "kube-system", ServiceName: "ok", Resources: []string{"pods"}},
		},
		APIServices: []k8s.APIService{{Name: "v1beta1.metrics.k8s.io", Available: false, Reason: "MissingEndpoints", Service: "kube-system/metrics-server"}, {Name: "v1.", Local: true}},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "gone", DeletionTimestamp: &old}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating,
			Conditions: []corev1.NamespaceCondition{{Type: corev1.NamespaceDeletionDiscoveryFailure, Status: corev1.ConditionTrue, Message: "Discovery failed for some groups"}}}}},
		PDBs: []policyv1.PodDisruptionBudget{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "strict"}, Status: policyv1.PodDisruptionBudgetStatus{ExpectedPods: 1, CurrentHealthy: 1, DesiredHealthy: 1}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Name: "instance-manager-x"}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"longhorn.io/managed-by": "longhorn-manager"}}},
				Status: policyv1.PodDisruptionBudgetStatus{ExpectedPods: 1, CurrentHealthy: 1, DesiredHealthy: 1}},
		},
		CSRs: []k8s.CSR{{Name: "csr-1", Signer: "kubernetes.io/kubelet-serving", Created: old.Time, Pending: true}},
	}
	fs := Evaluate(Input{Snap: s, Cfg: config.Default(), Now: now})
	for _, w := range []struct {
		sev    Severity
		substr string
	}{
		{SevCrit, "webhook rancher.cattle.io.pods fails closed"},
		{SevWarn, "webhook cm.example.com fails closed"},
		{SevInfo, "webhook l.example.com has no ready endpoint"},
		{SevWarn, "aggregated API v1beta1.metrics.k8s.io is unavailable"},
		{SevWarn, "namespace gone has been Terminating"},
		{SevWarn, "PodDisruptionBudget allows no disruption"},
		{SevWarn, "kubelet serving certificates are not issued"},
	} {
		if anyMessage(fs, w.sev, w.substr) == nil {
			t.Errorf("missing %s %q", w.sev, w.substr)
		}
	}
	for _, f := range fs {
		if f.Object == "webhook/healthy" || f.Object == "longhorn-system/pdb/instance-manager-x" {
			t.Errorf("unexpected: %s %s", f.Object, f.Message)
		}
	}
}
