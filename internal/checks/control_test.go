package checks

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
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

func TestAPIMetricsFindings(t *testing.T) {
	now := time.Now()
	s := &k8s.Snapshot{APIMetrics: &k8s.APIMetrics{At: now, Since: 15 * time.Minute,
		Rejected:    map[string]float64{"workload-low|queue-full": 340},
		RejectedNew: map[string]float64{"workload-low|queue-full": 120},
		Objects:     map[string]float64{"events": 80000, "pods": 300}}}
	fs := Evaluate(Input{Snap: s, Cfg: config.Default(), Now: now})
	if anyMessage(fs, SevWarn, "rejected 120 requests (429") == nil {
		t.Error("APF rejections in the window")
	}
	if anyMessage(fs, SevWarn, "80000 events objects in storage") == nil {
		t.Error("object bloat")
	}
	if anyMessage(fs, SevWarn, "pods objects") != nil {
		t.Error("300 pods is no bloat")
	}
}

func TestIngressBlockedByCISPolicy(t *testing.T) {
	mk := func(extra ...networkingv1.NetworkPolicy) []Finding {
		s := &k8s.Snapshot{
			Pods:      []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "nginx", Labels: map[string]string{"app.kubernetes.io/name": "rke2-ingress-nginx"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}},
			Ingresses: []networkingv1.Ingress{{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"}}},
			NetPols: append([]networkingv1.NetworkPolicy{{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-network-policy", Annotations: map[string]string{"np.rke2.io": "resolved"}},
				Spec: networkingv1.NetworkPolicySpec{Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}}}}}}, extra...),
		}
		return Evaluate(Input{Snap: s, Cfg: config.Default(), Now: time.Now()})
	}
	if anyMessage(mk(), SevWarn, "cannot reach this Ingress's backends") == nil {
		t.Error("CIS default policy blocking the controller not reported")
	}
	allow := networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "allow-ingress"},
		Spec: networkingv1.NetworkPolicySpec{Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}}}}}}}}
	if f := anyMessage(mk(allow), SevWarn, "cannot reach"); f != nil {
		t.Errorf("an allow policy exists: %s", f.Message)
	}
}

func TestCertManagerFindings(t *testing.T) {
	now := time.Now()
	s := &k8s.Snapshot{CertManager: &k8s.CertManager{
		Certificates: []k8s.CMCertificate{
			{Namespace: "cattle-system", Name: "tls-rancher-ingress", Ready: true, NotAfter: now.Add(60 * 24 * time.Hour)},
			{Namespace: "app", Name: "expired", Ready: false, NotAfter: now.Add(-time.Hour)},
			{Namespace: "app", Name: "stuck", Ready: true, NotAfter: now.Add(3 * 24 * time.Hour), RenewalTime: now.Add(-10 * 24 * time.Hour)},
			{Namespace: "app", Name: "pending", Ready: false, Reason: "DoesNotExist", Message: "Issuer missing"},
		},
		Issuers: []k8s.CMIssuer{{Kind: "ClusterIssuer", Name: "letsencrypt", Ready: false, Message: "Failed to register ACME account"}},
	}}
	fs := Evaluate(Input{Snap: s, Cfg: config.Default(), Now: now})
	for _, w := range []struct {
		sev    Severity
		substr string
	}{
		{SevCrit, "certificate expired expired"},
		{SevWarn, "certificate stuck expires in"},
		{SevWarn, "certificate pending is not Ready (DoesNotExist)"},
		{SevWarn, "ClusterIssuer letsencrypt is not Ready"},
	} {
		if anyMessage(fs, w.sev, w.substr) == nil {
			t.Errorf("missing %s %q", w.sev, w.substr)
		}
	}
	if anyMessage(fs, SevWarn, "tls-rancher-ingress") != nil {
		t.Error("a healthy certificate is reported")
	}
}

func TestVIPHolders(t *testing.T) {
	ni := func(addrs ...string) *nodeinfo.Info {
		return &nodeinfo.Info{Addrs: addrs, Settings: map[string]string{"server": "https://10.0.0.50:9345"}, Services: []nodeinfo.Service{{Name: "keepalived", Load: "loaded", Active: "active"}}}
	}
	node := func(name, ip string) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}}}
	}
	snap := &k8s.Snapshot{Nodes: []corev1.Node{node("a", "10.0.0.1"), node("b", "10.0.0.2")}}
	run := func(a, b *nodeinfo.Info) []Finding {
		return Evaluate(Input{Snap: snap, Cfg: config.Default(), Now: time.Now(), APIServer: "https://10.0.0.50:6443", Nodes: map[string]*nodeinfo.Info{"a": a, "b": b}})
	}
	if anyMessage(run(ni("10.0.0.1", "10.0.0.50"), ni("10.0.0.2", "10.0.0.50")), SevCrit, "configured on 2 nodes at once") == nil {
		t.Error("split brain")
	}
	if anyMessage(run(ni("10.0.0.1"), ni("10.0.0.2")), SevWarn, "held by no node although keepalived runs") == nil {
		t.Error("unannounced VIP")
	}
	fs := run(ni("10.0.0.1", "10.0.0.50"), ni("10.0.0.2"))
	if anyMessage(fs, SevCrit, "vip") != nil || anyMessage(fs, SevWarn, "held by no node") != nil {
		t.Error("one holder is the healthy state")
	}
}

func TestK3sSQLDatastoreKnownIssue(t *testing.T) {
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "s1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true"},
		Annotations: map[string]string{"k3s.io/node-args": `["server","--datastore-endpoint","postgres://k3s:<masked>@db:5432/k3s"]`}}}
	fs := Evaluate(Input{Snap: &k8s.Snapshot{Distribution: "k3s", Nodes: []corev1.Node{n}}, Cfg: config.Default(), Now: time.Now()})
	if anyMessage(fs, SevInfo, "goes read-only when its revision reaches 2147483647") == nil {
		t.Error("kine SQL known issue not mentioned")
	}
}
