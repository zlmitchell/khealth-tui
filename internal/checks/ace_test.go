package checks

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

func TestACEFindings(t *testing.T) {
	apiserver := func(node string, webhook bool) corev1.Pod {
		args := []string{"kube-apiserver", "--anonymous-auth=false"}
		if webhook {
			args = append(args, "--authentication-token-webhook-config-file=/var/lib/rancher/rke2/kube-api-authn-webhook.yaml")
		}
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-" + node, Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}},
			Spec: corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "kube-apiserver", Args: args}}}}
	}
	authDS := func(ready, desired int32) appsv1.DaemonSet {
		return appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "kube-api-auth", Namespace: "cattle-system"}, Status: appsv1.DaemonSetStatus{NumberReady: ready, DesiredNumberScheduled: desired}}
	}
	server := func(name string, provisioned bool) *nodeinfo.Info {
		ni := &nodeinfo.Info{Node: name, Dist: "rke2", ControlPlane: true, Settings: map[string]string{}, KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Hardening: map[string]string{}}
		ni.Rancher.Provisioned = provisioned
		return ni
	}
	find := func(fs []Finding) *Finding {
		for i := range fs {
			if fs[i].Object == "rancher" && strings.Contains(fs[i].Message, "ACE") {
				return &fs[i]
			}
		}
		return nil
	}
	managed := &k8s.RancherInfo{Managed: true, Server: "https://rancher.example.com", ClusterAgentOK: true, ClusterAgent: "1/1 ready"}
	base := func(pods ...corev1.Pod) Input {
		return Input{Snap: &k8s.Snapshot{Rancher: managed, Pods: pods}, Cfg: config.Default(), Now: time.Now(), SSHEnabled: true,
			Nodes: map[string]*nodeinfo.Info{"cp-1": server("cp-1", true), "cp-2": server("cp-2", true)}}
	}

	// provisioned, no webhook anywhere: not enabled
	in := base(apiserver("cp-1", false), apiserver("cp-2", false))
	if f := find(Evaluate(in)); f == nil || f.Severity != SevInfo || !strings.Contains(f.Message, "ACE) is not enabled") || !strings.Contains(f.Hint, "Authorized Endpoint") {
		t.Errorf("not enabled: %+v", f)
	}
	// imported cluster (no 50-rancher.yaml on the servers): nothing to say
	in.Nodes["cp-1"].Rancher.Provisioned, in.Nodes["cp-2"].Rancher.Provisioned = false, false
	if f := find(Evaluate(in)); f != nil {
		t.Errorf("imported cluster: %+v", f)
	}
	// enabled everywhere with the authenticator ready: no finding
	in = base(apiserver("cp-1", true), apiserver("cp-2", true))
	in.Snap.DaemonSets = []appsv1.DaemonSet{authDS(2, 2)}
	if f := find(Evaluate(in)); f != nil {
		t.Errorf("healthy ACE: %+v", f)
	}
	ace := in.Snap.ACE()
	if !ace.Enabled() || ace.Webhook != "/var/lib/rancher/rke2/kube-api-authn-webhook.yaml" || !ace.AuthFound || ace.AuthNamespace != "cattle-system" {
		t.Errorf("status: %+v", ace)
	}
	// enabled but the authenticator is gone / not ready
	in.Snap.DaemonSets = nil
	if f := find(Evaluate(in)); f == nil || f.Severity != SevCrit || !strings.Contains(f.Message, "kube-api-auth DaemonSet is missing") {
		t.Errorf("no authenticator: %+v", f)
	}
	in.Snap.DaemonSets = []appsv1.DaemonSet{authDS(1, 2)}
	if f := find(Evaluate(in)); f == nil || f.Severity != SevCrit || !strings.Contains(f.Message, "kube-api-auth is 1/2 ready") {
		t.Errorf("authenticator not ready: %+v", f)
	}
	// the plan landed on one server only
	in = base(apiserver("cp-1", true), apiserver("cp-2", false))
	in.Snap.DaemonSets = []appsv1.DaemonSet{authDS(2, 2)}
	if f := find(Evaluate(in)); f == nil || f.Severity != SevWarn || !strings.Contains(f.Message, "configured on cp-1 but not on cp-2") {
		t.Errorf("mixed: %+v", f)
	}
	// not Rancher-managed: nothing
	in.Snap.Rancher = nil
	if f := find(Evaluate(in)); f != nil {
		t.Errorf("unmanaged: %+v", f)
	}
}
