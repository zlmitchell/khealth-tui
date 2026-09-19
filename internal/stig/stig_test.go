package stig

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
)

func find(rs []Result, id string) *Result {
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i]
		}
	}
	return nil
}

func TestEvaluate(t *testing.T) {
	snap := &k8s.Snapshot{
		Distribution: "rke2",
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-cp-1", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}},
				Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "kube-apiserver", Args: []string{"kube-apiserver", "--anonymous-auth=false", "--authorization-mode=Node,RBAC", "--audit-log-maxage=10", "--profiling=false"}}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
		},
		Namespaces:     []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}, {ObjectMeta: metav1.ObjectMeta{Name: "team-b", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}},
		KubeletConfigs: map[string]map[string]any{"cp-1": {"authentication": map[string]any{"anonymous": map[string]any{"enabled": false}}, "authorization": map[string]any{"mode": "Webhook"}, "readOnlyPort": float64(0), "protectKernelDefaults": true, "streamingConnectionIdleTimeout": "0s"}},
	}
	nodes := map[string]*nodeinfo.Info{"cp-1": {Node: "cp-1", Dist: "rke2", ControlPlane: true, EtcdUser: true, Settings: map[string]string{"profile": "cis"}, Sysctl: map[string]string{"vm.overcommit_memory": "0"},
		Perms: []nodeinfo.Perm{{Path: "/etc/rancher/rke2/config.yaml", Mode: "644", User: "root", Group: "root", Type: "regular file"}, {Path: "/var/lib/rancher/rke2/server/db/etcd", Mode: "700", User: "etcd", Group: "etcd", Type: "directory"}}, KubeletFlags: map[string]string{"hostname-override": "cp-1"}}}
	rs := Evaluate(Input{Snap: snap, Nodes: nodes})
	expect := map[string]Status{
		"V-242390": Pass, "V-242382": Pass, "V-242464": Fail, "V-242378": Fail, "CIS-1.2.15": Pass,
		"V-242391": Pass, "V-242392": Pass, "V-242387": Pass, "V-245541": Fail, "V-242434": Pass, "V-242404": NA,
		"V-254555": Pass, "CIS-sysctl": Fail, "V-242445": Pass, "RKE2-etcd-user": Pass, "V-254564": Fail,
		"V-242383": Fail, "V-254800-ns": Fail, "V-242395": Pass,
	}
	for id, want := range expect {
		r := find(rs, id)
		if r == nil {
			t.Errorf("missing rule %s", id)
			continue
		}
		if r.Status != want {
			t.Errorf("%s: got %s (%s) want %s", id, r.Status, r.Detail, want)
		}
	}
	if !modeAtMost("600", 0o600) || modeAtMost("644", 0o600) || !modeAtMost("400", 0o644) {
		t.Errorf("modeAtMost")
	}
}
