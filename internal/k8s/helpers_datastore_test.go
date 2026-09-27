package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func k3sNode(name string, labels map[string]string, args string) corev1.Node {
	l := map[string]string{"node-role.kubernetes.io/control-plane": "true"}
	for k, v := range labels {
		l[k] = v
	}
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: l, Annotations: map[string]string{"k3s.io/node-args": args}}}
}

// A single k3s server without --cluster-init keeps its state in SQLite:
// no node is an etcd node, and the datastore says where the state lives.
func TestDatastore(t *testing.T) {
	sqlite := []corev1.Node{k3sNode("s1", nil, `["server","--node-name","s1"]`)}
	if IsEtcdNode(sqlite, &sqlite[0]) {
		t.Error("a k3s server without the etcd label counted as an etcd node")
	}
	if got := Datastore(sqlite); got != "SQLite (kine) on s1" {
		t.Errorf("sqlite: %q", got)
	}
	ext := []corev1.Node{k3sNode("s1", nil, `["server","--datastore-endpoint","mysql://user:secret@tcp(db:3306)/k3s"]`)}
	if got := Datastore(ext); got != "an external mysql datastore (kine)" {
		t.Errorf("external: %q", got)
	}
	etcd := []corev1.Node{k3sNode("s1", map[string]string{"node-role.kubernetes.io/etcd": "true"}, `["server","--cluster-init"]`)}
	if !IsEtcdNode(etcd, &etcd[0]) || Datastore(etcd) != "" {
		t.Error("embedded etcd not recognized")
	}
	// kubeadm: no rke2/k3s annotations, control-plane nodes run etcd
	kubeadm := []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "cp", Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}}}
	if !IsEtcdNode(kubeadm, &kubeadm[0]) || Datastore(kubeadm) != "" {
		t.Error("kubeadm control plane should be an etcd node")
	}
}
