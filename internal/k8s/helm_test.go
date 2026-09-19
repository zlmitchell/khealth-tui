package k8s

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDecodeHelmRelease(t *testing.T) {
	js := `{"name":"nginx","namespace":"web","version":3,"info":{"status":"deployed","last_deployed":"2024-09-18T10:00:00Z","description":"Upgrade complete"},"chart":{"metadata":{"name":"nginx","version":"15.0.1","appVersion":"1.25"}},"config":{"replicaCount":2,"service":{"type":"LoadBalancer"}}}`
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(js))
	w.Close()
	payload := []byte(base64.StdEncoding.EncodeToString(gz.Bytes()))
	rel, err := decodeHelmRelease(payload)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Name != "nginx" || rel.Namespace != "web" || rel.Revision != 3 || rel.Chart != "nginx" || rel.Version != "15.0.1" || rel.AppVersion != "1.25" || rel.Status != "deployed" {
		t.Errorf("decoded: %+v", rel)
	}
	if rel.ValuesYAML == "" || !bytes.Contains([]byte(rel.ValuesYAML), []byte("replicaCount: 2")) {
		t.Errorf("values: %q", rel.ValuesYAML)
	}
	if _, err := decodeHelmRelease(nil); err == nil {
		t.Errorf("expected error on empty payload")
	}
}

func TestPodStatus(t *testing.T) {
	p := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "a", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}, {Name: "b", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "a"}, {Name: "b"}}}}
	if got := PodStatus(p); got != "CrashLoopBackOff" {
		t.Errorf("status = %s", got)
	}
	if r, tot := PodReady(p); r != 1 || tot != 2 {
		t.Errorf("ready %d/%d", r, tot)
	}
	if PodHealthy(p) {
		t.Errorf("should be unhealthy")
	}
	now := metav1.Now()
	p.DeletionTimestamp = &now
	if got := PodStatus(p); got != "Terminating" {
		t.Errorf("status = %s", got)
	}
}

func TestComponentArgs(t *testing.T) {
	pods := []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-cp-1", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}},
		Spec:       corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "kube-apiserver", Command: []string{"kube-apiserver"}, Args: []string{"--anonymous-auth=false", "--profiling=false", "--v=2"}}}},
	}}
	args := ComponentArgs(pods, "kube-apiserver")
	if args["cp-1"]["anonymous-auth"] != "false" || args["cp-1"]["v"] != "2" {
		t.Errorf("args: %v", args)
	}
	if len(ComponentArgs(pods, "kube-scheduler")) != 0 {
		t.Errorf("unexpected scheduler args")
	}
}

func TestNodeRolesAndAddress(t *testing.T) {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeHostName, Address: "cp-1.local"}, {Type: corev1.NodeInternalIP, Address: "10.0.0.1"}}}}
	if r := NodeRoles(n); len(r) != 2 || r[0] != "control-plane" {
		t.Errorf("roles %v", r)
	}
	if !IsControlPlane(n) || !IsEtcdNode([]corev1.Node{*n}, n) {
		t.Errorf("control plane detection")
	}
	if NodeAddress(n, "InternalIP") != "10.0.0.1" || NodeAddress(n, "Hostname") != "cp-1.local" || NodeAddress(n, "ExternalIP") != "10.0.0.1" {
		t.Errorf("address selection")
	}
	w := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w-1"}}
	if IsEtcdNode([]corev1.Node{*n, *w}, w) {
		t.Errorf("worker should not be etcd node")
	}
}

func TestDetectDistribution(t *testing.T) {
	if d := detectDistribution([]corev1.Node{{Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.30.4+rke2r1"}}}}); d != "rke2" {
		t.Errorf("got %s", d)
	}
	if d := detectDistribution([]corev1.Node{{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"kubeadm.alpha.kubernetes.io/cri-socket": "x"}}}}); d != "kubeadm" {
		t.Errorf("got %s", d)
	}
}
