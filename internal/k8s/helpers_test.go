package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodStatusVariants(t *testing.T) {
	waiting := func(reason string) corev1.ContainerState {
		return corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}
	}
	cases := []struct {
		name string
		pod  corev1.Pod
		want string
	}{
		{"running", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}, "Running"},
		{"evicted", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"}}, "Evicted"},
		{"reason", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, Reason: "NodeAffinity"}}, "NodeAffinity"},
		{"init waiting", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{{State: waiting("ImagePullBackOff")}}}}, "Init:ImagePullBackOff"},
		{"init initializing is not a status", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{{State: waiting("PodInitializing")}}}}, "Pending"},
		{"init error", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}}}}}, "Init:Error"},
		{"init running", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, InitContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}, "Init:Running"},
		{"terminated reason", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}}}}}, "OOMKilled"},
		{"succeeded keeps phase", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed"}}}}}}, "Succeeded"},
	}
	for _, c := range cases {
		if got := PodStatus(&c.pod); got != c.want {
			t.Errorf("%s: %q want %q", c.name, got, c.want)
		}
	}
	// a succeeded pod being deleted is not "Terminating"
	now := metav1.Now()
	done := corev1.Pod{ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
	if PodStatus(&done) != "Succeeded" || !PodHealthy(&done) {
		t.Error("succeeded pod under deletion")
	}
	pending := corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending}}
	if PodHealthy(&pending) {
		t.Error("pending is not healthy")
	}
	partial := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{}, {}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Ready: true}}}}
	if PodHealthy(&partial) {
		t.Error("1/2 ready is not healthy")
	}
}

func TestPodRestartsAndRequests(t *testing.T) {
	t1 := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	t2 := metav1.NewTime(t1.Add(time.Hour))
	p := corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
		{RestartCount: 2, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{FinishedAt: t2}}},
		{RestartCount: 3, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{FinishedAt: t1}}},
		{RestartCount: 0},
	}}}
	if n, last := PodRestarts(&p); n != 5 || !last.Equal(t2.Time) {
		t.Errorf("restarts %d last %s", n, last)
	}
	req := func(cpu, mem string) corev1.ResourceRequirements {
		return corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu), corev1.ResourceMemory: resource.MustParse(mem)}}
	}
	pods := []corev1.Pod{
		{Spec: corev1.PodSpec{Containers: []corev1.Container{{Resources: req("250m", "128Mi")}, {Resources: req("1", "1Gi")}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		{Spec: corev1.PodSpec{Containers: []corev1.Container{{Resources: req("4", "4Gi")}}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
		{Spec: corev1.PodSpec{Containers: []corev1.Container{{}}}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
	}
	cpu, mem := SumRequests(pods)
	if cpu != 1250 || mem != 128*1024*1024+1024*1024*1024 {
		t.Errorf("sum: %d %d", cpu, mem)
	}
	l := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("3Gi")}
	if QuantityMilli(l, corev1.ResourceCPU) != 2000 || QuantityValue(l, corev1.ResourceMemory) != 3*1024*1024*1024 || QuantityMilli(l, "pods") != 0 || QuantityValue(l, "pods") != 0 {
		t.Error("quantity helpers")
	}
	if ParseQuantityValue("1Ki") != 1024 || ParseQuantityValue("garbage") != 0 {
		t.Error("ParseQuantityValue")
	}
}

func TestNodeConditions(t *testing.T) {
	n := &corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Message: "kubelet is posting ready status"}, {Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse}}}}
	if !NodeReady(n) {
		t.Error("ready")
	}
	if s, msg := NodeCondition(n, corev1.NodeReady); s != corev1.ConditionTrue || !strings.Contains(msg, "kubelet") {
		t.Errorf("condition: %s %q", s, msg)
	}
	if s, _ := NodeCondition(n, corev1.NodeMemoryPressure); s != "" {
		t.Errorf("absent condition: %q", s)
	}
	n.Status.Conditions[0].Status = corev1.ConditionUnknown
	if NodeReady(n) {
		t.Error("unknown is not ready")
	}
	// NodeAddress falls back to the name; roles default to worker
	bare := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "bare", Labels: map[string]string{"node-role.kubernetes.io/": "empty-role-ignored"}}}
	if NodeAddress(bare, "") != "bare" || strings.Join(NodeRoles(bare), ",") != "worker" || IsControlPlane(bare) {
		t.Errorf("bare node: %q %v", NodeAddress(bare, ""), NodeRoles(bare))
	}
	master := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/master": ""}}}
	if !IsControlPlane(master) || !IsEtcdNode([]corev1.Node{*master}, master) {
		t.Error("legacy master label")
	}
	ext := &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.5"}, {Type: corev1.NodeInternalIP, Address: ""}}}}
	if NodeAddress(ext, "internalip") != "203.0.113.5" {
		t.Error("empty internal IP must fall through to external")
	}
}

func TestIsSystemNamespace(t *testing.T) {
	for _, ns := range []string{"kube-system", "default", "cattle-system", "cattle-fleet-system", "longhorn-system", "cert-manager", "monitoring", "ingress-nginx", "calico-apiserver", "trident"} {
		if !IsSystemNamespace(ns) {
			t.Errorf("%s should be system", ns)
		}
	}
	for _, ns := range []string{"web", "prod-api", "team-a", "kubeflow"} {
		if IsSystemNamespace(ns) {
			t.Errorf("%s should not be system", ns)
		}
	}
}

func TestControlPlaneIsolation(t *testing.T) {
	req := func(cpu, mem string) corev1.ResourceRequirements {
		return corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu), corev1.ResourceMemory: resource.MustParse(mem)}}
	}
	alloc := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("8Gi")}
	s := &Snapshot{
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}},
				Spec:   corev1.NodeSpec{Taints: []corev1.Taint{{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule}, {Key: "CriticalAddonsOnly", Value: "true", Effect: corev1.TaintEffectNoExecute}}},
				Status: corev1.NodeStatus{Allocatable: alloc}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-2", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}},
				Spec:   corev1.NodeSpec{Taints: []corev1.Taint{{Key: "soft", Effect: corev1.TaintEffectPreferNoSchedule}}},
				Status: corev1.NodeStatus{Allocatable: alloc}},
			{ObjectMeta: metav1.ObjectMeta{Name: "w-1"}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kube-apiserver-cp-1", Labels: map[string]string{"component": "kube-apiserver"}}, Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Resources: req("250m", "512Mi")}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "etcd-cp-1", Labels: map[string]string{"component": "etcd"}}, Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "canal-x", OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet"}}}, Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Resources: req("100m", "64Mi")}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "logger-y", OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet"}}}, Spec: corev1.PodSpec{NodeName: "cp-2", Containers: []corev1.Container{{Resources: req("50m", "32Mi")}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "api-1", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet"}}}, Spec: corev1.PodSpec{NodeName: "cp-2", Containers: []corev1.Container{{Resources: req("500m", "256Mi")}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "aaa-first"}, Spec: corev1.PodSpec{NodeName: "cp-2", Containers: []corev1.Container{{}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "done"}, Spec: corev1.PodSpec{NodeName: "cp-2", Containers: []corev1.Container{{Resources: req("9", "9Gi")}}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "elsewhere"}, Spec: corev1.PodSpec{NodeName: "w-1", Containers: []corev1.Container{{Resources: req("9", "9Gi")}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		},
	}
	iso := s.ControlPlaneIsolation()
	if len(iso) != 2 || iso[0].Node != "cp-1" || iso[1].Node != "cp-2" {
		t.Fatalf("isolation rows: %+v", iso)
	}
	cp1 := iso[0]
	if !cp1.Protected || len(cp1.Taints) != 2 || cp1.Taints[1] != "CriticalAddonsOnly=true:NoExecute" || cp1.AllocCPU != 4000 || cp1.AllocMem != 8*1024*1024*1024 {
		t.Errorf("cp-1 taints/alloc: %+v", cp1)
	}
	if len(cp1.UserPods) != 0 || cp1.AllCPUReq != 350 || cp1.UserCPUReq != 0 {
		t.Errorf("cp-1 pods: %+v", cp1)
	}
	if a := cp1.CPComponents["kube-apiserver"]; !a.Set || a.CPUMilli != 250 || a.MemBytes != 512*1024*1024 {
		t.Errorf("apiserver requests: %+v", a)
	}
	if e := cp1.CPComponents["etcd"]; e.Set {
		t.Errorf("etcd without requests: %+v", e)
	}
	cp2 := iso[1]
	if cp2.Protected {
		t.Error("PreferNoSchedule does not protect")
	}
	if strings.Join(cp2.UserPods, ",") != "web/aaa-first,web/api-1" || cp2.UserCPUReq != 500 || cp2.UserMemReq != 256*1024*1024 || cp2.AllCPUReq != 550 {
		t.Errorf("cp-2 user pods: %+v", cp2)
	}
	if strings.Join(cp2.Roles, ",") != "control-plane,etcd" {
		t.Errorf("roles: %v", cp2.Roles)
	}
}

func TestEventHelpers(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mt := func(d time.Duration) metav1.Time { return metav1.NewTime(base.Add(d)) }
	e := &corev1.Event{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: mt(0)}}
	if !EventTime(e).Equal(base) || EventCount(e) != 1 {
		t.Error("creation timestamp fallback / count 1")
	}
	e.FirstTimestamp = mt(time.Minute)
	if !EventTime(e).Equal(base.Add(time.Minute)) {
		t.Error("first timestamp")
	}
	e.EventTime = metav1.MicroTime{Time: base.Add(2 * time.Minute)}
	if !EventTime(e).Equal(base.Add(2 * time.Minute)) {
		t.Error("event time beats first")
	}
	e.Series = &corev1.EventSeries{Count: 7, LastObservedTime: metav1.MicroTime{Time: base.Add(3 * time.Minute)}}
	if !EventTime(e).Equal(base.Add(3*time.Minute)) || EventCount(e) != 7 {
		t.Error("series beats event time")
	}
	e.LastTimestamp = mt(4 * time.Minute)
	if !EventTime(e).Equal(base.Add(4 * time.Minute)) {
		t.Error("last timestamp wins")
	}
	e.Series = nil
	e.Count = 3
	if EventCount(e) != 3 {
		t.Error("count field")
	}
	s := &Snapshot{Events: []corev1.Event{{Type: "Normal"}, {Type: "Warning"}, {Type: "Warning"}}}
	if len(s.WarningEvents()) != 2 {
		t.Error("warning filter")
	}
}

func TestEtcdPods(t *testing.T) {
	running := corev1.PodStatus{Phase: corev1.PodRunning}
	s := &Snapshot{Pods: []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "etcd-cp-1", Labels: map[string]string{"component": "etcd"}}, Spec: corev1.PodSpec{NodeName: "cp-1"}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "etcd-cp-2"}, Spec: corev1.PodSpec{NodeName: "cp-2"}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "etcd-cp-3", Labels: map[string]string{"component": "etcd"}}, Spec: corev1.PodSpec{NodeName: "cp-3"}, Status: corev1.PodStatus{Phase: corev1.PodPending}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "etcd-backup-job"}, Spec: corev1.PodSpec{NodeName: "cp-1"}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "etcd", Name: "etcd-cp-4", Labels: map[string]string{"component": "etcd"}}, Spec: corev1.PodSpec{NodeName: "cp-4"}, Status: running},
	}}
	pods := s.EtcdPods()
	if len(pods) != 2 || pods["cp-1"] == nil || pods["cp-2"] == nil {
		t.Errorf("etcd pods: %v", pods)
	}
}

func TestDiagHelpers(t *testing.T) {
	pv := func(src corev1.PersistentVolumeSource) *corev1.PersistentVolume {
		return &corev1.PersistentVolume{Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: src}}
	}
	cases := []struct {
		src        corev1.PersistentVolumeSource
		kind, path string
	}{
		{corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "csi.trident.netapp.io"}}, "csi:csi.trident.netapp.io", ""},
		{corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}, "hostPath", "/data"},
		{corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: "/mnt/disk"}}, "local", "/mnt/disk"},
		{corev1.PersistentVolumeSource{NFS: &corev1.NFSVolumeSource{Server: "nas", Path: "/export"}}, "nfs", "nas:/export"},
		{corev1.PersistentVolumeSource{ISCSI: &corev1.ISCSIPersistentVolumeSource{}}, "iscsi", ""},
		{corev1.PersistentVolumeSource{RBD: &corev1.RBDPersistentVolumeSource{}}, "rbd", ""},
		{corev1.PersistentVolumeSource{CephFS: &corev1.CephFSPersistentVolumeSource{}}, "cephfs", ""},
		{corev1.PersistentVolumeSource{}, "other", ""},
	}
	for _, c := range cases {
		if k, p := pvSource(pv(c.src)); k != c.kind || p != c.path {
			t.Errorf("%+v: %q %q", c.src, k, p)
		}
	}
	if (VolumeUsage{}).UsedPct() != -1 || (VolumeUsage{Capacity: 200, Used: 50}).UsedPct() != 25 {
		t.Error("UsedPct")
	}
	if (Stats{Requests: 10, BytesIn: 100, BytesOut: 5, Errors: 2}).Sub(Stats{Requests: 4, BytesIn: 40, BytesOut: 1, Errors: 1}) != (Stats{Requests: 6, BytesIn: 60, BytesOut: 4, Errors: 1}) {
		t.Error("Stats.Sub")
	}
	var nilClient *Client
	if nilClient.Stats() != (Stats{}) || nilClient.DeniedList() != nil {
		t.Error("nil client accessors")
	}
	nilClient.ResetDenied()
	if _, ok := nilClient.Denied("x"); ok {
		t.Error("nil client denied")
	}
}

func TestDiag(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	f.set("/api/v1/persistentvolumes", corev1.PersistentVolumeList{TypeMeta: tm("PersistentVolumeList"), Items: []corev1.PersistentVolume{
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}, Spec: corev1.PersistentVolumeSpec{StorageClassName: "local", ClaimRef: &corev1.ObjectReference{Namespace: "web", Name: "data"}, PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}}},
	}})
	// a running pod mounting a claim on w-1, whose kubelet reports nothing
	f.set("/api/v1/pods", corev1.PodList{TypeMeta: tm("PodList"), Items: []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "nginx-a"}, Spec: corev1.PodSpec{NodeName: "w-1", Volumes: []corev1.Volume{{Name: "d", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "etcd-cp-1", Labels: map[string]string{"component": "etcd"}}, Spec: corev1.PodSpec{NodeName: "cp-1"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	}})
	f.denyWith("/api/v1/nodes/cp-1/proxy/configz", http.StatusForbidden)
	f.setRaw("/api/v1/nodes/w-1/proxy/stats/summary", http.StatusOK, `{"pods":[{"podRef":{"name":"nginx-a","namespace":"web"},"volume":[{"name":"d","capacityBytes":10,"usedBytes":1}]}]}`)
	c := f.client(t, DefaultOptions())
	called := false
	SetEtcdDiag(func(_ context.Context, cc *Client, node, pod string, w io.Writer) {
		called = cc == c && node == "cp-1" && pod == "etcd-cp-1"
	})
	t.Cleanup(func() { SetEtcdDiag(nil) })
	var out bytes.Buffer
	c.Diag(context.Background(), &out)
	text := out.String()
	for _, want := range []string{
		"server version: v1.30.4+rke2r1",
		"nodes: 2   PVCs: 1 (0 bound)",
		"pv-1", "hostPath", "web/data", "/data", "by source: map[hostPath:1]",
		"[cp-1]", "configz:       ERROR", "stats/summary: ok", "used 250B of 1000B (25%) pod web/nginx-b",
		"[w-1]", "claims mounted by running pods here: 1", "NOTE: pods here mount web/data but the kubelet reported no pvcRef volumes", "raw volume sample:",
		"== metrics.k8s.io ==", "ok, 2 nodes",
		"etcd-cp-1: ERROR",
		fmt.Sprintf("%-28s ok", "secrets (helm releases)"), fmt.Sprintf("%-28s ok", "events"), fmt.Sprintf("%-28s ok", "clusterrolebindings"), fmt.Sprintf("%-28s ok", "customresourcedefinitions"), fmt.Sprintf("%-28s ok", "readyz"),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("diag output lacks %q\n%s", want, text)
		}
	}
	if !called {
		t.Error("etcd diag hook not called for the running etcd pod")
	}

	// no nodes at all stops early; no etcd pod says so
	f.denyWith("/api/v1/nodes", http.StatusForbidden)
	out.Reset()
	c.Diag(context.Background(), &out)
	if !strings.Contains(out.String(), "list nodes: ERROR") || strings.Contains(out.String(), "== metrics") {
		t.Errorf("early return:\n%s", out.String())
	}
	f.deny = map[string]int{}
	f.set("/api/v1/pods", corev1.PodList{TypeMeta: tm("PodList")})
	f.denyWith("/version", http.StatusInternalServerError)
	out.Reset()
	c.Diag(context.Background(), &out)
	if !strings.Contains(out.String(), "server version: ERROR") || !strings.Contains(out.String(), "no running etcd pod") {
		t.Errorf("errors:\n%s", out.String())
	}
}
