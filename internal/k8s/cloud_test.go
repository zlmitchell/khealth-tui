package k8s

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func cloudSnapshot() *Snapshot {
	now := time.Now()
	one := int32(1)
	ds := func(ns, name string, desired, ready int32) appsv1.DaemonSet {
		return appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: desired, NumberReady: ready}}
	}
	dep := func(ns, name string, ready int32) appsv1.Deployment {
		return appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: appsv1.DeploymentSpec{Replicas: &one}, Status: appsv1.DeploymentStatus{Replicas: 1, ReadyReplicas: ready}}
	}
	s := &Snapshot{Taken: now}
	s.Nodes = []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"topology.kubernetes.io/zone": "z1"}}, Spec: corev1.NodeSpec{ProviderID: "vsphere://4212aaaa-bbbb"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "w-1"}, Spec: corev1.NodeSpec{ProviderID: "rke2://w-1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "w-2"}, Spec: corev1.NodeSpec{Taints: []corev1.Taint{{Key: uninitializedTaint, Value: "true", Effect: corev1.TaintEffectNoSchedule}}}},
	}
	s.DaemonSets = []appsv1.DaemonSet{ds("kube-system", "rancher-vsphere-cpi-cloud-controller-manager", 1, 1), ds("kube-system", "vsphere-csi-node", 3, 2), ds("trident", "trident-node-linux", 3, 3)}
	s.Deployments = []appsv1.Deployment{dep("kube-system", "vsphere-csi-controller", 0), dep("trident", "trident-controller", 1)}
	s.Pods = []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "vsphere-csi-controller-abc"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "vsphere-csi-controller", RestartCount: 12, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: "failed to connect to vCenter\nmore"}}}}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "cloud-controller-manager-cp-1", Annotations: map[string]string{"kubernetes.io/config.source": "file"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "rke2-ccm"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	}
	s.CSIDrivers = []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "csi.vsphere.vmware.com"}}, {ObjectMeta: metav1.ObjectMeta{Name: "csi.trident.netapp.io"}}}
	s.CSINodes = []storagev1.CSINode{
		{ObjectMeta: metav1.ObjectMeta{Name: "cp-1"}, Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{{Name: "csi.vsphere.vmware.com"}, {Name: "csi.trident.netapp.io"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "w-1"}, Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{{Name: "csi.vsphere.vmware.com"}, {Name: "csi.trident.netapp.io"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "w-2"}, Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{{Name: "csi.trident.netapp.io"}}}},
	}
	s.StorageClasses = []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "vsphere"}, Provisioner: "csi.vsphere.vmware.com"}, {ObjectMeta: metav1.ObjectMeta{Name: "ontap-nas"}, Provisioner: "csi.trident.netapp.io"}, {ObjectMeta: metav1.ObjectMeta{Name: "ghost"}, Provisioner: "ebs.csi.aws.com"}}
	s.PVs = []corev1.PersistentVolume{{ObjectMeta: metav1.ObjectMeta{Name: "pvc-11111111-1111-1111-1111-111111111111"}, Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "csi.vsphere.vmware.com"}}}}}
	s.Events = []corev1.Event{{Reason: "FailedAttachVolume", Message: `AttachVolume.Attach failed for volume "pvc-11111111-1111-1111-1111-111111111111" : rpc error: code = Internal`, Count: 3, LastTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)), InvolvedObject: corev1.ObjectReference{Namespace: "app", Name: "db-0"}}}
	s.TridentBackends = []TridentBackend{{Namespace: "trident", Name: "tbe-1", BackendName: "ontap-nas-1", State: "online", Online: true, Driver: "ontap-nas"}, {Namespace: "trident", Name: "tbe-2", BackendName: "ontap-san-1", State: "failed", Online: false, Driver: "ontap-san"}}
	s.VSphereConf = &VSphereConf{VCenters: []string{"vc.corp:443"}, Datacenters: []string{"DC1"}, Insecure: true, SecretRef: "kube-system/vsphere-cpi-creds"}
	s.SecretNames = map[string]bool{"kube-system/vsphere-cpi-creds": true}
	return s
}

func TestCloud(t *testing.T) {
	ci := cloudSnapshot().Cloud()
	if ci.Provider != "vsphere" || len(ci.CCMs) != 2 {
		t.Fatalf("provider %q ccms %+v", ci.Provider, ci.CCMs)
	}
	if stub := ci.Component("rke2", "ccm"); stub == nil || stub.Kind != "StaticPod" || stub.Ready != 1 {
		t.Errorf("stub: %+v", stub)
	}
	var uninit, rke2ID int
	for _, n := range ci.Nodes {
		if n.Uninitialized {
			uninit++
		}
		if n.ProviderID == "rke2://w-1" {
			rke2ID++
		}
		if n.Name == "cp-1" && n.Zone != "z1" {
			t.Errorf("zone: %+v", n)
		}
	}
	if uninit != 1 || rke2ID != 1 {
		t.Errorf("nodes: %+v", ci.Nodes)
	}
	if len(ci.CSI) != 2 {
		t.Fatalf("csi: %+v", ci.CSI)
	}
	tr, vs := ci.CSI[0], ci.CSI[1]
	if tr.Driver != "csi.trident.netapp.io" || tr.Registered != 3 || len(tr.Missing) != 0 || tr.Controller == nil || !tr.Controller.OK() || tr.NodePlugin == nil || len(tr.Trident) != 2 {
		t.Errorf("trident: %+v", tr)
	}
	if vs.Registered != 2 || len(vs.Missing) != 1 || vs.Missing[0] != "w-2" || vs.PVs != 1 || len(vs.StorageCls) != 1 {
		t.Errorf("vsphere: %+v", vs)
	}
	if vs.Controller == nil || vs.Controller.OK() || vs.Controller.Restarts != 12 || vs.Controller.Problem != "vsphere-csi-controller-abc: CrashLoopBackOff (failed to connect to vCenter)" {
		t.Errorf("vsphere controller: %+v", vs.Controller)
	}
	if vs.NodePlugin == nil || vs.NodePlugin.Ready != 2 || vs.NodePlugin.Desired != 3 {
		t.Errorf("vsphere node plugin: %+v", vs.NodePlugin)
	}
	if len(vs.Failures) != 1 || vs.Failures[0].Reason != "FailedAttachVolume" || vs.Failures[0].Object != "app/db-0" {
		t.Errorf("failures: %+v", vs.Failures)
	}
	if vs.VSphere == nil || !vs.VSphere.SecretFound || vs.VSphere.VCenters[0] != "vc.corp:443" {
		t.Errorf("vsphere conf: %+v", vs.VSphere)
	}
}

func TestParseVSphereConf(t *testing.T) {
	v := parseVSphereConf(`[Global]
port = "443"
insecure-flag = "true"
secret-name = "vsphere-cpi-creds"
secret-namespace = "kube-system"

[VirtualCenter "vc1.corp"]
datacenters = "DC1, DC2"

[VirtualCenter "vc2.corp"]
port = 8443
datacenters = "DC3"
`)
	if len(v.VCenters) != 2 || v.VCenters[0] != "vc1.corp:443" || v.VCenters[1] != "vc2.corp:8443" {
		t.Errorf("vcenters: %v", v.VCenters)
	}
	if len(v.Datacenters) != 3 || !v.Insecure || v.SecretRef != "kube-system/vsphere-cpi-creds" {
		t.Errorf("conf: %+v", v)
	}
}
