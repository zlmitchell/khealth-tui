package checks

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
)

// cloudInput: a vSphere cluster where one node was grabbed by the rke2 stub
// controller, one is still uninitialised, the vSphere CSI controller crash
// loops, a Trident SAN backend failed and a StorageClass points at a driver
// that is not installed.
func cloudInput() Input {
	in := baseInput()
	s := in.Snap
	s.Taken = now
	s.Nodes[1].Spec.ProviderID = "rke2://cp-2"
	s.Nodes[0].Spec.ProviderID = "vsphere://4212aaaa"
	s.Nodes[2].Spec.Taints = append(s.Nodes[2].Spec.Taints, corev1.Taint{Key: "node.cloudprovider.kubernetes.io/uninitialized", Value: "true", Effect: corev1.TaintEffectNoSchedule})
	one := int32(1)
	s.DaemonSets = []appsv1.DaemonSet{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "rancher-vsphere-cpi-cloud-controller-manager"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 3}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "vsphere-csi-node"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 3}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "trident", Name: "trident-node-linux"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 3}},
	}
	s.Deployments = []appsv1.Deployment{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "vsphere-csi-controller"}, Spec: appsv1.DeploymentSpec{Replicas: &one}, Status: appsv1.DeploymentStatus{Replicas: 1}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "trident", Name: "trident-controller"}, Spec: appsv1.DeploymentSpec{Replicas: &one}, Status: appsv1.DeploymentStatus{Replicas: 1, ReadyReplicas: 1}},
	}
	s.Pods = []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "vsphere-csi-controller-x"}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "cloud-controller-manager-cp-1", Annotations: map[string]string{"kubernetes.io/config.source": "file"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	}
	s.CSIDrivers = []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "csi.vsphere.vmware.com"}}, {ObjectMeta: metav1.ObjectMeta{Name: "csi.trident.netapp.io"}}}
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		s.CSINodes = append(s.CSINodes, storagev1.CSINode{ObjectMeta: metav1.ObjectMeta{Name: n}, Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{{Name: "csi.vsphere.vmware.com"}, {Name: "csi.trident.netapp.io"}}}})
	}
	s.StorageClasses = []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "ghost"}, Provisioner: "ebs.csi.aws.com"}}
	s.TridentBackends = []k8s.TridentBackend{{BackendName: "san-1", State: "failed", Driver: "ontap-san"}, {BackendName: "nas-1", State: "online", Online: true, Driver: "ontap-nas"}}
	s.VSphereConf = &k8s.VSphereConf{VCenters: []string{"vc.corp"}, SecretRef: "kube-system/vsphere-cpi-creds"}
	s.SecretNames = map[string]bool{}
	return in
}

func TestCloudFindings(t *testing.T) {
	in := cloudInput()
	ni := &nodeinfo.Info{Node: "cp-2", Dist: "rke2", DataDir: "/var/lib/rancher/rke2", KubeletFlags: map[string]string{"cloud-provider": "external"}, Sysctl: map[string]string{}, Settings: map[string]string{}, Hardening: map[string]string{}}
	ni.Preflight = nodeinfo.Preflight{Probed: true, Units: map[string]nodeinfo.PFUnit{"multipathd.service": {Active: true}},
		Virt: nodeinfo.VirtInfo{Vendor: "VMware, Inc.", VMTools: true, WWNDisks: 0}, VCenters: []nodeinfo.VCenterProbe{{Host: "vc.corp", Code: 0, Exit: 7}},
		CSI:      nodeinfo.CSIInfo{Drivers: []string{"csi.trident.netapp.io", "csi.vsphere.vmware.com"}, ISCSID: false, FindMultipaths: "yes", MountNFS: false, MultipathBlacklist: -1},
		SudoUser: "root", Today: 20000, Accounts: []nodeinfo.Account{{Name: "root", PW: "set", LastChange: 19990, Max: 99999, Inactive: -1, Expire: -1}}}
	in.Nodes["cp-2"] = ni
	f := Evaluate(in)
	want := []struct {
		sev    Severity
		area   string
		substr string
	}{
		{SevWarn, "cloud", "rke2's embedded cloud-controller runs alongside the vsphere cloud controller"},
		{SevCrit, "cloud", "node still carries the node.cloudprovider.kubernetes.io/uninitialized taint"},
		{SevCrit, "cloud", "node was initialised by the embedded rke2 cloud-controller (providerID rke2://cp-2)"},
		{SevCrit, "storage", "vSphere CSI controller not healthy: 0/1 ready (vsphere-csi-controller-x: CrashLoopBackOff)"},
		{SevCrit, "storage", "Trident backend san-1 (ontap-san) is failed"},
		{SevCrit, "cloud", "vsphere.conf references credentials secret kube-system/vsphere-cpi-creds which does not exist"},
		{SevWarn, "cloud", "vsphere.conf lists no datacenters"},
		{SevWarn, "storage", "StorageClass provisioner ebs.csi.aws.com has no CSIDriver object"},
		{SevCrit, "storage", "no /dev/disk/by-id/wwn-* on this VMware VM"},
		{SevCrit, "cloud", "vCenter vc.corp unreachable from the node (curl exit 7)"},
		{SevWarn, "storage", "Trident SAN backend in use but iscsid is not running"},
		{SevWarn, "storage", "multipath.conf find_multipaths is yes"},
		{SevWarn, "storage", "Trident NAS backend in use but mount.nfs is missing"},
	}
	for _, w := range want {
		if findingWith(f, w.sev, w.area, w.substr) == nil {
			t.Errorf("missing %s/%s finding containing %q", w.sev, w.area, w.substr)
		}
	}
	for _, x := range f {
		if strings.Contains(x.Message, "Trident controller not healthy") || strings.Contains(x.Message, "backend nas-1") {
			t.Errorf("unexpected: %s", x.Message)
		}
	}
}

func TestCloudKubeletFlagMismatch(t *testing.T) {
	in := cloudInput()
	ni := &nodeinfo.Info{Node: "cp-1", Dist: "rke2", KubeletFlags: map[string]string{"cloud-provider": "rke2"}, Sysctl: map[string]string{}, Settings: map[string]string{}, Hardening: map[string]string{}}
	in.Nodes["cp-1"] = ni
	f := Evaluate(in)
	if findingWith(f, SevCrit, "cloud", "kubelet runs with --cloud-provider=rke2 while the vsphere cloud controller is installed") == nil {
		t.Error("expected the kubelet cloud-provider mismatch finding")
	}
}

func TestProvisioningUserFindings(t *testing.T) {
	in := baseInput()
	in.Now = time.Now()
	ni := &nodeinfo.Info{Node: "cp-1", Dist: "rke2", DataDir: "/var/lib/rancher/rke2", ControlPlane: true, EtcdUser: true, KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Settings: map[string]string{"profile": "cis"}, Hardening: map[string]string{},
		Perms: []nodeinfo.Perm{{Path: "/var/lib/rancher/rke2/server/db/etcd", Mode: "700", User: "root", Group: "root"}}}
	ni.Preflight = nodeinfo.Preflight{Probed: true, Units: map[string]nodeinfo.PFUnit{}, SudoUser: "root", Today: 20000,
		LoginDefs: map[string]string{"PASS_MAX_DAYS": "60"},
		CIUsers:   []string{"rancher"}, CIDefault: "rocky",
		Sudo: map[string]nodeinfo.SudoInfo{"rancher": {NoPasswd: false, Keys: 1}},
		Accounts: []nodeinfo.Account{
			{Name: "root", PW: "set", LastChange: 19990, Max: 99999, Inactive: -1, Expire: -1},
			{Name: "rancher", UID: 1000, Shell: "/bin/bash", PW: "set", LastChange: 19990, Max: 60, Inactive: 35, Expire: -1},
			{Name: "etcd", UID: 1002, Shell: "/bin/bash", PW: "set", LastChange: 19990, Max: 60, Inactive: -1, Expire: -1},
		}}
	in.Nodes["cp-1"] = ni
	f := Evaluate(in)
	for _, w := range []string{
		"provisioning user rancher (cloud-init) has a password with aging (max 60 days, PASS_MAX_DAYS=60)",
		"provisioning user rancher must type its password for sudo",
		"etcd user does not match the RKE2 STIG (useradd -r -s /sbin/nologin -M etcd -U): uid 1002 is not a system uid, shell /bin/bash, has a password (aging applies)",
		"etcd data directory is owned by root:root, not etcd:etcd",
	} {
		found := false
		for _, x := range f {
			if strings.Contains(x.Message, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing finding containing %q", w)
		}
	}
	// locked password, NOPASSWD sudo, key auth: nothing to say
	ni.Preflight.Accounts[1].PW = "locked"
	ni.Preflight.Sudo["rancher"] = nodeinfo.SudoInfo{NoPasswd: true, Keys: 1}
	for _, x := range Evaluate(in) {
		if strings.Contains(x.Message, "provisioning user") {
			t.Errorf("unexpected: %s", x.Message)
		}
	}
	// no etcd user with profile cis
	ni.EtcdUser = false
	ni.Preflight.Accounts = ni.Preflight.Accounts[:2]
	if findingWith(Evaluate(in), SevCrit, "security", "profile: cis is set but there is no etcd user") == nil {
		t.Error("expected the missing etcd user finding")
	}
}
