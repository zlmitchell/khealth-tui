package checks

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// Regression tests for checks that fired on healthy clusters, each with
// the scenario that used to produce the false finding.

func TestRancherPlanFailedThenApplied(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	line := func(at, msg string) string {
		return "2026-10-11T" + at + "+00:00 w-1 rancher-system-agent[900]: time=\"2026-10-11T" + at + "Z\" level=info msg=\"" + msg + "\""
	}
	failed := []string{
		line("09:00:00", "[Applyinator] Applying one-time instructions for plan with checksum abc"),
		line("09:00:40", "[Applyinator] Command sh [-c run.sh] finished with err: exit status 1 and exit code: 1"),
	}
	in := Input{Snap: &k8s.Snapshot{}, Cfg: config.Default(), Now: now, Logs: map[string]*logs.Summary{"w-1": logs.Classify(failed, now)}}
	if findingWith(Evaluate(in), SevCrit, "node", "Rancher plan failed 1 time(s)") == nil {
		t.Error("a failed plan with no later apply must stay CRIT")
	}
	retried := append(failed,
		line("10:00:00", "[Applyinator] Applying one-time instructions for plan with checksum def"),
		line("10:00:30", "[Applyinator] Command sh [-c run.sh] finished with err: <nil> and exit code: 0"))
	in.Logs["w-1"] = logs.Classify(retried, now)
	fs := Evaluate(in)
	if f := findingWith(fs, SevCrit, "node", "Rancher plan failed"); f != nil {
		t.Errorf("failure followed by a successful apply still CRIT: %s", f.Message)
	}
	if findingWith(fs, SevInfo, "node", "then a later plan was applied") == nil {
		t.Error("the earlier failure should remain visible as INFO")
	}
}

func TestPendingClaimWaitForFirstConsumer(t *testing.T) {
	now := time.Now()
	wffc, imm := storagev1.VolumeBindingWaitForFirstConsumer, storagev1.VolumeBindingImmediate
	lp, lh := "local-path", "longhorn"
	old := metav1.NewTime(now.Add(-time.Hour))
	claim := func(name string, sc *string) corev1.PersistentVolumeClaim {
		return corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, CreationTimestamp: old},
			Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: sc}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
	}
	snap := &k8s.Snapshot{
		StorageClasses: []storagev1.StorageClass{
			{ObjectMeta: metav1.ObjectMeta{Name: lp}, VolumeBindingMode: &wffc},
			{ObjectMeta: metav1.ObjectMeta{Name: lh}, VolumeBindingMode: &imm},
		},
		PVCs: []corev1.PersistentVolumeClaim{claim("unused-wffc", &lp), claim("used-wffc", &lp), claim("immediate", &lh)},
		Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "p", CreationTimestamp: old},
			Spec:   corev1.PodSpec{Volumes: []corev1.Volume{{Name: "d", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "used-wffc"}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodPending}}},
	}
	fs := Evaluate(Input{Snap: snap, Cfg: config.Default(), Now: now})
	pending := map[string]bool{}
	for _, f := range fs {
		if f.Area == "storage" && f.Message == "Pending" {
			pending[f.Object] = true
		}
	}
	if pending["app/pvc/unused-wffc"] {
		t.Error("an unused WaitForFirstConsumer claim is Pending by design")
	}
	if !pending["app/pvc/used-wffc"] || !pending["app/pvc/immediate"] {
		t.Errorf("claims that should bind are not reported: %v", pending)
	}
}

func TestCNIRestartsOnlyRecent(t *testing.T) {
	now := time.Now()
	cni := func(restarts int32, ago time.Duration, reason string, code int32) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "rke2-canal-x", Labels: map[string]string{"k8s-app": "canal"}},
			Spec: corev1.PodSpec{NodeName: "cp-1"},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "calico-node", RestartCount: restarts,
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, ExitCode: code, FinishedAt: metav1.NewTime(now.Add(-ago))}}}}}}
	}
	run := func(p corev1.Pod) *Finding {
		fs := Evaluate(Input{Snap: &k8s.Snapshot{Pods: []corev1.Pod{p}}, Cfg: config.Default(), Now: now})
		for i := range fs {
			if fs[i].Area == "network" && strings.Contains(fs[i].Message, "CNI pod") {
				return &fs[i]
			}
		}
		return nil
	}
	if f := run(cni(7, 40*24*time.Hour, "Error", 1)); f != nil {
		t.Errorf("restarts 40 days ago still reported: %s", f.Message)
	}
	if f := run(cni(7, 10*time.Minute, "Error", 1)); f == nil || f.Severity != SevWarn {
		t.Errorf("recent crash loop: %+v", f)
	}
	if f := run(cni(7, 10*time.Minute, "Unknown", 255)); f == nil || f.Severity != SevInfo {
		t.Errorf("a node reboot is not the agent failing: %+v", f)
	}
}

func TestClockSkewAgainstOtherNodes(t *testing.T) {
	ni := func(off time.Duration) *nodeinfo.Info {
		return &nodeinfo.Info{ClockOffset: off, Settings: map[string]string{}}
	}
	run := func(offs ...time.Duration) []Finding {
		in := Input{Snap: &k8s.Snapshot{}, Cfg: config.Default(), Now: time.Now(), Nodes: map[string]*nodeinfo.Info{}}
		for i, o := range offs {
			in.Nodes["n"+string(rune('1'+i))] = ni(o)
		}
		var out []Finding
		for _, f := range Evaluate(in) {
			if strings.Contains(f.Message, "clock") {
				out = append(out, f)
			}
		}
		return out
	}
	// this machine 30s behind the cluster: one INFO, no node blamed
	fs := run(30*time.Second, 30*time.Second+200*time.Millisecond, 29*time.Second)
	if len(fs) != 1 || fs[0].Severity != SevInfo || fs[0].Object != "clock" {
		t.Errorf("skewed workstation: %+v", fs)
	}
	// two nodes: this machine breaks the tie
	fs = run(0, 20*time.Second)
	if len(fs) != 1 || fs[0].Object != "n2" || fs[0].Severity != SevWarn {
		t.Errorf("two nodes, one skewed: %+v", fs)
	}
	// one node 20s ahead of the other two
	fs = run(0, 100*time.Millisecond, 20*time.Second)
	if len(fs) != 1 || fs[0].Object != "n3" || fs[0].Severity != SevWarn {
		t.Errorf("one skewed node: %+v", fs)
	}
}

func TestCertExpiryLevels(t *testing.T) {
	now := time.Now()
	in := Input{Snap: &k8s.Snapshot{}, Cfg: config.Default(), Now: now, Nodes: map[string]*nodeinfo.Info{"cp-1": {Dist: "rke2", Settings: map[string]string{}, Certs: []nodeinfo.Cert{
		{Path: "/var/lib/rancher/rke2/server/tls/client-admin.crt", NotAfter: now.Add(3 * 24 * time.Hour)},
		{Path: "/var/lib/rancher/rke2/server/tls/serving-kube-apiserver.crt", NotAfter: now.Add(20 * 24 * time.Hour)},
		{Path: "/var/lib/rancher/rke2/server/tls/server-ca.crt", NotAfter: now.Add(20 * 24 * time.Hour)},
	}}}}
	fs := Evaluate(in)
	if f := findingWith(fs, SevCrit, "node", "client-admin.crt"); f == nil || !strings.Contains(f.Hint, "120 days") {
		t.Errorf("3 days left: %+v", f)
	}
	if f := findingWith(fs, SevWarn, "node", "serving-kube-apiserver.crt"); f == nil || f.Hint == "" {
		t.Errorf("20 days left needs a hint: %+v", f)
	}
	if f := findingWith(fs, SevWarn, "node", "server-ca.crt"); f == nil || !strings.Contains(f.Hint, "rotate-ca") {
		t.Errorf("a CA is not renewed by a restart: %+v", f)
	}
}

func TestSystemDeploymentNoneAvailable(t *testing.T) {
	now := time.Now()
	two := int32(2)
	dep := func(ns string, avail int32) appsv1.Deployment {
		return appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "d", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
			Spec: appsv1.DeploymentSpec{Replicas: &two}, Status: appsv1.DeploymentStatus{AvailableReplicas: avail, UnavailableReplicas: 2 - avail}}
	}
	sev := func(d appsv1.Deployment) Severity {
		for _, f := range Evaluate(Input{Snap: &k8s.Snapshot{Deployments: []appsv1.Deployment{d}}, Cfg: config.Default(), Now: now}) {
			if strings.Contains(f.Object, "/deploy/") {
				return f.Severity
			}
		}
		return -1
	}
	if s := sev(dep("kube-system", 0)); s != SevCrit {
		t.Errorf("kube-system 0/2: %v", s)
	}
	if s := sev(dep("kube-system", 1)); s != SevWarn {
		t.Errorf("kube-system 1/2: %v", s)
	}
	if s := sev(dep("shop", 0)); s != SevWarn {
		t.Errorf("app namespace 0/2: %v", s)
	}
}

// evalPreflightNode runs Evaluate on one preflightInfo node after mod.
func evalPreflightNode(mod func(ni *nodeinfo.Info)) []Finding {
	in := baseInput()
	ni := preflightInfo()
	mod(ni)
	in.Nodes["cp-1"] = ni
	return Evaluate(in)
}

func TestAuditdHalfFullIsNotNear(t *testing.T) {
	stig := func(usePct int, availKB int64) func(*nodeinfo.Info) {
		return func(ni *nodeinfo.Info) {
			ni.Mounts[1] = nodeinfo.Mount{Mountpoint: "/var/log/audit", SizeKB: 20e6, AvailKB: availKB, UsePct: usePct}
			ni.Preflight.Auditd = map[string]string{"space_left": "25%", "space_left_action": "email", "admin_space_left": "5%", "admin_space_left_action": "single", "disk_full_action": "HALT", "disk_error_action": "HALT"}
		}
	}
	if f := findingWith(evalPreflightNode(stig(55, 9e6)), SevCrit, "node", "auditd"); f != nil {
		t.Errorf("STIG auditd at 55%%: %s", f.Message)
	}
	f := findingWith(evalPreflightNode(stig(78, 4.4e6)), SevCrit, "node", "auditd")
	if f == nil {
		t.Fatal("past space_left (25% free) must be CRIT")
	}
	if strings.Contains(f.Message, "disk_error_action") {
		t.Errorf("disk_error_action is about I/O errors: %s", f.Message)
	}
}

func TestFapolicydDenialAge(t *testing.T) {
	deny := func(ago time.Duration) func(*nodeinfo.Info) {
		return func(ni *nodeinfo.Info) {
			ni.Preflight.Denies = []nodeinfo.FapDeny{{Count: 3, Exe: "/root/khtest-runc", Path: "/root/khtest-runc", Last: now.Add(-ago)}}
		}
	}
	if findingWith(evalPreflightNode(deny(5*time.Minute)), SevCrit, "node", "fapolicyd denied 3") == nil {
		t.Error("a denial minutes ago is CRIT")
	}
	if findingWith(evalPreflightNode(deny(3*time.Hour)), SevWarn, "node", "fapolicyd denied 3") == nil {
		t.Error("the last denial hours ago is WARN")
	}
}

func TestFaillockUnlockTime(t *testing.T) {
	lock := func(unlock, age int) func(*nodeinfo.Info) {
		return func(ni *nodeinfo.Info) {
			ni.Preflight.Faillock = map[string]int{"zach": 3}
			ni.Preflight.FaillockAge = map[string]int{"zach": age}
			ni.Preflight.FaillockDeny, ni.Preflight.FaillockUnlock = 3, unlock
		}
	}
	if findingWith(evalPreflightNode(lock(60, 30)), SevWarn, "security", "zach is locked out") == nil {
		t.Error("within unlock_time: locked")
	}
	if f := findingWith(evalPreflightNode(lock(60, 120)), SevWarn, "security", "zach is locked out"); f != nil {
		t.Errorf("unlock_time passed: %s", f.Message)
	}
	if findingWith(evalPreflightNode(lock(0, 99999)), SevWarn, "security", "zach is locked out") == nil {
		t.Error("unlock_time=0 stays locked until reset")
	}
}

func TestProxyByConsumer(t *testing.T) {
	proxy := func(lines ...nodeinfo.ProxyLine) func(*nodeinfo.Info) {
		return func(ni *nodeinfo.Info) { ni.Preflight.Proxy = lines }
	}
	fs := evalPreflightNode(proxy(nodeinfo.ProxyLine{File: "/etc/environment", Key: "HTTP_PROXY", Value: "http://proxy:3128"}))
	if f := findingWith(fs, SevWarn, "node", "NO_PROXY"); f != nil {
		t.Errorf("/etc/environment is not read by the units: %s", f.Message)
	}
	if findingWith(fs, SevInfo, "node", "set in /etc/environment only") == nil {
		t.Error("the shell-only proxy should be mentioned")
	}
	fs = evalPreflightNode(proxy(nodeinfo.ProxyLine{File: "/etc/default/rke2-server", Key: "CONTAINERD_HTTPS_PROXY", Value: "http://proxy:3128"}))
	if f := findingWith(fs, SevWarn, "node", "without NO_PROXY"); f == nil || !strings.Contains(f.Message, "image pulls") {
		t.Errorf("containerd-only proxy: %+v", f)
	}
}

func TestNonKubernetesPlanNotComparedWithKubelets(t *testing.T) {
	now := time.Now()
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"plan.upgrade.cattle.io/system-agent-upgrader": "h1"}},
		Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.35.8+rke2r1"}}}
	snap := &k8s.Snapshot{Version: "v1.35.8+rke2r1", Distribution: "rke2", Nodes: []corev1.Node{n},
		Upgrade: &k8s.UpgradeInfo{PlansCRD: true, Plans: []k8s.UpgradePlan{{Namespace: "cattle-system", Name: "system-agent-upgrader", Version: "v0.3.12", Latest: "v0.3.12", Hash: "h1", Image: "rancher/system-agent"}}}}
	for _, f := range Evaluate(Input{Snap: snap, Cfg: config.Default(), Now: now}) {
		if f.Area == "upgrade" && f.Severity >= SevWarn {
			t.Errorf("agent plan compared with kubelets: %s", f.Message)
		}
	}
}

func TestKubeletAheadDuringControlPlaneUpgrade(t *testing.T) {
	kn := func(name, v string, cp bool) corev1.Node {
		l := map[string]string{}
		if cp {
			l["node-role.kubernetes.io/control-plane"] = "true"
		}
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: l}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: v}}}
	}
	sevOf := func(snap *k8s.Snapshot, node string) Severity {
		for _, f := range Evaluate(Input{Snap: snap, Cfg: config.Default(), Now: time.Now()}) {
			if f.Area == "upgrade" && f.Object == node {
				return f.Severity
			}
		}
		return -1
	}
	// cp-1 upgraded, cp-2 (old) answered: the documented order
	snap := &k8s.Snapshot{Version: "v1.34.3", Nodes: []corev1.Node{kn("cp-1", "v1.35.1", true), kn("cp-2", "v1.34.3", true), kn("w-1", "v1.34.3", false)}}
	if s := sevOf(snap, "cp-1"); s != SevWarn {
		t.Errorf("upgraded server mid-upgrade: %v", s)
	}
	// a worker ahead of every control-plane node
	snap.Nodes = []corev1.Node{kn("cp-1", "v1.34.3", true), kn("w-1", "v1.35.1", false)}
	if s := sevOf(snap, "w-1"); s != SevCrit {
		t.Errorf("worker ahead of the control plane: %v", s)
	}
	// 1.27 apiserver allowed only 2 minors of skew
	snap = &k8s.Snapshot{Version: "v1.27.4", Nodes: []corev1.Node{kn("cp-1", "v1.27.4", true), kn("w-1", "v1.24.9", false)}}
	if s := sevOf(snap, "w-1"); s != SevWarn {
		t.Errorf("3 minors behind a 1.27 apiserver: %v", s)
	}
}

func TestNonCSIProvisionerWithoutClaims(t *testing.T) {
	snap := &k8s.Snapshot{StorageClasses: []storagev1.StorageClass{
		{ObjectMeta: metav1.ObjectMeta{Name: "nfs"}, Provisioner: "k8s-sigs.io/nfs-subdir-external-provisioner"},
		{ObjectMeta: metav1.ObjectMeta{Name: "ghost"}, Provisioner: "ghost.csi.example.com"}}}
	fs := Evaluate(Input{Snap: snap, Cfg: config.Default(), Now: time.Now()})
	if f := findingWith(fs, SevWarn, "storage", "nfs-subdir-external-provisioner has no CSIDriver"); f != nil {
		t.Errorf("non-CSI provisioner without pending claims: %s", f.Message)
	}
	if findingWith(fs, SevWarn, "storage", "ghost.csi.example.com has no CSIDriver") == nil {
		t.Error("a missing CSI driver is still a WARN")
	}
}

// IMDS turned off by hardening only matters to AWS integrations.
func TestIMDSOnlyWithAWSIntegration(t *testing.T) {
	aws := func(ni *nodeinfo.Info) {
		ni.Preflight.Virt = nodeinfo.VirtInfo{Vendor: "Amazon EC2", IMDS: "000"}
	}
	if f := findingWith(evalPreflightNode(aws), SevCrit, "cloud", "EC2 instance metadata"); f != nil {
		t.Errorf("no AWS CCM/CSI installed: %s", f.Message)
	}
}

// A volume moving onto this node: the device appears before the cluster
// says "attached", which is not a split brain.
func TestLonghornDeviceWhileAttachingHere(t *testing.T) {
	in := longhornInput()
	ni := &nodeinfo.Info{Node: "cp-3", Dist: "rke2", KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Settings: map[string]string{}, Hardening: map[string]string{}}
	ni.Preflight = nodeinfo.Preflight{Probed: true, Units: map[string]nodeinfo.PFUnit{}, CSI: nodeinfo.CSIInfo{Drivers: []string{"driver.longhorn.io"}, ISCSID: true, MultipathBlacklist: -1,
		LonghornDevs: []string{"pvc-data-db-1"}}, SudoUser: "root", Today: 20000}
	in.Nodes["cp-3"] = ni
	in.Snap.Longhorn.Volumes[1].State, in.Snap.Longhorn.Volumes[1].Node = "attaching", "cp-3"
	if f := findingWith(Evaluate(in), SevCrit, "storage", "still presents /dev/longhorn/pvc-data-db-1"); f != nil {
		t.Errorf("attaching on this very node: %s", f.Message)
	}
}

// More replicas than nodes on a detached volume: it works with fewer
// copies (WARN), it is not unattachable (CRIT).
func TestLonghornPartlyScheduled(t *testing.T) {
	in := longhornInput()
	v := &in.Snap.Longhorn.Volumes[0]
	v.State, v.Robustness, v.Scheduled, v.SchedMessage = "detached", "unknown", false, "replica scheduling failed: no available disks"
	v.ReplicaList = []k8s.LonghornReplica{{Name: "r1", Node: "cp-1"}, {Name: "r2", Node: "cp-2"}, {Name: "r3"}}
	fs := Evaluate(in)
	if f := findingWith(fs, SevCrit, "storage", "cannot schedule its replicas"); f != nil && strings.Contains(f.Message, v.Name) {
		t.Errorf("two of three replicas placed: %s", f.Message)
	}
	if findingWith(fs, SevWarn, "storage", "Longhorn volume "+v.Name+" cannot schedule its replicas") == nil {
		t.Error("the missing replica should still be a WARN")
	}
}

func TestLonghornSoftAntiAffinityReplicaCount(t *testing.T) {
	in := longhornInput() // replica-soft-anti-affinity is true there
	if f := findingWith(Evaluate(in), SevWarn, "storage", "default-replica-count is"); f != nil {
		t.Errorf("soft anti-affinity places extra replicas on the same node: %s", f.Message)
	}
}

func TestCephWarnLevels(t *testing.T) {
	run := func(cc k8s.CephCluster) []Finding {
		in := baseInput()
		in.Snap.CSIDrivers = []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "rbd.csi.ceph.com"}}}
		in.Snap.Ceph = &k8s.CephInfo{Clusters: []k8s.CephCluster{cc},
			Pools: []k8s.CephResource{{Kind: "CephBlockPool", Namespace: "rook-ceph", Name: "ext", Phase: "Connected"}}}
		var out []Finding
		for _, f := range Evaluate(in) {
			if f.Area == "storage" && strings.HasPrefix(f.Object, "rook-ceph/") {
				out = append(out, f)
			}
		}
		return out
	}
	// one monitor of three down, quorum kept; OSDs at 85%: warnings
	fs := run(k8s.CephCluster{Namespace: "rook-ceph", Name: "rook-ceph", Phase: "Ready", Health: "HEALTH_WARN",
		Details: []k8s.CephCheck{{Name: "MON_DOWN", Severity: "HEALTH_WARN", Message: "1/3 mons down, quorum a,b"}, {Name: "OSD_NEARFULL", Severity: "HEALTH_WARN", Message: "1 nearfull osd(s)"}}})
	for _, f := range fs {
		if f.Severity == SevCrit {
			t.Errorf("MON_DOWN with quorum / NEARFULL: %s", f.Message)
		}
	}
	// an external cluster connected and healthy: nothing to say
	if fs := run(k8s.CephCluster{Namespace: "rook-ceph", Name: "rook-ceph", Phase: "Connected", Health: "HEALTH_OK", External: true}); len(fs) != 0 {
		t.Errorf("healthy external cluster: %+v", fs)
	}
	// a cluster being created: WARN, not CRIT
	for _, f := range run(k8s.CephCluster{Namespace: "rook-ceph", Name: "rook-ceph", Phase: "Progressing"}) {
		if f.Severity == SevCrit {
			t.Errorf("Progressing without health yet: %s", f.Message)
		}
	}
}

// A finished Job pod that once mounted the claim elsewhere does not wait
// for the volume: no "both nodes write" CRIT for it.
func TestVolumeAttachmentIgnoresFinishedPods(t *testing.T) {
	in := longhornInput()
	for i := range in.Snap.Pods {
		if in.Snap.Pods[i].Name == "single-new" {
			in.Snap.Pods[i].Status.Phase = corev1.PodSucceeded
			in.Snap.Pods[i].Spec.NodeName = "cp-1"
		}
	}
	if f := findingWith(Evaluate(in), SevCrit, "storage", "volume is still attached to cp-3 (NotReady) while"); f != nil {
		t.Errorf("a completed pod is not waiting: %s", f.Message)
	}
}
