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

// longhornInput mirrors what the redhat9-test cluster looked like with
// node cp-3 partitioned: its kubelet still runs db-1 and single with their
// Longhorn devices attached, the cluster has given up on those volumes,
// the other volumes are degraded and cannot rebuild, a 4-replica volume
// never fit three nodes, a 3 TiB volume never scheduled, a bogus disk on
// cp-1, an orphan, no backup target.
func longhornInput() Input {
	in := baseInput()
	s := in.Snap
	s.Taken = now
	s.Nodes[2] = node("cp-3", false, "10.0.0.3")
	s.DaemonSets = []appsv1.DaemonSet{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Name: "longhorn-manager"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 2}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Name: "longhorn-csi-plugin"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 2}},
	}
	s.CSIDrivers = []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "driver.longhorn.io"}}}
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		s.CSINodes = append(s.CSINodes, storagev1.CSINode{ObjectMeta: metav1.ObjectMeta{Name: n}, Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{{Name: "driver.longhorn.io"}}}})
	}
	pv := func(name string, modes ...corev1.PersistentVolumeAccessMode) corev1.PersistentVolume {
		return corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.PersistentVolumeSpec{AccessModes: modes,
			ClaimRef:               &corev1.ObjectReference{Namespace: "lh-test", Name: strings.TrimPrefix(name, "pvc-")},
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", VolumeHandle: name}}}}
	}
	s.PVs = []corev1.PersistentVolume{pv("pvc-web", corev1.ReadWriteOnce), pv("pvc-data-db-1", corev1.ReadWriteOnce), pv("pvc-single", corev1.ReadWriteOnce), pv("pvc-shared", corev1.ReadWriteMany), pv("pvc-four", corev1.ReadWriteOnce), pv("pvc-huge", corev1.ReadWriteOnce)}
	for _, p := range s.PVs {
		s.PVCs = append(s.PVCs, corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "lh-test", Name: p.Spec.ClaimRef.Name}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: p.Name}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}})
	}
	pod := func(name, node, claim string, phase corev1.PodPhase, terminating bool) corev1.Pod {
		p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "lh-test", Name: name}, Spec: corev1.PodSpec{NodeName: node, Volumes: []corev1.Volume{{Name: "d", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}}}, Status: corev1.PodStatus{Phase: phase}}
		if terminating {
			p.DeletionTimestamp = &metav1.Time{Time: now.Add(-10 * time.Minute)}
		}
		return p
	}
	s.Pods = []corev1.Pod{
		pod("web-1", "cp-1", "web", corev1.PodRunning, false),
		pod("db-1", "cp-3", "data-db-1", corev1.PodRunning, true),
		pod("single-old", "cp-3", "single", corev1.PodRunning, true),
		pod("single-new", "", "single", corev1.PodPending, false),
		pod("shared-a", "cp-1", "shared", corev1.PodRunning, false),
		pod("shared-b", "cp-3", "shared", corev1.PodRunning, true),
		pod("four-1", "cp-2", "four", corev1.PodRunning, false),
	}
	s.StatefulSets = []appsv1.StatefulSet{{ObjectMeta: metav1.ObjectMeta{Namespace: "lh-test", Name: "db"}}}
	va := func(name, pv, node string, attached bool) storagev1.VolumeAttachment {
		return storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: storagev1.VolumeAttachmentSpec{Attacher: "driver.longhorn.io", NodeName: node, Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pv}}, Status: storagev1.VolumeAttachmentStatus{Attached: attached}}
	}
	s.VolumeAttachments = []storagev1.VolumeAttachment{
		va("csi-web", "pvc-web", "cp-1", true),
		va("csi-db1", "pvc-data-db-1", "cp-3", true),
		va("csi-single", "pvc-single", "cp-3", true),
		va("csi-shared-1", "pvc-shared", "cp-1", true),
		va("csi-shared-3", "pvc-shared", "cp-3", true),
		va("csi-four", "pvc-four", "cp-2", true),
	}
	s.VolumeAttachments[0].Status.DetachError = &storagev1.VolumeError{Time: metav1.NewTime(now.Add(-2 * time.Minute)), Message: "rpc error: code = DeadlineExceeded"}
	rep := func(name, node, state, failed, mode string) k8s.LonghornReplica {
		return k8s.LonghornReplica{Name: name, Node: node, State: state, FailedAt: failed, Mode: mode, Rebuild: -1, Active: true}
	}
	vol := func(name, pvc, state, rob, node string, n int, scheduled bool, msg string, reps ...k8s.LonghornReplica) k8s.LonghornVolume {
		v := k8s.LonghornVolume{Name: name, PVC: "lh-test/" + pvc, PV: name, State: state, Robustness: rob, Node: node, Replicas: n, Scheduled: scheduled, SchedMessage: msg, AccessMode: "rwo", Size: 1 << 30, Image: "e:v1.12.1", CurrentImage: "e:v1.12.1", ReplicaList: reps, ReplicaMode: map[string]string{}}
		for _, r := range reps {
			if r.Mode != "" {
				v.ReplicaMode[r.Name] = r.Mode
			}
		}
		return v
	}
	li := &k8s.LonghornInfo{Settings: map[string]string{"default-replica-count": `{"v1":"3","v2":"3"}`, "node-down-pod-deletion-policy": "do-nothing", "upgrade-checker": "true", "concurrent-replica-rebuild-per-node-limit": "0", "replica-soft-anti-affinity": "true"}}
	li.Volumes = []k8s.LonghornVolume{
		vol("pvc-web", "web", "attached", "degraded", "cp-1", 3, false, "precheck new replica failed: disks are unavailable",
			rep("pvc-web-r-1", "cp-1", "running", "", "RW"), rep("pvc-web-r-2", "cp-2", "running", "", "RW"), rep("pvc-web-r-3", "cp-3", "stopped", "2026-09-20T19:13:11Z", "ERR")),
		vol("pvc-data-db-1", "data-db-1", "attached", "unknown", "cp-3", 3, true, "",
			rep("pvc-data-db-1-r-1", "cp-1", "running", "", ""), rep("pvc-data-db-1-r-2", "cp-2", "running", "", ""), rep("pvc-data-db-1-r-3", "cp-3", "unknown", "", "")),
		vol("pvc-single", "single", "detached", "faulted", "", 1, true, "",
			rep("pvc-single-r-1", "cp-3", "unknown", "2026-09-20T19:13:11Z", "")),
		vol("pvc-four", "four", "attached", "degraded", "cp-2", 4, false, "replica scheduling failed",
			rep("pvc-four-r-1", "cp-1", "running", "", "RW"), rep("pvc-four-r-2", "cp-2", "running", "", "RW"), rep("pvc-four-r-3", "cp-3", "unknown", "", "ERR"), rep("pvc-four-r-4", "", "stopped", "", "")),
		vol("pvc-huge", "huge", "detached", "faulted", "", 3, false, "precheck new replica failed: insufficient storage",
			rep("pvc-huge-r-1", "", "stopped", "", ""), rep("pvc-huge-r-2", "", "stopped", "", ""), rep("pvc-huge-r-3", "", "stopped", "", "")),
	}
	li.Volumes[0].LastDegraded = now.Add(-2 * time.Hour)
	li.Volumes[2].Workloads = []string{"single-old", "single-new"}
	shared := vol("pvc-shared", "shared", "attached", "healthy", "cp-1", 3, true, "", rep("pvc-shared-r-1", "cp-1", "running", "", "RW"), rep("pvc-shared-r-2", "cp-2", "running", "", "RW"), rep("pvc-shared-r-3", "cp-3", "running", "", "RW"))
	shared.AccessMode, shared.ShareState = "rwx", "error"
	li.Volumes = append(li.Volumes, shared)
	li.Volumes[4].Size = 3 << 40
	disk := func(path string, ready bool) k8s.LonghornDisk {
		d := k8s.LonghornDisk{Name: path, Path: path, AllowScheduling: true, Ready: ready, Schedulable: ready, Maximum: 200 << 30, Available: 180 << 30, Scheduled: 6 << 30, Replicas: 5}
		if !ready {
			d.ReadyMsg = "Disk bad-disk(" + path + ") on node cp-1 is not ready: no such file or directory"
		}
		return d
	}
	li.Nodes = []k8s.LonghornNode{
		{Name: "cp-1", AllowScheduling: true, Ready: true, Schedulable: true, InstanceManager: "running", Conditions: map[string]k8s.LonghornCond{"MountPropagation": {Status: true}}, Disks: []k8s.LonghornDisk{disk("/mnt/missing-disk", false), disk("/var/lib/longhorn/", true)}},
		{Name: "cp-2", AllowScheduling: true, Ready: true, Schedulable: true, InstanceManager: "running", Conditions: map[string]k8s.LonghornCond{"MountPropagation": {Status: true}, "NFSClientInstalled": {Status: false, Message: "NFS client is not found"}}, Disks: []k8s.LonghornDisk{disk("/var/lib/longhorn/", true)}},
		{Name: "cp-3", AllowScheduling: true, Ready: false, ReadyMsg: "Kubernetes node cp-3 not ready", Schedulable: true, InstanceManager: "error", Disks: []k8s.LonghornDisk{disk("/var/lib/longhorn/", true)}},
	}
	li.EngineImages = []k8s.LonghornEngineImage{{Name: "ei-1", Version: "v1.12.1", State: "deploying", RefCount: 30, NotOn: []string{"cp-3"}}}
	li.BackupTargets = []k8s.LonghornBackupTarget{{Name: "default"}}
	li.Backups = []k8s.LonghornBackup{
		{Name: "backup-3d2f", Volume: "pvc-four", Snapshot: "nightly--1", State: "Error", Created: now.Add(-5 * time.Minute), Error: "proxyServer=10.42.1.17:8501 destination=10.42.1.17:10092: failed to backup snapshot nightly--1 to backup-3d2f: rpc error: code = Internal desc = failed to create backup: rpc error: code = Unknown desc = failed to store updated lock: mkdir /var/lib/longhorn-backupstore-mounts/10_0_0_143/srv/longhorn-backup: file exists"},
		{Name: "backup-old", Volume: "pvc-four", State: "Error", Created: now.Add(-time.Hour), Error: "older failure"},
		{Name: "backup-ok", Volume: "pvc-web", State: "Completed", Created: now.Add(-time.Hour)},
	}
	li.RecurringJobs = []k8s.LonghornRecurringJob{{Name: "nightly", Task: "backup", Cron: "0 2 * * *", Retain: 7, Groups: []string{"default"}}}
	// web-data is one snapshot over its limit, four is close to it
	li.Volumes[0].Snapshots, li.Volumes[0].SnapshotMax = 6, 5
	li.Volumes[3].Snapshots, li.Volumes[3].SnapshotMax = 230, 250
	li.Orphans = []k8s.LonghornOrphan{{Name: "orphan-1", Type: "replica", Node: "cp-1"}}
	s.Longhorn = li
	return in
}

func TestLonghornFindings(t *testing.T) {
	in := longhornInput()
	f := Evaluate(in)
	want := []struct {
		sev    Severity
		area   string
		substr string
	}{
		// volumes
		{SevWarn, "storage", "Longhorn volume pvc-web degraded: 2/3 replicas healthy (failed: cp-3); cannot rebuild: precheck new replica failed: disks are unavailable (3 replicas requested, 2 schedulable nodes)"},
		{SevCrit, "storage", "Longhorn volume pvc-data-db-1 is attached on cp-3 which is down"},
		{SevCrit, "storage", "Longhorn volume pvc-single is FAULTED: every replica failed (0/1 replicas healthy (failed: cp-3)) used by single-old, single-new"},
		{SevWarn, "storage", "Longhorn volume pvc-four degraded: 2/4 replicas healthy (failed: cp-3, unscheduled)"},
		{SevWarn, "storage", "(4 replicas requested, 2 schedulable nodes)"},
		{SevCrit, "storage", "Longhorn volume pvc-huge cannot schedule its replicas: precheck new replica failed: insufficient storage - the 3.0TiB volume does not fit"},
		{SevCrit, "storage", "Longhorn RWX volume pvc-shared share manager is error"},
		{SevInfo, "storage", "1 Longhorn volumes have a single replica (no redundancy: lh-test/single)"},
		// nodes and disks
		{SevCrit, "storage", "Longhorn disk not ready: Disk bad-disk(/mnt/missing-disk) on node cp-1 is not ready"},
		{SevWarn, "storage", "Longhorn NFSClientInstalled condition failed: NFS client is not found"},
		// backup target, orphans, settings
		{SevInfo, "storage", "Longhorn has no backup target"},
		{SevWarn, "storage", "1 orphaned replica directories on the Longhorn disks (cp-1 x1)"},
		{SevWarn, "storage", "concurrent-replica-rebuild-per-node-limit is 0"},
		{SevInfo, "storage", "replica-soft-anti-affinity is on"},
		{SevInfo, "storage", "Longhorn upgrade-checker is on"},
		{SevInfo, "storage", "node-down-pod-deletion-policy is do-nothing"},
		// backups and snapshots
		{SevWarn, "storage", "Longhorn backup backup-3d2f of volume pvc-four failed (2 failed backups for this volume): failed to store updated lock: mkdir /var/lib/longhorn-backupstore-mounts/10_0_0_143/srv/longhorn-backup: file exists"},
		{SevWarn, "storage", "recurring backup job nightly (0 2 * * *) is scheduled but the backup target is not set"},
		{SevWarn, "storage", "Longhorn volume pvc-web has too many snapshots (6, max 5)"},
		{SevInfo, "storage", "Longhorn volume pvc-four is at 230 of 250 snapshots"},
		// VolumeAttachments (driver-independent)
		{SevCrit, "storage", "volume is still attached to cp-3 (NotReady) while lh-test/single-new (unscheduled) waits for it"},
		{SevWarn, "storage", "volume attached to cp-3 (NotReady) with lh-test/db-1 (Terminating) still bound there"},
		{SevInfo, "storage", "shared (RWX/ROX) volume still attached to cp-3 (NotReady)"},
		{SevWarn, "storage", "detach from cp-1 failing since 2m: rpc error: code = DeadlineExceeded"},
	}
	for _, w := range want {
		if findingWith(f, w.sev, w.area, w.substr) == nil {
			t.Errorf("missing %s/%s finding containing %q", w.sev, w.area, w.substr)
		}
	}
	// the huge volume is unschedulable, not "faulted"; cp-3's Longhorn node
	// is NotReady because the Kubernetes node is (no separate finding);
	// the engine image missing on the dead node is not reported either
	if n := 0; true {
		for _, x := range f {
			if strings.Contains(x.Message, "Longhorn backup backup-") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("failed backups reported %d times, want one per volume", n)
		}
	}
	for _, x := range f {
		for _, bad := range []string{"pvc-huge is FAULTED", "Longhorn node not ready although", "engine image ei-1", "default-replica-count is 3 but only"} {
			if strings.Contains(x.Message, bad) {
				t.Errorf("unexpected: %s", x.Message)
			}
		}
	}
	// object attribution: volumes go to their PVC, disks to node:path
	if x := findingWith(f, SevWarn, "storage", "pvc-web degraded"); x != nil && x.Object != "lh-test/web" {
		t.Errorf("volume finding object %q", x.Object)
	}
	if x := findingWith(f, SevCrit, "storage", "Longhorn disk not ready"); x != nil && x.Object != "cp-1:/mnt/missing-disk" {
		t.Errorf("disk finding object %q", x.Object)
	}
}

func TestLonghornNodeSide(t *testing.T) {
	in := longhornInput()
	// cp-3 as its own kubelet sees it: the two devices still attached, the
	// RWX export hung
	ni := &nodeinfo.Info{Node: "cp-3", Dist: "rke2", KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Settings: map[string]string{}, Hardening: map[string]string{},
		StaleMounts: []nodeinfo.StaleMount{
			{Mountpoint: "/var/lib/kubelet/plugins/kubernetes.io/csi/driver.longhorn.io/78dc/globalmount", Source: "10.43.224.112:/pvc-shared", FSType: "nfs4"},
			{Mountpoint: "/var/lib/kubelet/pods/0223/volumes/kubernetes.io~csi/pvc-shared/mount", Source: "10.43.224.112:/pvc-shared", FSType: "nfs4"},
		}}
	ni.Preflight = nodeinfo.Preflight{Probed: true, Units: map[string]nodeinfo.PFUnit{}, CSI: nodeinfo.CSIInfo{Drivers: []string{"driver.longhorn.io"}, ISCSID: true, MultipathBlacklist: -1,
		LonghornDevs:  []string{"pvc-data-db-1", "pvc-single", "pvc-gone"},
		ISCSISessions: []nodeinfo.ISCSISession{{Target: "iqn.2019-10.io.longhorn:pvc-data-db-1", State: "LOGGED_IN"}, {Target: "iqn.2019-10.io.longhorn:pvc-single", State: "LOGGED_IN"}}},
		SudoUser: "root", Today: 20000}
	in.Nodes["cp-3"] = ni
	// the cluster side moved on: db-1's volume is being attached elsewhere
	in.Snap.Longhorn.Volumes[1].State, in.Snap.Longhorn.Volumes[1].Node = "attaching", ""
	in.Snap.Services = []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Name: "pvc-shared"}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.224.112"}}}
	f := Evaluate(in)
	for _, w := range []struct {
		sev    Severity
		obj    string
		substr string
	}{
		{SevCrit, "lh-test/data-db-1", "node cp-3 still presents /dev/longhorn/pvc-data-db-1 (iSCSI session LOGGED_IN) while the cluster has the volume attaching"},
		{SevCrit, "lh-test/single", "node cp-3 still presents /dev/longhorn/pvc-single (iSCSI session LOGGED_IN) while the cluster has the volume detached"},
		{SevWarn, "cp-3", "/dev/longhorn/pvc-gone is still present on the node but the Longhorn volume no longer exists"},
		{SevCrit, "cp-3", "network mount 10.43.224.112:/pvc-shared (nfs4, 2 mountpoints under /var/lib/kubelet) is hung"},
	} {
		x := findingWith(f, w.sev, "storage", w.substr)
		if x == nil {
			t.Errorf("missing %s finding containing %q", w.sev, w.substr)
		} else if x.Object != w.obj {
			t.Errorf("finding %q attributed to %q, want %q", w.substr, x.Object, w.obj)
		} else if w.substr[:13] == "network mount" && !strings.Contains(x.Hint, "Longhorn RWX export") {
			t.Errorf("stale mount hint did not recognise the share-manager service: %q", x.Hint)
		}
	}
	n := 0
	for _, x := range f {
		if strings.Contains(x.Message, "is hung") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("hung mount reported %d times, want once per export", n)
	}
}

func TestTridentExtraFindings(t *testing.T) {
	in := cloudInput()
	s := in.Snap
	s.TridentBackends = append(s.TridentBackends, k8s.TridentBackend{BackendName: "nas-2", State: "online", Online: true, Driver: "ontap-nas", UserState: "suspended"})
	s.Trident = &k8s.TridentInfo{
		Orchestrator: &k8s.TridentOrchestrator{Name: "trident", Status: "Failed", Message: "Trident installation failed: image pull", Namespace: "trident"},
		BackendConfigs: []k8s.TridentBackendConfig{{Namespace: "trident", Name: "tbc-san", BackendName: "san-1", Driver: "ontap-san", Phase: "Failed", Message: "could not log in to SVM", Credentials: "svm-creds"}, {Namespace: "trident", Name: "tbc-nas", Phase: "Bound", LastOperation: "Failed", Message: "update rejected"},
			{Namespace: "trident", Name: "tbc-new", Driver: "ontap-nas", LastOperation: "Failed", Message: "Failed to create backend: problem initializing storage driver 'ontap-nas': error initializing ontap-nas driver: could not create Data ONTAP API client: error creating ONTAP API client: error reading SVM details: Post \"https://10.0.0.250/servlets/netapp.servlets.admin.XMLrequest_filer\": dial tcp 10.0.0.250:443: connect: no route to host"}},
		Nodes:        []k8s.TridentNode{{Name: "cp-1", Registered: true, PublicationState: "dirty", Services: []string{"NFS"}}, {Name: "cp-2", Registered: true, PublicationState: "clean", Services: []string{"NFS", "iSCSI"}}},
		Publications: []k8s.TridentPublication{{Volume: "pvc-a", Node: "cp-1", AccessMode: 1}, {Volume: "pvc-a", Node: "cp-2", AccessMode: 1}, {Volume: "pvc-b", Node: "cp-1", AccessMode: 5}, {Volume: "pvc-b", Node: "cp-2", AccessMode: 5}},
		// classes: gold selects the online NAS pool, san-gold the failed SAN backend, platinum nothing, ghost is unknown to Trident, old-tsc is only in Trident
		StorageClassesListed: true,
		StorageClasses:       []k8s.TridentStorageClass{{Name: "gold"}, {Name: "san-gold"}, {Name: "platinum"}, {Name: "old-tsc"}},
	}
	for i := range s.TridentBackends {
		b := &s.TridentBackends[i]
		b.Pools = []k8s.TridentPool{{Name: b.BackendName, Labels: map[string]string{"performance": "gold"}, Defaults: map[string]string{"snapshotPolicy": "none"}}}
	}
	scOf := func(name string, params map[string]string) storagev1.StorageClass {
		return storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: name}, Provisioner: "csi.trident.netapp.io", Parameters: params}
	}
	s.StorageClasses = append(s.StorageClasses,
		scOf("gold", map[string]string{"backendType": "ontap-nas", "selector": "performance=gold"}),
		scOf("san-gold", map[string]string{"backendType": "ontap-san"}),
		scOf("platinum", map[string]string{"selector": "performance=platinum"}),
		scOf("ghost", map[string]string{"backendType": "ontap-nas"}),
	)
	f := Evaluate(in)
	for _, w := range []struct {
		sev    Severity
		substr string
	}{
		{SevCrit, "Trident operator reports Failed: Trident installation failed: image pull"},
		{SevCrit, "TridentBackendConfig tbc-san (ontap-san) is Failed: could not log in to SVM"},
		{SevCrit, "TridentBackendConfig tbc-new (ontap-nas) creation failed: Failed to create backend: problem initializing storage driver 'ontap-nas': error initializ ... etapp.servlets.admin.XMLrequest_filer\": dial tcp 10.0.0.250:443: connect: no route to host"},
		{SevWarn, "Trident found no usable iSCSI on cp-1 (TridentNode hostInfo.services) while a SAN backend is configured"},
		{SevWarn, "TridentBackendConfig last update failed: update rejected"},
		{SevWarn, "no TridentNode registration for cp-3"},
		{SevWarn, "TridentNode publication state is dirty on cp-1"},
		{SevCrit, "Trident published the single-writer volume to cp-1 and cp-2 at the same time"},
		{SevInfo, "Trident backend nas-2 is suspended by the user"},
		{SevInfo, "Trident enableForceDetach is off"},
		{SevCrit, "every backend StorageClass san-gold can provision on is offline (san-1 failed)"},
		{SevCrit, "StorageClass platinum selects no Trident backend (backendType=any selector=performance=platinum)"},
		{SevCrit, "StorageClass ghost is not registered with Trident (no TridentStorageClass)"},
		{SevInfo, "Trident still holds StorageClass old-tsc which no longer exists in Kubernetes"},
	} {
		if findingWith(f, w.sev, "storage", w.substr) == nil {
			t.Errorf("missing %s finding containing %q", w.sev, w.substr)
		}
	}
	for _, x := range f {
		if strings.Contains(x.Message, "pvc-b") {
			t.Errorf("multi-writer volume reported as split brain: %s", x.Message)
		}
		if strings.Contains(x.Message, "StorageClass gold ") {
			t.Errorf("the healthy class must not be reported: %s", x.Message)
		}
	}
}

func TestFailedCreateProblem(t *testing.T) {
	in := longhornInput()
	s := in.Snap
	// PodSecurity rejected every pod of the DaemonSet: no pod carries the reason
	s.DaemonSets[0].Status.NumberReady = 0
	s.Events = []corev1.Event{{ObjectMeta: metav1.ObjectMeta{Namespace: "longhorn-system", Name: "lm.1"}, Type: corev1.EventTypeWarning, Reason: "FailedCreate",
		InvolvedObject: corev1.ObjectReference{Kind: "DaemonSet", Namespace: "longhorn-system", Name: "longhorn-manager"},
		Message:        `Error creating: pods "longhorn-manager-b7zv2" is forbidden: violates PodSecurity "restricted:latest": privileged (container "longhorn-manager" must not set securityContext.privileged=true)`}}
	f := Evaluate(in)
	x := findingWith(f, SevCrit, "storage", "Longhorn manager not healthy: 0/3 ready (FailedCreate: pods \"longhorn-manager-b7zv2\" is forbidden: violates PodSecurity")
	if x == nil {
		t.Error("FailedCreate reason not attached to the component")
	}
}

func TestLonghornJoiningReplica(t *testing.T) {
	in := longhornInput()
	li := in.Snap.Longhorn
	// data-db-0 style: a replacement replica is running but the engine has
	// not admitted it yet, so it is neither failed nor RW/WO
	v := &li.Volumes[1]
	v.State, v.Node, v.Robustness = "attached", "cp-1", "degraded"
	v.ReplicaList = []k8s.LonghornReplica{
		{Name: "r-1", Node: "cp-1", State: "running", Mode: "RW", Rebuild: -1},
		{Name: "r-2", Node: "cp-2", State: "running", Mode: "RW", Rebuild: -1},
		{Name: "r-3", Node: "cp-3", State: "running", Rebuild: -1},
	}
	v.ReplicaMode = map[string]string{"r-1": "RW", "r-2": "RW"}
	f := Evaluate(in)
	if findingWith(f, SevWarn, "storage", "Longhorn volume pvc-data-db-1 degraded: 2/3 replicas healthy, rebuilding on cp-3 (joining)") == nil {
		t.Error("joining replica not reported as rebuilding")
	}
	if lastCause("a: rpc error: code = Internal desc = b: rpc error: desc = the cause\nsecond line") != "the cause" || lastCause("plain") != "plain" {
		t.Error("lastCause")
	}
}

func TestCephFindings(t *testing.T) {
	in := baseInput()
	s := in.Snap
	s.CSIDrivers = []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "rbd.csi.ceph.com"}}, {ObjectMeta: metav1.ObjectMeta{Name: "cephfs.csi.ceph.com"}}}
	s.Ceph = &k8s.CephInfo{
		Clusters: []k8s.CephCluster{{Namespace: "rook-ceph", Name: "rook-ceph", Phase: "Ready", Health: "HEALTH_ERR", Capacity: k8s.CephCapacity{Total: 1000, Used: 960},
			Details: []k8s.CephCheck{{Name: "MON_DOWN", Severity: "HEALTH_ERR", Message: "1/3 mons down, quorum a,b"}, {Name: "OSD_DOWN", Severity: "HEALTH_WARN", Message: "1 osds down"}}}},
		Pools: []k8s.CephResource{{Kind: "CephBlockPool", Namespace: "rook-ceph", Name: "replicapool", Phase: "Ready"}, {Kind: "CephBlockPool", Namespace: "rook-ceph", Name: "broken", Phase: "Failure"}},
	}
	f := Evaluate(in)
	for _, w := range []struct {
		sev    Severity
		substr string
	}{
		{SevCrit, "Ceph reports HEALTH_ERR: MON_DOWN: 1/3 mons down, quorum a,b, OSD_DOWN: 1 osds down"},
		{SevCrit, "Ceph raw capacity 96% used"},
		{SevWarn, "Rook CephBlockPool broken is in phase Failure"},
	} {
		x := findingWith(f, w.sev, "storage", w.substr)
		if x == nil {
			t.Errorf("missing %s finding containing %q", w.sev, w.substr)
		} else if x.Object != "rook-ceph/rook-ceph" && x.Object != "rook-ceph/broken" {
			t.Errorf("finding %q attributed to %q", w.substr, x.Object)
		}
	}
	// one CephCluster shared by two drivers: reported once
	n := 0
	for _, x := range f {
		if strings.Contains(x.Message, "HEALTH_ERR") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("cluster health reported %d times, want 1", n)
	}
}
