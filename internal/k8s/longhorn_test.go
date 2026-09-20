package k8s

import (
	"context"
	"testing"
)

// longhornCluster serves the Longhorn CRs of a three-node cluster in the
// state observed on the redhat9-test cluster with one node partitioned:
// one healthy volume, one degraded with a replica that cannot be
// rescheduled, one faulted single-replica volume on the dead node, one
// RWX volume, an unschedulable 3 TiB volume, a bad disk, an orphan and no
// backup target.
func longhornCluster(f *fakeAPI) {
	const gv = "longhorn.io/v1beta2"
	cond := func(t, status, reason, msg string) map[string]any {
		return map[string]any{"type": t, "status": status, "reason": reason, "message": msg}
	}
	vol := func(name, pvc, state, rob, node string, replicas int, extra map[string]any) map[string]any {
		spec := map[string]any{"numberOfReplicas": int64(replicas), "size": "1073741824", "accessMode": "rwo", "frontend": "blockdev", "image": "longhornio/longhorn-engine:v1.12.1", "nodeID": node}
		status := map[string]any{"state": state, "robustness": rob, "currentNodeID": node, "currentImage": "longhornio/longhorn-engine:v1.12.1", "actualSize": int64(51011584),
			"kubernetesStatus": map[string]any{"namespace": "lh-test", "pvcName": pvc, "pvName": name, "workloadsStatus": []any{map[string]any{"podName": pvc + "-pod", "podStatus": "Running"}}},
			"conditions":       []any{cond("Scheduled", "True", "", ""), cond("TooManySnapshots", "False", "", "")}}
		for k, v := range extra {
			switch k {
			case "spec":
				for k2, v2 := range v.(map[string]any) {
					spec[k2] = v2
				}
			case "status":
				for k2, v2 := range v.(map[string]any) {
					status[k2] = v2
				}
			}
		}
		return uobj("longhorn-system", name, map[string]any{"spec": spec, "status": status})
	}
	replica := func(name, vol, node, state, failedAt string) map[string]any {
		return uobj("longhorn-system", name, map[string]any{"spec": map[string]any{"volumeName": vol, "nodeID": node, "diskPath": "/var/lib/longhorn/", "failedAt": failedAt, "active": true}, "status": map[string]any{"currentState": state}})
	}
	f.set("/apis/longhorn.io/v1beta2/volumes", ulist(gv, "Volume",
		vol("pvc-ok", "web", "attached", "healthy", "cp-1", 3, nil),
		vol("pvc-deg", "db", "attached", "degraded", "cp-1", 3, map[string]any{"status": map[string]any{"lastDegradedAt": "2026-09-20T19:13:00Z",
			"conditions": []any{cond("Scheduled", "False", "ReplicaSchedulingFailure", "precheck new replica failed: disks are unavailable"), cond("TooManySnapshots", "False", "", "")}}}),
		vol("pvc-single", "single", "detached", "faulted", "", 1, map[string]any{"status": map[string]any{"currentNodeID": ""}}),
		vol("pvc-rwx", "shared", "attached", "healthy", "w-1", 3, map[string]any{"spec": map[string]any{"accessMode": "rwx"}}),
		vol("pvc-huge", "huge", "detached", "faulted", "", 3, map[string]any{"spec": map[string]any{"size": "3298534883328"}, "status": map[string]any{"currentNodeID": "", "actualSize": int64(0),
			"conditions": []any{cond("Scheduled", "False", "ReplicaSchedulingFailure", "precheck new replica failed: insufficient storage")}}}),
	))
	f.set("/apis/longhorn.io/v1beta2/replicas", ulist(gv, "Replica",
		replica("pvc-ok-r-1", "pvc-ok", "cp-1", "running", ""), replica("pvc-ok-r-2", "pvc-ok", "w-1", "running", ""), replica("pvc-ok-r-3", "pvc-ok", "w-2", "running", ""),
		replica("pvc-deg-r-1", "pvc-deg", "cp-1", "running", ""), replica("pvc-deg-r-2", "pvc-deg", "w-1", "running", ""), replica("pvc-deg-r-3", "pvc-deg", "w-2", "stopped", "2026-09-20T19:13:11Z"),
		replica("pvc-single-r-1", "pvc-single", "w-2", "unknown", "2026-09-20T19:13:11Z"),
		replica("pvc-rwx-r-1", "pvc-rwx", "cp-1", "running", ""), replica("pvc-rwx-r-2", "pvc-rwx", "w-1", "running", ""), replica("pvc-rwx-r-3", "pvc-rwx", "w-2", "running", ""),
		replica("pvc-huge-r-1", "pvc-huge", "", "stopped", ""), replica("pvc-huge-r-2", "pvc-huge", "", "stopped", ""), replica("pvc-huge-r-3", "pvc-huge", "", "stopped", ""),
	))
	f.set("/apis/longhorn.io/v1beta2/engines", ulist(gv, "Engine",
		uobj("longhorn-system", "pvc-ok-e-0", map[string]any{"spec": map[string]any{"volumeName": "pvc-ok", "nodeID": "cp-1", "active": true, "replicaAddressMap": map[string]any{"pvc-ok-r-1": "10.42.0.7:10010", "pvc-ok-r-2": "10.42.1.8:10010", "pvc-ok-r-3": "10.42.2.8:10000"}},
			"status": map[string]any{"currentState": "running", "replicaModeMap": map[string]any{"pvc-ok-r-1": "RW", "pvc-ok-r-2": "RW", "pvc-ok-r-3": "RW"},
				"snapshots": map[string]any{"volume-head": map[string]any{}, "snap-1": map[string]any{}, "snap-2": map[string]any{}}}}),
		uobj("longhorn-system", "pvc-deg-e-0", map[string]any{"spec": map[string]any{"volumeName": "pvc-deg", "nodeID": "cp-1", "active": true, "replicaAddressMap": map[string]any{"pvc-deg-r-1": "10.42.0.7:10020", "pvc-deg-r-2": "10.42.1.8:10020"}},
			"status": map[string]any{"currentState": "running", "replicaModeMap": map[string]any{"pvc-deg-r-1": "RW", "pvc-deg-r-2": "WO"},
				"currentReplicaAddressMap": map[string]any{"pvc-deg-r-1": "10.42.0.7:10020", "pvc-deg-r-2": "10.42.1.8:10020"},
				"rebuildStatus":            map[string]any{"tcp://10.42.1.8:10020": map[string]any{"isRebuilding": true, "progress": int64(42), "state": "in_progress", "error": ""}}}}),
		uobj("longhorn-system", "pvc-rwx-e-0", map[string]any{"spec": map[string]any{"volumeName": "pvc-rwx", "nodeID": "w-1", "active": true}, "status": map[string]any{"currentState": "running", "replicaModeMap": map[string]any{"pvc-rwx-r-1": "RW", "pvc-rwx-r-2": "RW", "pvc-rwx-r-3": "RW"}}}),
	))
	f.set("/apis/longhorn.io/v1beta2/sharemanagers", ulist(gv, "ShareManager",
		uobj("longhorn-system", "pvc-rwx", map[string]any{"spec": map[string]any{"image": "longhornio/longhorn-share-manager:v1.12.1"}, "status": map[string]any{"state": "error", "endpoint": "nfs://10.43.224.112/pvc-rwx"}}),
	))
	f.set("/apis/longhorn.io/v1beta2/instancemanagers", ulist(gv, "InstanceManager",
		uobj("longhorn-system", "instance-manager-a", map[string]any{"spec": map[string]any{"nodeID": "cp-1", "type": "aio", "image": "im:v1.12.1"}, "status": map[string]any{"currentState": "running", "instanceEngines": map[string]any{"e1": map[string]any{}}, "instanceReplicas": map[string]any{"r1": map[string]any{}, "r2": map[string]any{}}}}),
		uobj("longhorn-system", "instance-manager-b", map[string]any{"spec": map[string]any{"nodeID": "w-1", "type": "aio"}, "status": map[string]any{"currentState": "running"}}),
		uobj("longhorn-system", "instance-manager-c", map[string]any{"spec": map[string]any{"nodeID": "w-2", "type": "aio"}, "status": map[string]any{"currentState": "error"}}),
	))
	node := func(name string, ready bool, disks map[string]any, diskStatus map[string]any) map[string]any {
		rs := "True"
		if !ready {
			rs = "False"
		}
		return uobj("longhorn-system", name, map[string]any{"spec": map[string]any{"allowScheduling": true, "disks": disks},
			"status": map[string]any{"conditions": []any{cond("Ready", rs, "", "Node "+name+" is ready"), cond("Schedulable", "True", "", ""), cond("MountPropagation", "True", "", ""), cond("RequiredPackages", "True", "", "")}, "diskStatus": diskStatus}})
	}
	goodDisk := func() (map[string]any, map[string]any) {
		return map[string]any{"path": "/var/lib/longhorn/", "diskType": "filesystem", "allowScheduling": true, "storageReserved": int64(63072468172)},
			map[string]any{"diskPath": "/var/lib/longhorn/", "storageMaximum": int64(210241560576), "storageAvailable": int64(199963443200), "storageScheduled": int64(6442450944),
				"scheduledReplica": map[string]any{"pvc-ok-r-1": int64(1073741824), "pvc-deg-r-1": int64(1073741824)},
				"conditions":       []any{cond("Ready", "True", "", ""), cond("Schedulable", "True", "", "")}}
	}
	d1, s1 := goodDisk()
	d2, s2 := goodDisk()
	d3, s3 := goodDisk()
	f.set("/apis/longhorn.io/v1beta2/nodes", ulist(gv, "Node",
		node("cp-1", true, map[string]any{"default-disk": d1, "bad-disk": map[string]any{"path": "/mnt/missing-disk", "diskType": "filesystem", "allowScheduling": true}},
			map[string]any{"default-disk": s1, "bad-disk": map[string]any{"diskPath": "/mnt/missing-disk", "conditions": []any{cond("Ready", "False", "DiskNotReady", "Disk bad-disk(/mnt/missing-disk) on node cp-1 is not ready: errors: failed to generate disk config"), cond("Schedulable", "False", "DiskNotReady", "Disk bad-disk (/mnt/missing-disk) on the node cp-1 is not ready")}}}),
		node("w-1", true, map[string]any{"default-disk": d2}, map[string]any{"default-disk": s2}),
		node("w-2", false, map[string]any{"default-disk": d3}, map[string]any{"default-disk": s3}),
	))
	f.set("/apis/longhorn.io/v1beta2/engineimages", ulist(gv, "EngineImage",
		uobj("longhorn-system", "ei-493e04e7", map[string]any{"spec": map[string]any{"image": "longhornio/longhorn-engine:v1.12.1"}, "status": map[string]any{"state": "deploying", "version": "v1.12.1", "refCount": int64(31), "nodeDeploymentMap": map[string]any{"cp-1": true, "w-1": true, "w-2": false}}}),
	))
	f.set("/apis/longhorn.io/v1beta2/backuptargets", ulist(gv, "BackupTarget",
		uobj("longhorn-system", "default", map[string]any{"spec": map[string]any{"backupTargetURL": "", "credentialSecret": ""}, "status": map[string]any{"available": false, "conditions": []any{cond("Unavailable", "True", "Unavailable", "backup target URL is empty")}}}),
	))
	f.set("/apis/longhorn.io/v1beta2/orphans", ulist(gv, "Orphan",
		uobj("longhorn-system", "orphan-1a86", map[string]any{"spec": map[string]any{"orphanType": "replica", "nodeID": "cp-1", "parameters": map[string]any{"DataName": "pvc-00000000-dead-beef-0000-000000000000-abcdef12", "DiskPath": "/var/lib/longhorn/"}}}),
	))
	f.set("/apis/longhorn.io/v1beta2/backups", ulist(gv, "Backup",
		uobj("longhorn-system", "backup-ok", map[string]any{"spec": map[string]any{"snapshotName": "snap-1"}, "status": map[string]any{"volumeName": "pvc-ok", "state": "Completed", "backupCreatedAt": "2026-09-20T20:17:47Z", "size": "117440512"}}),
		uobj("longhorn-system", "backup-bad", map[string]any{"spec": map[string]any{"snapshotName": "nightly--1"}, "status": map[string]any{"volumeName": "pvc-deg", "state": "Error", "error": "proxyServer=10.42.1.17:8501 destination=10.42.1.17:10092: failed to backup snapshot: rpc error: code = Internal desc = failed to create backup: rpc error: code = Unknown desc = mkdir /var/lib/longhorn-backupstore-mounts/x: file exists", "backupCreatedAt": "2026-09-20T20:20:00Z"}}),
	))
	f.set("/apis/longhorn.io/v1beta2/recurringjobs", ulist(gv, "RecurringJob",
		uobj("longhorn-system", "nightly", map[string]any{"spec": map[string]any{"task": "backup", "cron": "0 2 * * *", "retain": int64(7), "groups": []any{"default"}}}),
	))
	set := func(name, value string) map[string]any {
		return uobj("longhorn-system", name, map[string]any{"value": value, "status": map[string]any{"applied": true}})
	}
	f.set("/apis/longhorn.io/v1beta2/settings", ulist(gv, "Setting",
		set("default-replica-count", `{"v1":"3","v2":"3"}`), set("replica-soft-anti-affinity", "false"), set("node-down-pod-deletion-policy", "do-nothing"),
		set("upgrade-checker", "true"), set("concurrent-replica-rebuild-per-node-limit", "5"), set("auto-salvage", "true"), set("storage-minimal-available-percentage", "25"),
		set("not-kept", "x"),
	))
}

func TestLonghornInfo(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	longhornCluster(f)
	c := f.client(t, DefaultOptions())
	li := c.longhornInfo(context.Background())
	if li == nil {
		t.Fatal("no Longhorn info")
	}
	if len(li.Volumes) != 5 || len(li.Nodes) != 3 || len(li.InstanceManagers) != 3 || len(li.EngineImages) != 1 || len(li.BackupTargets) != 1 || len(li.Orphans) != 1 {
		t.Fatalf("counts: volumes=%d nodes=%d im=%d ei=%d bt=%d orphans=%d", len(li.Volumes), len(li.Nodes), len(li.InstanceManagers), len(li.EngineImages), len(li.BackupTargets), len(li.Orphans))
	}
	byName := map[string]LonghornVolume{}
	for _, v := range li.Volumes {
		byName[v.Name] = v
	}
	ok := byName["pvc-ok"]
	if ok.PVC != "lh-test/web" || ok.State != "attached" || ok.Robustness != "healthy" || ok.Node != "cp-1" || ok.Replicas != 3 || ok.Healthy() != 3 || len(ok.ReplicaList) != 3 || ok.Snapshots != 2 || !ok.Scheduled || ok.Size != 1073741824 || len(ok.Workloads) != 1 {
		t.Errorf("healthy volume: %+v", ok)
	}
	deg := byName["pvc-deg"]
	if deg.Robustness != "degraded" || deg.Healthy() != 1 || deg.Scheduled || deg.SchedMessage != "precheck new replica failed: disks are unavailable" || deg.LastDegraded.IsZero() {
		t.Errorf("degraded volume: %+v", deg)
	}
	var rebuilding, failed *LonghornReplica
	for i := range deg.ReplicaList {
		r := &deg.ReplicaList[i]
		if r.Name == "pvc-deg-r-2" {
			rebuilding = r
		}
		if r.Name == "pvc-deg-r-3" {
			failed = r
		}
	}
	if rebuilding == nil || rebuilding.Mode != "WO" || rebuilding.Rebuild != 42 || failed == nil || failed.FailedAt == "" || failed.State != "stopped" || failed.Rebuild != -1 {
		t.Errorf("replicas: rebuilding=%+v failed=%+v", rebuilding, failed)
	}
	single := byName["pvc-single"]
	if single.Robustness != "faulted" || single.State != "detached" || single.Node != "" || single.Healthy() != 0 || len(single.ReplicaList) != 1 || single.ReplicaList[0].Node != "w-2" {
		t.Errorf("faulted volume: %+v", single)
	}
	rwx := byName["pvc-rwx"]
	if rwx.AccessMode != "rwx" || rwx.ShareState != "error" || rwx.ShareEndpoint != "nfs://10.43.224.112/pvc-rwx" {
		t.Errorf("rwx volume: %+v", rwx)
	}
	huge := byName["pvc-huge"]
	if huge.Size != 3298534883328 || huge.Scheduled || huge.SchedMessage != "precheck new replica failed: insufficient storage" {
		t.Errorf("huge volume: %+v", huge)
	}
	h, d, fa, u := li.Counts()
	if h != 2 || d != 1 || fa != 2 || u != 0 {
		t.Errorf("counts: healthy=%d degraded=%d faulted=%d unknown=%d", h, d, fa, u)
	}
	if v := li.VolumeForPVC("lh-test", "db"); v == nil || v.Name != "pvc-deg" {
		t.Errorf("VolumeForPVC: %+v", v)
	}

	cp := li.Node("cp-1")
	if cp == nil || !cp.Ready || !cp.Schedulable || cp.InstanceManager != "running" || len(cp.Disks) != 2 || !cp.Conditions["MountPropagation"].Status {
		t.Fatalf("cp-1: %+v", cp)
	}
	// disks sorted by path: /mnt/missing-disk before /var/lib/longhorn/
	if bad := cp.Disks[0]; bad.Path != "/mnt/missing-disk" || bad.Ready || bad.Schedulable || !bad.AllowScheduling || bad.ReadyMsg == "" {
		t.Errorf("bad disk: %+v", bad)
	}
	if good := cp.Disks[1]; good.Path != "/var/lib/longhorn/" || !good.Ready || good.Maximum != 210241560576 || good.Available != 199963443200 || good.Scheduled != 6442450944 || good.Reserved != 63072468172 || good.Replicas != 2 {
		t.Errorf("good disk: %+v", good)
	}
	if w2 := li.Node("w-2"); w2 == nil || w2.Ready || w2.InstanceManager != "error" {
		t.Errorf("w-2: %+v", w2)
	}
	if im := li.InstanceManagers[0]; im.Node != "cp-1" || im.Engines != 1 || im.Replicas != 2 || im.State != "running" {
		t.Errorf("instance manager: %+v", im)
	}
	if ei := li.EngineImages[0]; ei.State != "deploying" || ei.RefCount != 31 || len(ei.NotOn) != 1 || ei.NotOn[0] != "w-2" || ei.Version != "v1.12.1" {
		t.Errorf("engine image: %+v", ei)
	}
	if bt := li.BackupTargets[0]; bt.URL != "" || bt.Available || bt.Message != "backup target URL is empty" {
		t.Errorf("backup target: %+v", bt)
	}
	if o := li.Orphans[0]; o.Type != "replica" || o.Node != "cp-1" || o.DataName != "pvc-00000000-dead-beef-0000-000000000000-abcdef12" {
		t.Errorf("orphan: %+v", o)
	}
	// backups newest first, the failed one found
	if len(li.Backups) != 2 || li.Backups[0].Name != "backup-bad" || li.Backups[1].Size != 117440512 || li.Backups[1].State != "Completed" || li.Backups[1].Volume != "pvc-ok" {
		t.Errorf("backups: %+v", li.Backups)
	}
	if fb := li.FailedBackups(); len(fb) != 1 || fb[0].Volume != "pvc-deg" || fb[0].Error == "" {
		t.Errorf("failed backups: %+v", fb)
	}
	if len(li.RecurringJobs) != 1 || li.RecurringJobs[0].Task != "backup" || li.RecurringJobs[0].Retain != 7 || li.RecurringJobs[0].Cron != "0 2 * * *" || len(li.RecurringJobs[0].Groups) != 1 {
		t.Errorf("recurring jobs: %+v", li.RecurringJobs)
	}
	if li.Setting("default-replica-count") != "3" || li.SettingInt("default-replica-count", 0) != 3 || li.Setting("upgrade-checker") != "true" || li.Setting("not-kept") != "" || li.SettingInt("missing", 7) != 7 {
		t.Errorf("settings: %v", li.Settings)
	}

	// Fetch attaches it to the driver.longhorn.io CSIStatus and lists the VolumeAttachments
	f.set("/apis/storage.k8s.io/v1/csidrivers", ulist("storage.k8s.io/v1", "CSIDriver", uobj("", "driver.longhorn.io", map[string]any{"spec": map[string]any{"attachRequired": true}})))
	f.set("/apis/storage.k8s.io/v1/volumeattachments", ulist("storage.k8s.io/v1", "VolumeAttachment",
		uobj("", "csi-1", map[string]any{"spec": map[string]any{"attacher": "driver.longhorn.io", "nodeName": "w-2", "source": map[string]any{"persistentVolumeName": "pvc-single"}}, "status": map[string]any{"attached": true}}),
	))
	s := c.Fetch(context.Background())
	if s.Longhorn == nil || len(s.Longhorn.Volumes) != 5 || len(s.VolumeAttachments) != 1 || s.VolumeAttachments[0].Spec.NodeName != "w-2" {
		t.Fatalf("fetch: longhorn=%v attachments=%d", s.Longhorn != nil, len(s.VolumeAttachments))
	}
	ci := s.Cloud()
	if len(ci.CSI) != 1 || ci.CSI[0].Provider != "longhorn" || ci.CSI[0].Longhorn == nil || ci.CSI[0].TridentX != nil {
		t.Errorf("csi status: %+v", ci.CSI)
	}
}

func TestLonghornInfoAbsent(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	c := f.client(t, DefaultOptions())
	if li := c.longhornInfo(context.Background()); li != nil {
		t.Errorf("no CRDs: %+v", li)
	}
	if _, ok := c.Denied("volumes.longhorn.io"); !ok {
		t.Error("absent volumes CRD not remembered")
	}
	// only the volumes list was tried: the other nine are skipped when it fails
	if n := f.hitCount("/apis/longhorn.io/v1beta2/replicas"); n != 0 {
		t.Errorf("replicas listed %d times without the volumes CRD", n)
	}
}

func TestTridentInfo(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	const gv = "trident.netapp.io/v1"
	f.mu.Lock()
	delete(f.deny, "/apis/trident.netapp.io/v1/tridentbackends") // rke2Cluster denies it
	f.mu.Unlock()
	f.set("/apis/trident.netapp.io/v1/tridentbackends", ulist(gv, "TridentBackend",
		uobj("trident", "tbe-1", map[string]any{"backendName": "ontap-san-1", "state": "offline", "online": false, "userState": "suspended", "stateReason": "SVM unreachable", "configRef": "uid-1", "config": map[string]any{"storageDriverName": "ontap-san"}}),
	))
	f.set("/apis/trident.netapp.io/v1/tridentorchestrators", ulist(gv, "TridentOrchestrator",
		uobj("", "trident", map[string]any{"spec": map[string]any{"silenceAutosupport": true, "enableForceDetach": false}, "status": map[string]any{"status": "Failed", "message": "Trident installation failed: image pull", "version": "25.06.0", "namespace": "trident"}}),
	))
	f.set("/apis/trident.netapp.io/v1/tridentbackendconfigs", ulist(gv, "TridentBackendConfig",
		uobj("trident", "tbc-san", map[string]any{"spec": map[string]any{"storageDriverName": "ontap-san", "backendName": "ontap-san-1", "credentials": map[string]any{"name": "svm-creds"}}, "status": map[string]any{"phase": "Failed", "lastOperationStatus": "Failed", "message": "could not log in to SVM", "backendInfo": map[string]any{"backendName": "ontap-san-1"}}}),
	))
	f.set("/apis/trident.netapp.io/v1/tridentnodes", ulist(gv, "TridentNode",
		uobj("trident", "cp-1", map[string]any{"spec": map[string]any{"nodeName": "cp-1", "iqn": "iqn.1994-05.com.redhat:cp1"}, "status": map[string]any{"registered": true, "publicationState": "dirty"}}),
		uobj("trident", "w-1", map[string]any{"name": "w-1", "iqn": "iqn.1994-05.com.redhat:w1", "publicationState": "clean", "deleted": false}), // pre-25.x layout
	))
	f.set("/apis/trident.netapp.io/v1/tridentvolumepublications", ulist(gv, "TridentVolumePublication",
		uobj("trident", "pvc-a.cp-1", map[string]any{"volumeID": "pvc-a", "nodeID": "cp-1", "readOnly": false, "accessMode": int64(1)}),
		uobj("trident", "pvc-a.w-1", map[string]any{"volumeID": "pvc-a", "nodeID": "w-1", "readOnly": false, "accessMode": int64(1)}),
		uobj("trident", "pvc-b.cp-1", map[string]any{"volumeID": "pvc-b", "nodeID": "cp-1", "readOnly": false, "accessMode": int64(5)}),
		uobj("trident", "pvc-b.w-1", map[string]any{"volumeID": "pvc-b", "nodeID": "w-1", "readOnly": false, "accessMode": int64(5)}),
	))
	c := f.client(t, DefaultOptions())
	s := c.Fetch(context.Background())
	if len(s.TridentBackends) != 1 || s.TridentBackends[0].UserState != "suspended" || s.TridentBackends[0].StateReason != "SVM unreachable" || s.TridentBackends[0].ConfigRef != "uid-1" {
		t.Errorf("backends: %+v", s.TridentBackends)
	}
	ti := s.Trident
	if ti == nil || ti.Orchestrator == nil || ti.Orchestrator.Status != "Failed" || ti.Orchestrator.Version != "25.06.0" || !ti.Orchestrator.SilenceAutosupport || ti.Orchestrator.ForceDetach {
		t.Fatalf("orchestrator: %+v", ti)
	}
	if len(ti.BackendConfigs) != 1 || ti.BackendConfigs[0].Phase != "Failed" || ti.BackendConfigs[0].Credentials != "svm-creds" || ti.BackendConfigs[0].BackendName != "ontap-san-1" || ti.BackendConfigs[0].Driver != "ontap-san" {
		t.Errorf("backend configs: %+v", ti.BackendConfigs)
	}
	if len(ti.Nodes) != 2 || ti.TridentNode("cp-1") == nil || ti.TridentNode("cp-1").PublicationState != "dirty" || !ti.TridentNode("cp-1").Registered || ti.TridentNode("w-1") == nil || ti.TridentNode("w-1").IQN != "iqn.1994-05.com.redhat:w1" || ti.TridentNode("w-1").PublicationState != "clean" || ti.TridentNode("nope") != nil {
		t.Errorf("nodes: %+v", ti.Nodes)
	}
	mp := ti.MultiPublished()
	if len(mp) != 1 || len(mp["pvc-a"]) != 2 {
		t.Errorf("multi-published: %v", mp)
	}
	if ci := s.Cloud(); len(ci.CSI) == 0 {
		// no CSIDriver object in the fixture: fine, TridentX is attached only through a CSIStatus
	} else if ci.CSI[0].TridentX == nil {
		t.Error("TridentX not attached")
	}

	// no Trident at all: the extra lists are never tried
	f2 := newFakeAPI(t)
	rke2Cluster(f2)
	c2 := f2.client(t, DefaultOptions())
	if s2 := c2.Fetch(context.Background()); s2.Trident != nil {
		t.Errorf("trident info without the CRDs: %+v", s2.Trident)
	}
	if n := f2.hitCount("/apis/trident.netapp.io/v1/tridentnodes"); n != 0 {
		t.Errorf("tridentnodes listed %d times without the backend CRD", n)
	}
}

// The settings list is cached for DiscoveryTTL and the engines list is only
// re-listed while a volume is unhealthy (or after the TTL); R clears both.
func TestLonghornCaches(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	longhornCluster(f)
	// every volume healthy: engines are needed once, then carried forward
	const gv = "longhorn.io/v1beta2"
	f.set("/apis/longhorn.io/v1beta2/volumes", ulist(gv, "Volume",
		uobj("longhorn-system", "pvc-ok", map[string]any{"spec": map[string]any{"numberOfReplicas": int64(3)}, "status": map[string]any{"state": "attached", "robustness": "healthy", "currentNodeID": "cp-1"}}),
	))
	c := f.client(t, DefaultOptions())
	ctx := context.Background()
	li := c.longhornInfo(ctx)
	li2 := c.longhornInfo(ctx)
	if li == nil || li2 == nil || li.Volumes[0].Snapshots != 2 || li2.Volumes[0].Snapshots != 2 || li2.EnginesFrom.IsZero() || li2.Setting("default-replica-count") != "3" {
		t.Fatalf("carried-forward facts missing: %+v %+v", li, li2)
	}
	if n := f.hitCount("/apis/longhorn.io/v1beta2/engines"); n != 1 {
		t.Errorf("engines listed %d times for healthy volumes, want 1", n)
	}
	if n := f.hitCount("/apis/longhorn.io/v1beta2/settings"); n != 1 {
		t.Errorf("settings listed %d times, want 1", n)
	}
	if n := f.hitCount("/apis/longhorn.io/v1beta2/replicas"); n != 2 {
		t.Errorf("replicas listed %d times, want every call", n)
	}
	// a degraded volume re-lists the engines
	f.set("/apis/longhorn.io/v1beta2/volumes", ulist(gv, "Volume",
		uobj("longhorn-system", "pvc-ok", map[string]any{"spec": map[string]any{"numberOfReplicas": int64(3)}, "status": map[string]any{"state": "attached", "robustness": "degraded", "currentNodeID": "cp-1"}}),
	))
	c.longhornInfo(ctx)
	if n := f.hitCount("/apis/longhorn.io/v1beta2/engines"); n != 2 {
		t.Errorf("engines listed %d times after a volume degraded, want 2", n)
	}
	// R forgets both caches
	c.ResetDenied()
	c.longhornInfo(ctx)
	if n := f.hitCount("/apis/longhorn.io/v1beta2/settings"); n != 2 {
		t.Errorf("settings listed %d times after R, want 2", n)
	}
	// TTL 0: every call lists everything
	c2 := f.client(t, Options{})
	c2.longhornInfo(ctx)
	c2.longhornInfo(ctx)
	if n := f.hitCount("/apis/longhorn.io/v1beta2/settings"); n != 4 {
		t.Errorf("settings listed %d times with TTL 0, want 4", n)
	}
}
