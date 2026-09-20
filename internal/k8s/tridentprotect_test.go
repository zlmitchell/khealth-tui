package k8s

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The lab state after a vault turned out unreachable: a failed snapshot
// with reclaimPolicy Delete stuck deleting (its archive cannot be removed)
// holds the application's snapshot lock, so every later run is Blocked.
func TestTridentProtectAndLocks(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	const gv = "protect.trident.netapp.io/v1"
	f.set("/apis/protect.trident.netapp.io/v1/appvaults", ulist(gv, "AppVault",
		uobj("trident-protect", "lab-minio", map[string]any{"spec": map[string]any{"providerType": "GenericS3", "providerConfig": map[string]any{"s3": map[string]any{"endpoint": "minio.minio.svc:9000", "bucketName": "trident-protect"}}}, "status": map[string]any{"state": "Available"}}),
		uobj("trident-protect", "lab-s3-unreachable", map[string]any{"spec": map[string]any{"providerType": "GenericS3", "providerConfig": map[string]any{"s3": map[string]any{"endpoint": "10.0.0.250:9000", "bucketName": "trident-protect"}}}, "status": map[string]any{"state": "Error", "error": `Get "http://10.0.0.250:9000/trident-protect/?location=": dial tcp 10.0.0.250:9000: connect: no route to host`}}),
	))
	app := uobj("lh-test", "lh-test-app", map[string]any{"spec": map[string]any{"includedNamespaces": []any{map[string]any{"namespace": "lh-test"}}},
		"status": map[string]any{"protectionState": "Partial", "protectionHealthState": "Unhealthy", "protectionStateDetails": []any{"Scheduled backup unavailable"}}})
	app["metadata"].(map[string]any)["uid"] = "f6838827-a7b0-4ff8-9338-198628836459"
	f.set("/apis/protect.trident.netapp.io/v1/applications", ulist(gv, "Application", app))
	deleting := uobj("lh-test", "lh-test-snap-1", map[string]any{"spec": map[string]any{"applicationRef": "lh-test-app", "appVaultRef": "lab-s3-unreachable"}, "status": map[string]any{"state": "Error", "error": "error checking if resource collection exists: dial tcp 10.0.0.250:9000: connect: no route to host"}})
	deleting["metadata"].(map[string]any)["deletionTimestamp"] = "2026-09-20T22:50:00Z"
	deleting["metadata"].(map[string]any)["creationTimestamp"] = "2026-09-20T22:40:00Z"
	blocked := func(name string) map[string]any {
		o := uobj("lh-test", name, map[string]any{"spec": map[string]any{"applicationRef": "lh-test-app", "appVaultRef": "lab-minio"}, "status": map[string]any{"state": "Blocked", "error": "waiting for lock application-f6838827-a7b0-4ff8-9338-198628836459-snapshot to be available"}})
		o["metadata"].(map[string]any)["creationTimestamp"] = "2026-09-20T23:00:00Z"
		return o
	}
	f.set("/apis/protect.trident.netapp.io/v1/snapshots", ulist(gv, "Snapshot", deleting, blocked("lh-test-snap-2"), blocked("backup-718ddd14")))
	done := uobj("lh-test", "lh-test-backup-3", map[string]any{"spec": map[string]any{"applicationRef": "lh-test-app", "appVaultRef": "lab-minio", "dataMover": "Kopia"}, "status": map[string]any{"state": "Completed", "completionTimestamp": "2026-09-20T23:30:00Z"}})
	done["metadata"].(map[string]any)["creationTimestamp"] = "2026-09-20T23:20:00Z"
	f.set("/apis/protect.trident.netapp.io/v1/backups", ulist(gv, "Backup", done,
		uobj("lh-test", "lh-test-backup-1", map[string]any{"spec": map[string]any{"applicationRef": "lh-test-app", "appVaultRef": "lab-s3-unreachable", "dataMover": "Kopia"}, "status": map[string]any{"state": "Error", "error": "no route to host"}}),
	))
	f.set("/apis/protect.trident.netapp.io/v1/schedules", ulist(gv, "Schedule",
		uobj("lh-test", "lh-test-nightly", map[string]any{"spec": map[string]any{"applicationRef": "lh-test-app", "appVaultRef": "lab-s3-unreachable", "granularity": "Daily", "enabled": true}, "status": map[string]any{"lastRecoveryPoints": map[string]any{"maxAge": int64(86700000000000)}}}),
	))
	// the lock Leases: one held by the stuck snapshot (uid-lh-test-snap-1 in
	// the fixture), one for another application whose holder is gone
	dur := int32(3900)
	acq := metav1.NewMicroTime(time.Now().Add(-30 * time.Minute))
	holder1, holder2 := "snapshot-uid-lh-test-snap-1", "snapshot-00000000-dead-beef-0000-000000000000"
	f.set("/apis/coordination.k8s.io/v1/leases", coordinationv1.LeaseList{TypeMeta: metav1.TypeMeta{Kind: "LeaseList", APIVersion: "coordination.k8s.io/v1"}, Items: []coordinationv1.Lease{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "lh-test", Name: "application-f6838827-a7b0-4ff8-9338-198628836459-snapshot"}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder1, LeaseDurationSeconds: &dur, AcquireTime: &acq, RenewTime: &acq}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "application-11111111-2222-3333-4444-555555555555-snapshot"}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder2, LeaseDurationSeconds: &dur, AcquireTime: &acq, RenewTime: &acq}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-node-lease", Name: "cp-1"}},
	}})
	c := f.client(t, DefaultOptions())
	tp := c.tridentProtect(context.Background())
	if tp == nil || len(tp.Vaults) != 2 || len(tp.Applications) != 1 || len(tp.Snapshots) != 3 || len(tp.Backups) != 2 || len(tp.Schedules) != 1 {
		t.Fatalf("protect: %+v", tp)
	}
	if v := tp.Vaults[1]; v.Name != "lab-s3-unreachable" || v.State != "Error" || v.Endpoint != "10.0.0.250:9000" || v.Bucket != "trident-protect" || v.Provider != "GenericS3" {
		t.Errorf("vault: %+v", v)
	}
	if a := tp.Applications[0]; a.UID != "f6838827-a7b0-4ff8-9338-198628836459" || a.ProtectionState != "Partial" || a.ProtectionHealth != "Unhealthy" || len(a.Details) != 1 || len(a.Namespaces) != 1 {
		t.Errorf("application: %+v", a)
	}
	var stuck *ProtectRun
	for i := range tp.Snapshots {
		if tp.Snapshots[i].Name == "lh-test-snap-1" {
			stuck = &tp.Snapshots[i]
		}
	}
	if stuck == nil || !stuck.Deleting || !stuck.Failed() || stuck.DeletedAt.IsZero() {
		t.Fatalf("stuck snapshot: %+v", stuck)
	}
	if lock, uid, kind := tp.Snapshots[0].BlockedOn(); tp.Snapshots[0].State != "Blocked" || lock != "application-f6838827-a7b0-4ff8-9338-198628836459-snapshot" || uid != "f6838827-a7b0-4ff8-9338-198628836459" || kind != "snapshot" {
		t.Errorf("blocked on: %q %q %q (%+v)", lock, uid, kind, tp.Snapshots[0])
	}
	if len(tp.Locks) != 2 || tp.Locks[0].Kind != "snapshot" || tp.Locks[0].HolderUID != "uid-lh-test-snap-1" || tp.Locks[0].Duration != 3900*time.Second || tp.Locks[0].Expires().Before(time.Now()) {
		t.Errorf("locks: %+v", tp.Locks)
	}
	locks := tp.BlockedLocks()
	if len(locks) != 1 || locks[0].App != "lh-test-app" || len(locks[0].Waiting) != 2 || locks[0].Holder == nil || locks[0].Holder.Name != "lh-test-snap-1" || locks[0].Lease == nil || locks[0].Stale {
		t.Fatalf("blocked locks: %+v", locks)
	}
	// the holder disappears (finalizer dropped): the lease is stale
	f.set("/apis/protect.trident.netapp.io/v1/snapshots", ulist(gv, "Snapshot", blocked("lh-test-snap-2"), blocked("backup-718ddd14")))
	tp2 := c.tridentProtect(context.Background())
	if l2 := tp2.BlockedLocks(); len(l2) != 1 || !l2[0].Stale || l2[0].Holder != nil || l2[0].Lease == nil || l2[0].Lease.Holder != holder1 {
		t.Errorf("stale lock: %+v", l2)
	}
	if h := tp.LockHolder("lh-test", "lh-test-app", "backup"); h != nil {
		t.Errorf("no backup is in flight, holder %+v", h)
	}
	if r := tp.LatestRun("Backup", "lh-test", "lh-test-app"); r == nil || r.Name != "lh-test-backup-3" || r.Completed.IsZero() || r.Failed() {
		t.Errorf("latest backup: %+v", r)
	}
	if s := tp.Schedules[0]; !s.Enabled || s.Granularity != "Daily" || s.MaxRecoveryAge != 86700*time.Second {
		t.Errorf("schedule: %+v", s)
	}
	// through Fetch
	s := c.Fetch(context.Background())
	if s.Protect == nil || len(s.Protect.Vaults) != 2 {
		t.Error("Fetch did not attach the Trident Protect picture")
	}
}

func TestSnapshotInfo(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	const gv = "snapshot.storage.k8s.io/v1"
	cls := uobj("", "longhorn-snap", map[string]any{"driver": "driver.longhorn.io", "deletionPolicy": "Delete", "parameters": map[string]any{"type": "snap"}})
	cls["metadata"].(map[string]any)["annotations"] = map[string]any{"snapshot.storage.kubernetes.io/is-default-class": "true"}
	f.set("/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses", ulist(gv, "VolumeSnapshotClass", cls,
		uobj("", "vsphere-snap", map[string]any{"driver": "csi.vsphere.vmware.com", "deletionPolicy": "Delete"})))
	f.set("/apis/snapshot.storage.k8s.io/v1/volumesnapshots", ulist(gv, "VolumeSnapshot",
		uobj("lh-test", "web-data-snap", map[string]any{"spec": map[string]any{"volumeSnapshotClassName": "longhorn-snap", "source": map[string]any{"persistentVolumeClaimName": "web-data"}}, "status": map[string]any{"readyToUse": true, "boundVolumeSnapshotContentName": "snapcontent-1", "creationTime": "2026-09-20T22:37:29Z", "restoreSize": "2Gi"}}),
		uobj("lh-test", "missing-source-snap", map[string]any{"spec": map[string]any{"volumeSnapshotClassName": "longhorn-snap", "source": map[string]any{"persistentVolumeClaimName": "does-not-exist"}}, "status": map[string]any{"readyToUse": false, "error": map[string]any{"message": "Failed to create snapshot content with error snapshot controller failed to update missing-source-snap on API server: cannot get claim from snapshot", "time": "2026-09-20T22:37:29Z"}}}),
		uobj("lh-test", "nfs-snap", map[string]any{"spec": map[string]any{"source": map[string]any{"persistentVolumeClaimName": "unraid-shared"}}, "status": map[string]any{"error": map[string]any{"message": "Failed to set default snapshot class with error cannot find default snapshot class"}}}),
	))
	content := uobj("", "snapcontent-1", map[string]any{"spec": map[string]any{"driver": "driver.longhorn.io", "volumeSnapshotClassName": "longhorn-snap", "deletionPolicy": "Delete", "volumeSnapshotRef": map[string]any{"namespace": "lh-test", "name": "web-data-snap"}}, "status": map[string]any{"readyToUse": true, "snapshotHandle": "snap://pvc-2baeca39/snap-1", "restoreSize": int64(2147483648)}})
	stuck := uobj("", "snapcontent-gone", map[string]any{"spec": map[string]any{"driver": "driver.longhorn.io", "deletionPolicy": "Delete", "volumeSnapshotRef": map[string]any{"namespace": "lh-test", "name": "old"}}, "status": map[string]any{"readyToUse": true}})
	stuck["metadata"].(map[string]any)["deletionTimestamp"] = "2026-09-20T20:00:00Z"
	f.set("/apis/snapshot.storage.k8s.io/v1/volumesnapshotcontents", ulist(gv, "VolumeSnapshotContent", content, stuck))
	c := f.client(t, DefaultOptions())
	si := c.snapshotInfo(context.Background())
	if si == nil || len(si.Classes) != 2 || len(si.Snapshots) != 3 || len(si.Contents) != 2 {
		t.Fatalf("snapshots: %+v", si)
	}
	if d := si.DefaultClass("driver.longhorn.io"); d == nil || d.Name != "longhorn-snap" || d.Parameters["type"] != "snap" || si.DefaultClass("nfs.csi.k8s.io") != nil {
		t.Errorf("default class: %+v", d)
	}
	byName := map[string]VolumeSnapshot{}
	for _, vs := range si.Snapshots {
		byName[vs.Name] = vs
	}
	if ok := byName["web-data-snap"]; !ok.Ready || ok.Content != "snapcontent-1" || ok.RestoreSize != "2Gi" || ok.SnapshotTime.IsZero() || ok.SourcePVC != "web-data" {
		t.Errorf("ready snapshot: %+v", ok)
	}
	if bad := byName["missing-source-snap"]; bad.Ready || bad.Error == "" || bad.ErrorAt.IsZero() {
		t.Errorf("failed snapshot: %+v", bad)
	}
	if nc := byName["nfs-snap"]; nc.Class != "" || nc.Error == "" {
		t.Errorf("classless snapshot: %+v", nc)
	}
	if got := si.ForPVC("lh-test", "web-data"); len(got) != 1 || got[0].Name != "web-data-snap" {
		t.Errorf("ForPVC: %+v", got)
	}
	if c := si.Contents[0]; c.Name != "snapcontent-1" || c.Snapshot != "lh-test/web-data-snap" || c.Handle != "snap://pvc-2baeca39/snap-1" || !c.Ready {
		t.Errorf("content: %+v", c)
	}
	if c := si.Contents[1]; !c.Deleting || c.DeletedAt.IsZero() {
		t.Errorf("deleting content: %+v", c)
	}
}
