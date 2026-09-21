package k8s

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCephInfo(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	const gv = "ceph.rook.io/v1"
	f.set("/apis/ceph.rook.io/v1/cephclusters", ulist(gv, "CephCluster",
		uobj("rook-ceph", "rook-ceph", map[string]any{"spec": map[string]any{"external": map[string]any{"enable": false}}, "status": map[string]any{
			"phase": "Ready", "state": "Created", "message": "Cluster created successfully",
			"version": map[string]any{"version": "19.2.1-0"},
			"ceph": map[string]any{"health": "HEALTH_WARN", "lastChecked": "2026-09-20T20:00:00Z",
				"capacity": map[string]any{"bytesTotal": int64(3000000000000), "bytesUsed": int64(2700000000000), "bytesAvailable": int64(300000000000)},
				"details": map[string]any{
					"OSD_DOWN":    map[string]any{"severity": "HEALTH_WARN", "message": "1 osds down"},
					"PG_DEGRADED": map[string]any{"severity": "HEALTH_WARN", "message": "Degraded data redundancy: 120/360 objects degraded (33.3%), 12 pgs degraded"},
					"MON_DOWN":    map[string]any{"severity": "HEALTH_ERR", "message": "1/3 mons down, quorum a,b"},
				}}}}),
	))
	f.set("/apis/ceph.rook.io/v1/cephblockpools", ulist(gv, "CephBlockPool",
		uobj("rook-ceph", "replicapool", map[string]any{"status": map[string]any{"phase": "Ready", "info": map[string]any{"failureDomain": "host"}}}),
		uobj("rook-ceph", "broken", map[string]any{"status": map[string]any{"phase": "Failure"}}),
	))
	f.set("/apis/ceph.rook.io/v1/cephfilesystems", ulist(gv, "CephFilesystem",
		uobj("rook-ceph", "myfs", map[string]any{"status": map[string]any{"phase": "Progressing"}}),
	))
	c := f.client(t, DefaultOptions())
	ci := c.cephInfo(context.Background())
	if ci == nil || len(ci.Clusters) != 1 || len(ci.Pools) != 2 || len(ci.Filesys) != 1 || len(ci.Stores) != 0 {
		t.Fatalf("ceph info: %+v", ci)
	}
	cc := ci.Clusters[0]
	if cc.Health != "HEALTH_WARN" || cc.Phase != "Ready" || cc.Version != "19.2.1-0" || cc.Capacity.Total != 3000000000000 || cc.Capacity.Used != 2700000000000 || cc.External {
		t.Errorf("cluster: %+v", cc)
	}
	// HEALTH_ERR checks first, then by name
	if len(cc.Details) != 3 || cc.Details[0].Name != "MON_DOWN" || cc.Details[1].Name != "OSD_DOWN" || cc.Details[2].Name != "PG_DEGRADED" {
		t.Errorf("details order: %+v", cc.Details)
	}
	if u := ci.Unhealthy(); len(u) != 2 || u[0].Name != "broken" || u[0].Kind != "CephBlockPool" || u[1].Name != "myfs" || u[1].Phase != "Progressing" {
		t.Errorf("unhealthy: %+v", u)
	}
	if ci.Pools[1].Info["failureDomain"] != "host" {
		t.Errorf("pool info: %+v", ci.Pools[1])
	}
	// attached to both Ceph CSI drivers by Fetch, including Rook's
	// namespace-prefixed names, and the ceph-csi-operator's pod names classify
	f.set("/apis/storage.k8s.io/v1/csidrivers", ulist("storage.k8s.io/v1", "CSIDriver", uobj("", "rbd.csi.ceph.com", map[string]any{}), uobj("", "rook-ceph.cephfs.csi.ceph.com", map[string]any{})))
	f.set("/apis/apps/v1/deployments", appsv1.DeploymentList{TypeMeta: metav1.TypeMeta{Kind: "DeploymentList", APIVersion: "apps/v1"}, Items: []appsv1.Deployment{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "rook-ceph", Name: "rook-ceph.rbd.csi.ceph.com-ctrlplugin"}, Status: appsv1.DeploymentStatus{Replicas: 2, ReadyReplicas: 2}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "rook-ceph", Name: "rook-ceph-operator"}, Status: appsv1.DeploymentStatus{Replicas: 1, ReadyReplicas: 1}},
	}})
	f.set("/apis/apps/v1/daemonsets", appsv1.DaemonSetList{TypeMeta: metav1.TypeMeta{Kind: "DaemonSetList", APIVersion: "apps/v1"}, Items: []appsv1.DaemonSet{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "rook-ceph", Name: "rook-ceph.cephfs.csi.ceph.com-nodeplugin"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 3}},
	}})
	s := c.Fetch(context.Background())
	cl := s.Cloud()
	if s.Ceph == nil || len(cl.CSI) != 2 || cl.CSI[0].Ceph == nil || cl.CSI[1].Ceph == nil || cl.CSI[1].Provider != "ceph" {
		t.Errorf("ceph not attached to the CSI drivers: %+v", cl.CSI)
	}
	if ctl := cl.Component("ceph", "csi-controller"); ctl == nil || ctl.Name != "rook-ceph.rbd.csi.ceph.com-ctrlplugin" || !ctl.OK() {
		t.Errorf("ceph-csi-operator controller not classified: %+v", ctl)
	}
	if np := cl.Component("ceph", "csi-node"); np == nil || np.Name != "rook-ceph.cephfs.csi.ceph.com-nodeplugin" {
		t.Errorf("ceph-csi-operator node plugin not classified: %+v", np)
	}
	// data-safety checks rank ahead of hygiene, and a warning that hides an
	// availability problem is critical
	ranked := CephCluster{Health: "HEALTH_WARN", Details: []CephCheck{{Name: "AUTH_INSECURE_KEYS_ALLOWED", Severity: "HEALTH_WARN"}, {Name: "PG_DEGRADED", Severity: "HEALTH_WARN"}, {Name: "OSD_DOWN", Severity: "HEALTH_WARN"}}}
	if cephCheckWeight("AUTH_INSECURE_KEYS_ALLOWED") <= cephCheckWeight("OSD_DOWN") || cephCheckWeight("PG_AVAILABILITY") != 0 {
		t.Error("check weights")
	}
	if crit, _ := ranked.Critical(); crit {
		t.Error("a down OSD with replicas left is a warning")
	}
	ranked.Details = append(ranked.Details, CephCheck{Name: "PG_AVAILABILITY", Severity: "HEALTH_WARN", Message: "Reduced data availability: 3 pgs inactive"})
	if crit, why := ranked.Critical(); !crit || why != "PG_AVAILABILITY: Reduced data availability: 3 pgs inactive" {
		t.Errorf("inactive PGs must be critical: %v %q", crit, why)
	}
	// absent CRD: remembered, the pool lists never tried
	f2 := newFakeAPI(t)
	rke2Cluster(f2)
	c2 := f2.client(t, DefaultOptions())
	if ci := c2.cephInfo(context.Background()); ci != nil {
		t.Errorf("no CRDs: %+v", ci)
	}
	if n := f2.hitCount("/apis/ceph.rook.io/v1/cephblockpools"); n != 0 {
		t.Errorf("pools listed %d times without the cluster CRD", n)
	}
}
