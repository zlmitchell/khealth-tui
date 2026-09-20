package k8s

import (
	"context"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Rook-Ceph backend state from its CRs (ceph.rook.io/v1): the cluster's
// own health (HEALTH_OK / WARN / ERR with the check details Ceph reports),
// the operator's reconcile phase, and the phase of every pool, filesystem
// and object store the CSI drivers provision from. Fetched only when the
// cephclusters CRD exists.

// CephInfo is the Rook-Ceph picture.
type CephInfo struct {
	Clusters []CephCluster
	Pools    []CephResource // CephBlockPool
	Filesys  []CephResource // CephFilesystem
	Stores   []CephResource // CephObjectStore
}

// CephCluster is a cephclusters.ceph.rook.io object.
type CephCluster struct {
	Namespace, Name string
	Phase           string // Progressing, Ready, Failure, Updating, Connecting, ...
	State           string // Creating, Created, Updating, Error
	Message         string
	Health          string // HEALTH_OK, HEALTH_WARN, HEALTH_ERR
	Details         []CephCheck
	Version         string
	LastChecked     string
	Capacity        CephCapacity
	External        bool
}

// CephCheck is one entry of status.ceph.details (MON_DOWN, OSD_DOWN,
// PG_DEGRADED, ...).
type CephCheck struct {
	Name, Severity, Message string
}

// CephCapacity is status.ceph.capacity in bytes.
type CephCapacity struct {
	Total, Used, Available int64
}

// CephResource is a pool / filesystem / object store with its phase.
type CephResource struct {
	Kind, Namespace, Name string
	Phase                 string // Progressing, Ready, Failure, ...
	Info                  map[string]string
}

var (
	cephClusterGVR     = schema.GroupVersionResource{Group: "ceph.rook.io", Version: "v1", Resource: "cephclusters"}
	cephBlockPoolGVR   = schema.GroupVersionResource{Group: "ceph.rook.io", Version: "v1", Resource: "cephblockpools"}
	cephFilesystemGVR  = schema.GroupVersionResource{Group: "ceph.rook.io", Version: "v1", Resource: "cephfilesystems"}
	cephObjectStoreGVR = schema.GroupVersionResource{Group: "ceph.rook.io", Version: "v1", Resource: "cephobjectstores"}
)

// cephInfo lists the Rook-Ceph CRs; nil when the cephclusters CRD is
// absent or cannot be listed.
func (c *Client) cephInfo(ctx context.Context) *CephInfo {
	l, err := c.dynList(ctx, "cephclusters.ceph.rook.io", cephClusterGVR)
	if err != nil {
		return nil
	}
	ci := &CephInfo{}
	for _, it := range l.Items {
		o := it.Object
		cc := CephCluster{Namespace: it.GetNamespace(), Name: it.GetName()}
		cc.Phase, _, _ = unstructured.NestedString(o, "status", "phase")
		cc.State, _, _ = unstructured.NestedString(o, "status", "state")
		cc.Message, _, _ = unstructured.NestedString(o, "status", "message")
		cc.Health, _, _ = unstructured.NestedString(o, "status", "ceph", "health")
		cc.LastChecked, _, _ = unstructured.NestedString(o, "status", "ceph", "lastChecked")
		cc.Version, _, _ = unstructured.NestedString(o, "status", "version", "version")
		cc.External, _, _ = unstructured.NestedBool(o, "spec", "external", "enable")
		if capa, _, _ := unstructured.NestedMap(o, "status", "ceph", "capacity"); capa != nil {
			cc.Capacity = CephCapacity{Total: toInt64(capa["bytesTotal"]), Used: toInt64(capa["bytesUsed"]), Available: toInt64(capa["bytesAvailable"])}
		}
		if det, _, _ := unstructured.NestedMap(o, "status", "ceph", "details"); det != nil {
			for name, v := range det {
				m, _ := v.(map[string]any)
				if m == nil {
					continue
				}
				sev, _ := m["severity"].(string)
				msg, _ := m["message"].(string)
				cc.Details = append(cc.Details, CephCheck{Name: name, Severity: sev, Message: msg})
			}
			sort.Slice(cc.Details, func(i, j int) bool {
				if cc.Details[i].Severity != cc.Details[j].Severity {
					return cc.Details[i].Severity < cc.Details[j].Severity // HEALTH_ERR before HEALTH_WARN
				}
				return cc.Details[i].Name < cc.Details[j].Name
			})
		}
		ci.Clusters = append(ci.Clusters, cc)
	}
	sort.Slice(ci.Clusters, func(i, j int) bool {
		return ci.Clusters[i].Namespace+ci.Clusters[i].Name < ci.Clusters[j].Namespace+ci.Clusters[j].Name
	})
	list := func(what string, gvr schema.GroupVersionResource, kind string, dst *[]CephResource) {
		l, err := c.dynList(ctx, what+".ceph.rook.io", gvr)
		if err != nil {
			return
		}
		for _, it := range l.Items {
			r := CephResource{Kind: kind, Namespace: it.GetNamespace(), Name: it.GetName(), Info: map[string]string{}}
			r.Phase, _, _ = unstructured.NestedString(it.Object, "status", "phase")
			if info, _, _ := unstructured.NestedStringMap(it.Object, "status", "info"); info != nil {
				r.Info = info
			}
			*dst = append(*dst, r)
		}
		sort.Slice(*dst, func(i, j int) bool { return (*dst)[i].Name < (*dst)[j].Name })
	}
	list("cephblockpools", cephBlockPoolGVR, "CephBlockPool", &ci.Pools)
	list("cephfilesystems", cephFilesystemGVR, "CephFilesystem", &ci.Filesys)
	list("cephobjectstores", cephObjectStoreGVR, "CephObjectStore", &ci.Stores)
	return ci
}

// Unhealthy lists the pools / filesystems / object stores not in Ready phase.
func (ci *CephInfo) Unhealthy() []CephResource {
	if ci == nil {
		return nil
	}
	var out []CephResource
	for _, l := range [][]CephResource{ci.Pools, ci.Filesys, ci.Stores} {
		for _, r := range l {
			if !strings.EqualFold(r.Phase, "Ready") {
				out = append(out, r)
			}
		}
	}
	return out
}
