package k8s

import (
	"context"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CSI volume snapshots (snapshot.storage.k8s.io/v1): the classes, the
// snapshots users asked for and the contents the drivers created. Read
// with the snapshot every tick when the CRDs exist (small objects); the
// checks look for snapshots that never became ready, classes whose driver
// is not installed, contents stuck deleting and a missing controller.

// SnapshotInfo is the CSI snapshot picture.
type SnapshotInfo struct {
	Classes   []SnapshotClass
	Snapshots []VolumeSnapshot
	Contents  []SnapshotContent
}

// SnapshotClass is a VolumeSnapshotClass.
type SnapshotClass struct {
	Name, Driver, DeletionPolicy string
	Default                      bool
	Parameters                   map[string]string
}

// VolumeSnapshot is a namespaced VolumeSnapshot with its status.
type VolumeSnapshot struct {
	Namespace, Name string
	Class           string
	SourcePVC       string // spec.source.persistentVolumeClaimName
	SourceContent   string // spec.source.volumeSnapshotContentName (pre-provisioned)
	Ready           bool
	Content         string // status.boundVolumeSnapshotContentName
	RestoreSize     string
	Error           string
	ErrorAt         time.Time
	Created         time.Time // metadata.creationTimestamp
	SnapshotTime    time.Time // status.creationTime (when the driver took it)
	Deleting        bool
}

// SnapshotContent is a VolumeSnapshotContent.
type SnapshotContent struct {
	Name, Driver, Class, DeletionPolicy string
	Snapshot                            string // namespace/name of the bound VolumeSnapshot
	Handle                              string
	Ready                               bool
	Error                               string
	Deleting                            bool
	DeletedAt                           time.Time
	Created                             time.Time
}

var (
	snapClassGVR   = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"}
	snapshotGVR    = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}
	snapContentGVR = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotcontents"}
)

// snapshotInfo lists the snapshot CRs; nil when the CRDs are absent.
func (c *Client) snapshotInfo(ctx context.Context) *SnapshotInfo {
	classes, err := c.dynList(ctx, "volumesnapshotclasses.snapshot.storage.k8s.io", snapClassGVR)
	if err != nil {
		return nil
	}
	si := &SnapshotInfo{}
	for _, it := range classes.Items {
		o := it.Object
		sc := SnapshotClass{Name: it.GetName(), Default: it.GetAnnotations()["snapshot.storage.kubernetes.io/is-default-class"] == "true"}
		sc.Driver, _, _ = unstructured.NestedString(o, "driver")
		sc.DeletionPolicy, _, _ = unstructured.NestedString(o, "deletionPolicy")
		sc.Parameters, _, _ = unstructured.NestedStringMap(o, "parameters")
		si.Classes = append(si.Classes, sc)
	}
	sort.Slice(si.Classes, func(i, j int) bool { return si.Classes[i].Name < si.Classes[j].Name })
	if l, err := c.dynList(ctx, "volumesnapshots.snapshot.storage.k8s.io", snapshotGVR); err == nil {
		for _, it := range l.Items {
			o := it.Object
			vs := VolumeSnapshot{Namespace: it.GetNamespace(), Name: it.GetName(), Created: it.GetCreationTimestamp().Time, Deleting: it.GetDeletionTimestamp() != nil}
			vs.Class, _, _ = unstructured.NestedString(o, "spec", "volumeSnapshotClassName")
			vs.SourcePVC, _, _ = unstructured.NestedString(o, "spec", "source", "persistentVolumeClaimName")
			vs.SourceContent, _, _ = unstructured.NestedString(o, "spec", "source", "volumeSnapshotContentName")
			vs.Ready, _, _ = unstructured.NestedBool(o, "status", "readyToUse")
			vs.Content, _, _ = unstructured.NestedString(o, "status", "boundVolumeSnapshotContentName")
			if rs, _, _ := unstructured.NestedFieldNoCopy(o, "status", "restoreSize"); rs != nil {
				switch x := rs.(type) {
				case string:
					vs.RestoreSize = x
				default:
					vs.RestoreSize = resource.NewQuantity(toInt64(x), resource.BinarySI).String()
				}
			}
			vs.Error, _, _ = unstructured.NestedString(o, "status", "error", "message")
			if t, _, _ := unstructured.NestedString(o, "status", "error", "time"); t != "" {
				vs.ErrorAt, _ = time.Parse(time.RFC3339, t)
			}
			if t, _, _ := unstructured.NestedString(o, "status", "creationTime"); t != "" {
				vs.SnapshotTime, _ = time.Parse(time.RFC3339, t)
			}
			si.Snapshots = append(si.Snapshots, vs)
		}
		sort.Slice(si.Snapshots, func(i, j int) bool {
			return si.Snapshots[i].Namespace+"/"+si.Snapshots[i].Name < si.Snapshots[j].Namespace+"/"+si.Snapshots[j].Name
		})
	}
	if l, err := c.dynList(ctx, "volumesnapshotcontents.snapshot.storage.k8s.io", snapContentGVR); err == nil {
		for _, it := range l.Items {
			o := it.Object
			sc := SnapshotContent{Name: it.GetName(), Created: it.GetCreationTimestamp().Time, Deleting: it.GetDeletionTimestamp() != nil}
			if dt := it.GetDeletionTimestamp(); dt != nil {
				sc.DeletedAt = dt.Time
			}
			sc.Driver, _, _ = unstructured.NestedString(o, "spec", "driver")
			sc.Class, _, _ = unstructured.NestedString(o, "spec", "volumeSnapshotClassName")
			sc.DeletionPolicy, _, _ = unstructured.NestedString(o, "spec", "deletionPolicy")
			ns, _, _ := unstructured.NestedString(o, "spec", "volumeSnapshotRef", "namespace")
			name, _, _ := unstructured.NestedString(o, "spec", "volumeSnapshotRef", "name")
			if name != "" {
				sc.Snapshot = ns + "/" + name
			}
			sc.Handle, _, _ = unstructured.NestedString(o, "status", "snapshotHandle")
			if sc.Handle == "" {
				sc.Handle, _, _ = unstructured.NestedString(o, "spec", "source", "snapshotHandle")
			}
			sc.Ready, _, _ = unstructured.NestedBool(o, "status", "readyToUse")
			sc.Error, _, _ = unstructured.NestedString(o, "status", "error", "message")
			si.Contents = append(si.Contents, sc)
		}
		sort.Slice(si.Contents, func(i, j int) bool { return si.Contents[i].Name < si.Contents[j].Name })
	}
	return si
}

// ForPVC lists the snapshots taken from a claim, newest first.
func (si *SnapshotInfo) ForPVC(ns, name string) []VolumeSnapshot {
	if si == nil {
		return nil
	}
	var out []VolumeSnapshot
	for _, s := range si.Snapshots {
		if s.Namespace == ns && s.SourcePVC == name {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// DefaultClass returns the default VolumeSnapshotClass for a driver, if any.
func (si *SnapshotInfo) DefaultClass(driver string) *SnapshotClass {
	if si == nil {
		return nil
	}
	for i := range si.Classes {
		if si.Classes[i].Default && si.Classes[i].Driver == driver {
			return &si.Classes[i]
		}
	}
	return nil
}
