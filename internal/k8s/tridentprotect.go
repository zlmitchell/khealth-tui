package k8s

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NetApp Trident Protect (protect.trident.netapp.io/v1): application
// snapshots, backups and schedules with their vault (an S3/Azure/GCP
// bucket). Read when the appvaults CRD exists: the vault state, every
// application's protection state, the snapshot/backup outcomes and the
// schedules. Shapes as observed on Trident Protect 26.06.

// TridentProtect is the picture.
type TridentProtect struct {
	Vaults       []ProtectVault
	Applications []ProtectApplication
	Snapshots    []ProtectRun
	Backups      []ProtectRun
	Schedules    []ProtectSchedule
	// Locks are the coordination.k8s.io Leases the controller takes per
	// application and operation kind (application-<app uid>-snapshot, holder
	// <kind>-<run uid>): who really holds a lock, and whether the holder
	// still exists.
	Locks []ProtectLock
}

// ProtectLock is one application lock Lease.
type ProtectLock struct {
	Namespace, Name string
	AppUID, Kind    string // from the name
	Holder          string // holderIdentity: <kind>-<run uid>
	HolderUID       string
	Acquired        time.Time
	Renewed         time.Time
	Duration        time.Duration // leaseDurationSeconds
}

// Expires is when the lease lapses on its own (renewTime + duration).
func (l ProtectLock) Expires() time.Time {
	t := l.Renewed
	if t.IsZero() {
		t = l.Acquired
	}
	return t.Add(l.Duration)
}

// ProtectVault is an AppVault.
type ProtectVault struct {
	Namespace, Name string
	Provider        string // GenericS3, AWS, Azure, GCP, OntapS3, StorageGridS3
	Endpoint        string
	Bucket          string
	State           string // Available, Error, Terminating
	Error           string
	Message         string
}

// ProtectApplication is an Application (a set of namespaces to protect).
type ProtectApplication struct {
	Namespace, Name  string
	UID              string // the lock names embed it: application-<uid>-snapshot
	Namespaces       []string
	ProtectionState  string // None, Partial, Full
	ProtectionHealth string // Healthy, Unhealthy, ""
	Details          []string
}

// ProtectRun is a Snapshot or Backup of an application.
type ProtectRun struct {
	Kind            string // Snapshot, Backup
	Namespace, Name string
	UID             string
	App, Vault      string
	State           string // Running, Blocked, Completed, Error, Failed, ...
	Error           string
	Created         time.Time
	Completed       time.Time
	DataMover       string
	Deleting        bool // deletionTimestamp set: with reclaimPolicy Delete the archive must be removed from the vault first
	DeletedAt       time.Time
}

// ProtectSchedule is a Schedule.
type ProtectSchedule struct {
	Namespace, Name string
	App, Vault      string
	Granularity     string
	Enabled         bool
	State           string
	Error           string
	MaxRecoveryAge  time.Duration // status.lastRecoveryPoints.maxAge (0 when unknown)
}

var (
	protectVaultGVR    = schema.GroupVersionResource{Group: "protect.trident.netapp.io", Version: "v1", Resource: "appvaults"}
	protectAppGVR      = schema.GroupVersionResource{Group: "protect.trident.netapp.io", Version: "v1", Resource: "applications"}
	protectSnapshotGVR = schema.GroupVersionResource{Group: "protect.trident.netapp.io", Version: "v1", Resource: "snapshots"}
	protectBackupGVR   = schema.GroupVersionResource{Group: "protect.trident.netapp.io", Version: "v1", Resource: "backups"}
	protectScheduleGVR = schema.GroupVersionResource{Group: "protect.trident.netapp.io", Version: "v1", Resource: "schedules"}
)

// tridentProtect lists the Trident Protect CRs; nil when the appvaults CRD
// is absent or cannot be listed.
func (c *Client) tridentProtect(ctx context.Context) *TridentProtect {
	vaults, err := c.dynList(ctx, "appvaults.protect.trident.netapp.io", protectVaultGVR)
	if err != nil {
		return nil
	}
	tp := &TridentProtect{}
	for _, it := range vaults.Items {
		o := it.Object
		v := ProtectVault{Namespace: it.GetNamespace(), Name: it.GetName()}
		v.Provider, _, _ = unstructured.NestedString(o, "spec", "providerType")
		// the spec carries every provider's block, the unused ones empty
		for _, kind := range []string{"s3", "azure", "gcp"} {
			cfg, _, _ := unstructured.NestedMap(o, "spec", "providerConfig", kind)
			for _, k := range []string{"endpoint", "accountName"} {
				if x, _ := cfg[k].(string); x != "" && v.Endpoint == "" {
					v.Endpoint = x
				}
			}
			for _, k := range []string{"bucketName", "bucket"} {
				if x, _ := cfg[k].(string); x != "" && v.Bucket == "" {
					v.Bucket = x
				}
			}
		}
		v.State, _, _ = unstructured.NestedString(o, "status", "state")
		v.Error, _, _ = unstructured.NestedString(o, "status", "error")
		v.Message, _, _ = unstructured.NestedString(o, "status", "message")
		if it.GetDeletionTimestamp() != nil {
			v.State = "Terminating"
		}
		tp.Vaults = append(tp.Vaults, v)
	}
	sort.Slice(tp.Vaults, func(i, j int) bool { return tp.Vaults[i].Name < tp.Vaults[j].Name })
	if l, err := c.dynList(ctx, "applications.protect.trident.netapp.io", protectAppGVR); err == nil {
		for _, it := range l.Items {
			o := it.Object
			a := ProtectApplication{Namespace: it.GetNamespace(), Name: it.GetName(), UID: string(it.GetUID())}
			if ns, _, _ := unstructured.NestedSlice(o, "spec", "includedNamespaces"); ns != nil {
				for _, n := range ns {
					if m, _ := n.(map[string]any); m != nil {
						if s, _ := m["namespace"].(string); s != "" {
							a.Namespaces = append(a.Namespaces, s)
						}
					}
				}
			}
			a.ProtectionState, _, _ = unstructured.NestedString(o, "status", "protectionState")
			a.ProtectionHealth, _, _ = unstructured.NestedString(o, "status", "protectionHealthState")
			a.Details, _, _ = unstructured.NestedStringSlice(o, "status", "protectionStateDetails")
			tp.Applications = append(tp.Applications, a)
		}
		sort.Slice(tp.Applications, func(i, j int) bool {
			return tp.Applications[i].Namespace+"/"+tp.Applications[i].Name < tp.Applications[j].Namespace+"/"+tp.Applications[j].Name
		})
	}
	run := func(what string, gvr schema.GroupVersionResource, kind string, dst *[]ProtectRun) {
		l, err := c.dynList(ctx, what+".protect.trident.netapp.io", gvr)
		if err != nil {
			return
		}
		for _, it := range l.Items {
			o := it.Object
			r := ProtectRun{Kind: kind, Namespace: it.GetNamespace(), Name: it.GetName(), UID: string(it.GetUID()), Created: it.GetCreationTimestamp().Time}
			r.App, _, _ = unstructured.NestedString(o, "spec", "applicationRef")
			r.Vault, _, _ = unstructured.NestedString(o, "spec", "appVaultRef")
			r.DataMover, _, _ = unstructured.NestedString(o, "spec", "dataMover")
			r.State, _, _ = unstructured.NestedString(o, "status", "state")
			r.Error, _, _ = unstructured.NestedString(o, "status", "error")
			if dt := it.GetDeletionTimestamp(); dt != nil {
				r.Deleting, r.DeletedAt = true, dt.Time
			}
			if t, _, _ := unstructured.NestedString(o, "status", "completionTimestamp"); t != "" {
				r.Completed, _ = time.Parse(time.RFC3339, t)
			}
			*dst = append(*dst, r)
		}
		sort.Slice(*dst, func(i, j int) bool { return (*dst)[i].Created.After((*dst)[j].Created) })
	}
	run("snapshots", protectSnapshotGVR, "Snapshot", &tp.Snapshots)
	run("backups", protectBackupGVR, "Backup", &tp.Backups)
	// the lock leases live in the applications' namespaces; one cluster-wide
	// Lease list (node leases and leader elections are small) filtered by name
	if l, err := c.CS.CoordinationV1().Leases("").List(ctx, c.listOpts()); err == nil {
		for i := range l.Items {
			ls := &l.Items[i]
			m := lockNameRe.FindStringSubmatch(ls.Name)
			if m == nil {
				continue
			}
			pl := ProtectLock{Namespace: ls.Namespace, Name: ls.Name, AppUID: m[1], Kind: m[2]}
			if ls.Spec.HolderIdentity != nil {
				pl.Holder = *ls.Spec.HolderIdentity
				if _, uid, ok := strings.Cut(pl.Holder, "-"); ok {
					pl.HolderUID = uid
				}
			}
			if ls.Spec.AcquireTime != nil {
				pl.Acquired = ls.Spec.AcquireTime.Time
			}
			if ls.Spec.RenewTime != nil {
				pl.Renewed = ls.Spec.RenewTime.Time
			}
			if ls.Spec.LeaseDurationSeconds != nil {
				pl.Duration = time.Duration(*ls.Spec.LeaseDurationSeconds) * time.Second
			}
			tp.Locks = append(tp.Locks, pl)
		}
		sort.Slice(tp.Locks, func(i, j int) bool {
			return tp.Locks[i].Namespace+tp.Locks[i].Name < tp.Locks[j].Namespace+tp.Locks[j].Name
		})
	}
	if l, err := c.dynList(ctx, "schedules.protect.trident.netapp.io", protectScheduleGVR); err == nil {
		for _, it := range l.Items {
			o := it.Object
			s := ProtectSchedule{Namespace: it.GetNamespace(), Name: it.GetName(), Enabled: true}
			s.App, _, _ = unstructured.NestedString(o, "spec", "applicationRef")
			s.Vault, _, _ = unstructured.NestedString(o, "spec", "appVaultRef")
			s.Granularity, _, _ = unstructured.NestedString(o, "spec", "granularity")
			if en, found, _ := unstructured.NestedBool(o, "spec", "enabled"); found {
				s.Enabled = en
			}
			s.State, _, _ = unstructured.NestedString(o, "status", "state")
			s.Error, _, _ = unstructured.NestedString(o, "status", "error")
			if ma, _, _ := unstructured.NestedFieldNoCopy(o, "status", "lastRecoveryPoints", "maxAge"); ma != nil {
				s.MaxRecoveryAge = time.Duration(toInt64(ma))
			}
			tp.Schedules = append(tp.Schedules, s)
		}
		sort.Slice(tp.Schedules, func(i, j int) bool {
			return tp.Schedules[i].Namespace+"/"+tp.Schedules[i].Name < tp.Schedules[j].Namespace+"/"+tp.Schedules[j].Name
		})
	}
	return tp
}

// Failed reports whether a run ended badly.
func (r ProtectRun) Failed() bool {
	return strings.EqualFold(r.State, "Error") || strings.EqualFold(r.State, "Failed")
}

// LatestRun returns the newest snapshot or backup of an application in a
// namespace, or nil.
func (tp *TridentProtect) LatestRun(kind, ns, app string) *ProtectRun {
	if tp == nil {
		return nil
	}
	list := tp.Backups
	if kind == "Snapshot" {
		list = tp.Snapshots
	}
	for i := range list {
		if list[i].Namespace == ns && list[i].App == app {
			return &list[i]
		}
	}
	return nil
}

var (
	lockRe     = regexp.MustCompile(`waiting for lock (application-([0-9a-f-]{36})-([a-z]+))`)
	lockNameRe = regexp.MustCompile(`^application-([0-9a-f-]{36})-([a-z]+)$`)
)

// Lock returns the lease for a lock name in a namespace, if any.
func (tp *TridentProtect) Lock(ns, name string) *ProtectLock {
	if tp == nil {
		return nil
	}
	for i := range tp.Locks {
		if tp.Locks[i].Namespace == ns && tp.Locks[i].Name == name {
			return &tp.Locks[i]
		}
	}
	return nil
}

// RunByUID finds a snapshot or backup by its UID.
func (tp *TridentProtect) RunByUID(uid string) *ProtectRun {
	if tp == nil || uid == "" {
		return nil
	}
	for _, list := range [][]ProtectRun{tp.Snapshots, tp.Backups} {
		for i := range list {
			if list[i].UID == uid {
				return &list[i]
			}
		}
	}
	return nil
}

// BlockedOn parses the lock a Blocked run waits for: the lock name, the
// application UID and the lock kind ("snapshot", "backup").
func (r ProtectRun) BlockedOn() (lock, appUID, kind string) {
	m := lockRe.FindStringSubmatch(r.Error)
	if m == nil {
		return "", "", ""
	}
	return m[1], m[2], m[3]
}

// LockHolder finds the run that holds an application lock: a run of the
// lock's kind for the same application that is still in flight - Running,
// or stuck deleting (a failed run with reclaimPolicy Delete whose vault is
// unreachable never releases it). Backups take the snapshot lock through
// their child snapshot (backup-<uid>), so those are candidates too. The
// oldest such run is the holder; nil when none is found.
func (tp *TridentProtect) LockHolder(ns, app, kind string) *ProtectRun {
	if tp == nil {
		return nil
	}
	list := tp.Snapshots
	if kind == "backup" {
		list = tp.Backups
	}
	var holder *ProtectRun
	for i := range list {
		r := &list[i]
		if r.Namespace != ns || r.App != app || strings.EqualFold(r.State, "Blocked") {
			continue
		}
		busy := r.Deleting || strings.EqualFold(r.State, "Running") || strings.EqualFold(r.State, "Pending")
		if !busy {
			continue
		}
		if holder == nil || r.Created.Before(holder.Created) {
			holder = r
		}
	}
	return holder
}

// BlockedLock is a set of runs waiting for one application lock and the
// run holding it. Lease is the lock itself when it could be read; Stale
// means the lease names a holder that no longer exists, so nothing will
// release it before it expires.
type BlockedLock struct {
	Namespace, App, Lock, Kind string
	Waiting                    []string // kind/name
	Holder                     *ProtectRun
	Lease                      *ProtectLock
	Stale                      bool
}

// BlockedLocks groups the Blocked runs by the lock they wait for.
func (tp *TridentProtect) BlockedLocks() []BlockedLock {
	if tp == nil {
		return nil
	}
	appByUID := map[string]ProtectApplication{}
	for _, a := range tp.Applications {
		appByUID[a.UID] = a
	}
	byLock := map[string]*BlockedLock{}
	for _, list := range [][]ProtectRun{tp.Snapshots, tp.Backups} {
		for _, r := range list {
			if !strings.EqualFold(r.State, "Blocked") {
				continue
			}
			lock, uid, kind := r.BlockedOn()
			if lock == "" {
				lock, kind = "application-"+r.App+"-snapshot", "snapshot"
			}
			b := byLock[r.Namespace+"/"+lock]
			if b == nil {
				b = &BlockedLock{Namespace: r.Namespace, App: r.App, Lock: lock, Kind: kind}
				if a, ok := appByUID[uid]; ok {
					b.App = a.Name
				}
				if b.Lease = tp.Lock(r.Namespace, lock); b.Lease != nil {
					// the lease names the holder: exact, and stale when it is gone
					b.Holder = tp.RunByUID(b.Lease.HolderUID)
					b.Stale = b.Holder == nil
				} else {
					b.Holder = tp.LockHolder(r.Namespace, b.App, kind)
				}
				byLock[r.Namespace+"/"+lock] = b
			}
			b.Waiting = append(b.Waiting, strings.ToLower(r.Kind)+"/"+r.Name)
		}
	}
	var out []BlockedLock
	for _, b := range byLock {
		sort.Strings(b.Waiting)
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace+out[i].Lock < out[j].Namespace+out[j].Lock })
	return out
}
