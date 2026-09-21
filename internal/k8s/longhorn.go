package k8s

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Longhorn backend state from its CRs (longhorn.io/v1beta2, namespace
// longhorn-system): every volume with its replicas and engine, the Longhorn
// view of each node and disk, the instance managers, engine images, the
// backup target, orphans and the settings the checks care about. Fetch reads
// them in parallel with the rest of the snapshot (skipped for
// perf.denied_ttl when the CRDs are absent); Snapshot.Cloud attaches the
// result to the driver.longhorn.io CSIStatus.

// LonghornInfo is the Longhorn control-plane picture.
type LonghornInfo struct {
	Namespace        string // where Longhorn is installed (the namespace of its CRs); "" = not seen yet
	Volumes          []LonghornVolume
	Nodes            []LonghornNode
	InstanceManagers []LonghornInstanceManager
	EngineImages     []LonghornEngineImage
	BackupTargets    []LonghornBackupTarget
	Backups          []LonghornBackup
	RecurringJobs    []LonghornRecurringJob
	Orphans          []LonghornOrphan
	Settings         map[string]string // name -> value (raw; JSON for the per-data-engine ones)
	EnginesFrom      time.Time         // when the engine facts were listed (carried forward between refreshes)
}

// NS is the Longhorn namespace for kubectl hints: the one its CRs live in,
// else the conventional longhorn-system.
func (li *LonghornInfo) NS() string {
	if li != nil && li.Namespace != "" {
		return li.Namespace
	}
	return "longhorn-system"
}

// LonghornVolume is a longhorn.io Volume with what its Replicas, Engine and
// ShareManager say about it.
type LonghornVolume struct {
	Name          string
	PVC           string // namespace/name from status.kubernetesStatus
	PV            string
	Workloads     []string // pod names using it (kubernetesStatus.workloadsStatus)
	State         string   // creating, attached, detached, attaching, detaching, deleting
	Robustness    string   // healthy, degraded, faulted, unknown
	Node          string   // status.currentNodeID: where the engine (and the frontend) runs
	WantNode      string   // spec.nodeID
	Size          int64
	ActualSize    int64
	AccessMode    string // rwo, rwx
	Frontend      string // blockdev, iscsi, ""
	DataLocality  string
	Replicas      int    // spec.numberOfReplicas
	Image         string // spec.image (engine image)
	CurrentImage  string
	Scheduled     bool
	SchedMessage  string // Scheduled condition message when false
	TooManySnaps  bool
	SnapshotMax   int // spec.snapshotMaxCount (0: unlimited)
	LastBackup    string
	LastBackupAt  time.Time
	LastDegraded  time.Time
	ShareState    string // RWX: share manager state (running, error, stopped, starting)
	ShareEndpoint string
	Encrypted     bool
	Standby       bool // DR volume
	ExpansionErr  string
	ReplicaList   []LonghornReplica
	EngineState   string            // engine status.currentState
	EngineNode    string            // engine spec.nodeID
	ReplicaMode   map[string]string // engine replicaModeMap: replica -> RW / WO / ERR
	Rebuilding    map[string]int    // replica -> rebuild progress % (engine rebuildStatus)
	Snapshots     int               // engine snapshot count (without volume-head)
}

// Healthy counts the replicas the engine currently serves in RW mode; when
// the engine is not running it falls back to replicas in running state
// without a failure timestamp.
func (v LonghornVolume) Healthy() int {
	n := 0
	if len(v.ReplicaMode) > 0 {
		for _, m := range v.ReplicaMode {
			if m == "RW" {
				n++
			}
		}
		return n
	}
	for _, r := range v.ReplicaList {
		if r.State == "running" && r.FailedAt == "" {
			n++
		}
	}
	return n
}

// LonghornReplica is one replica of a volume.
type LonghornReplica struct {
	Name     string
	Node     string // spec.nodeID ("" while unscheduled)
	DiskPath string
	State    string // status.currentState: running, stopped, error, starting, unknown
	FailedAt string
	Active   bool
	Mode     string // RW / WO / ERR from the engine, "" when unknown
	Rebuild  int    // rebuild progress %, -1 when not rebuilding
}

// LonghornNode is the longhorn.io Node object for a Kubernetes node.
type LonghornNode struct {
	Name            string
	AllowScheduling bool
	Eviction        bool
	Ready           bool
	ReadyMsg        string
	Schedulable     bool
	SchedulableMsg  string
	Conditions      map[string]LonghornCond // RequiredPackages, Multipathd, NFSClientInstalled, KernelModulesLoaded, MountPropagation, ...
	Disks           []LonghornDisk
	Zone, Region    string
	InstanceManager string // state of the aio/engine instance manager on this node
}

// LonghornCond is a condition of a Longhorn object.
type LonghornCond struct {
	Status  bool
	Reason  string
	Message string
}

// LonghornDisk is one disk of a Longhorn node.
type LonghornDisk struct {
	Name            string
	Path            string
	Type            string // filesystem, block
	AllowScheduling bool
	Eviction        bool
	Ready           bool
	ReadyMsg        string
	Schedulable     bool
	SchedulableMsg  string
	Maximum         int64
	Available       int64
	Scheduled       int64
	Reserved        int64
	Replicas        int
}

// LonghornInstanceManager runs the engine and replica processes on a node.
type LonghornInstanceManager struct {
	Name, Node, Type, State, Image string
	Engines, Replicas              int
}

// LonghornEngineImage is a longhorn-engine image and its deployment state.
type LonghornEngineImage struct {
	Name, Image, Version, State string // state: deployed, deploying, ""
	RefCount                    int64
	Incompatible                bool
	NotOn                       []string // nodes where nodeDeploymentMap is false
}

// LonghornBackupTarget is the backup destination (S3 / NFS / SMB / CIFS).
type LonghornBackupTarget struct {
	Name, URL, Credential string
	Available             bool
	Message               string
	LastSynced            time.Time
}

// LonghornBackup is a backups.longhorn.io object: one snapshot shipped to
// the backup target.
type LonghornBackup struct {
	Name, Volume, Snapshot string
	State                  string // New, Pending, InProgress, Completed, Error, Unknown
	Error                  string
	Created                time.Time
	Size                   int64
}

// LonghornRecurringJob is a recurringjobs.longhorn.io schedule.
type LonghornRecurringJob struct {
	Name, Task, Cron string // Task: snapshot, backup, snapshot-cleanup, filesystem-trim, ...
	Retain           int
	Groups           []string
}

// LonghornOrphan is a replica directory or instance Longhorn found without
// a matching CR.
type LonghornOrphan struct {
	Name, Type, Node string
	DataName         string // orphan spec.parameters.DataName (replica dir)
}

var (
	lhVolumeGVR          = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "volumes"}
	lhReplicaGVR         = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "replicas"}
	lhEngineGVR          = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "engines"}
	lhNodeGVR            = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "nodes"}
	lhInstanceManagerGVR = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "instancemanagers"}
	lhEngineImageGVR     = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "engineimages"}
	lhShareManagerGVR    = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "sharemanagers"}
	lhBackupTargetGVR    = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "backuptargets"}
	lhOrphanGVR          = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "orphans"}
	lhSettingGVR         = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "settings"}
	lhBackupGVR          = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "backups"}
	lhRecurringJobGVR    = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "recurringjobs"}

	// longhornSettings are the settings kept in LonghornInfo.Settings.
	longhornSettings = map[string]bool{
		"default-replica-count": true, "replica-soft-anti-affinity": true, "replica-zone-soft-anti-affinity": true, "replica-disk-soft-anti-affinity": true,
		"storage-over-provisioning-percentage": true, "storage-minimal-available-percentage": true, "default-data-path": true,
		"node-down-pod-deletion-policy": true, "node-drain-policy": true, "auto-salvage": true, "upgrade-checker": true,
		"concurrent-replica-rebuild-per-node-limit": true, "replica-replenishment-wait-interval": true, "backup-target": true,
		"orphan-resource-auto-deletion": true, "orphan-auto-deletion": true, "taint-toleration": true, "priority-class": true,
		"v2-data-engine": true, "snapshot-max-count": true, "auto-delete-pod-when-volume-detached-unexpectedly": true,
		"kubernetes-cluster-autoscaler-enabled": true, "allow-volume-creation-with-degraded-availability": true,
		"deleting-confirmation-flag": true, "engine-replica-timeout": true, "storage-network": true,
	}
)

// lhEngineFacts is what the checks need from an engines.longhorn.io object.
type lhEngineFacts struct {
	state, node string
	modes       map[string]string
	rebuild     map[string]int
	snapshots   int
	expansion   string
}

// longhornInfo lists the Longhorn CRs. nil when the volumes CRD is absent
// or cannot be listed; the other lists are best effort. The volumes list
// comes first because it decides whether the engines are (re)listed.
func (c *Client) longhornInfo(ctx context.Context) *LonghornInfo {
	vols, err := c.dynList(ctx, "volumes.longhorn.io", lhVolumeGVR)
	if err != nil {
		return nil
	}
	li := &LonghornInfo{Settings: map[string]string{}}
	ttl := c.Opts.DiscoveryTTL
	unhealthy := false
	for _, it := range vols.Items {
		if li.Namespace == "" {
			li.Namespace = it.GetNamespace()
		}
		rob, _, _ := unstructured.NestedString(it.Object, "status", "robustness")
		st, _, _ := unstructured.NestedString(it.Object, "status", "state")
		if rob != "healthy" && st != "detached" && st != "" {
			unhealthy = true
		}
	}
	c.cacheMu.Lock()
	needEngines := c.lhEngines == nil || unhealthy || ttl <= 0 || time.Since(c.lhEnginesAt) > ttl
	needSettings := c.lhSettings == nil || ttl <= 0 || time.Since(c.lhSettingsAt) > ttl
	c.cacheMu.Unlock()
	var (
		mu                                   sync.Mutex
		wg                                   sync.WaitGroup
		replicas, engines, shares, ims       *unstructured.UnstructuredList
		nodes, images, targets, orphans, set *unstructured.UnstructuredList
		backups, jobs                        *unstructured.UnstructuredList
	)
	fetch := func(what string, gvr schema.GroupVersionResource, dst **unstructured.UnstructuredList) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := c.dynList(ctx, what+".longhorn.io", gvr)
			if err != nil {
				return
			}
			mu.Lock()
			*dst = l
			mu.Unlock()
		}()
	}
	fetch("replicas", lhReplicaGVR, &replicas)
	if needEngines {
		fetch("engines", lhEngineGVR, &engines)
	}
	fetch("sharemanagers", lhShareManagerGVR, &shares)
	fetch("instancemanagers", lhInstanceManagerGVR, &ims)
	fetch("nodes", lhNodeGVR, &nodes)
	fetch("engineimages", lhEngineImageGVR, &images)
	fetch("backuptargets", lhBackupTargetGVR, &targets)
	fetch("backups", lhBackupGVR, &backups)
	fetch("recurringjobs", lhRecurringJobGVR, &jobs)
	fetch("orphans", lhOrphanGVR, &orphans)
	if needSettings {
		fetch("settings", lhSettingGVR, &set)
	}
	wg.Wait()

	// replicas and engines by volume
	replicasOf := map[string][]LonghornReplica{}
	if replicas != nil {
		for _, it := range replicas.Items {
			o := it.Object
			r := LonghornReplica{Name: it.GetName(), Rebuild: -1}
			r.Node, _, _ = unstructured.NestedString(o, "spec", "nodeID")
			r.DiskPath, _, _ = unstructured.NestedString(o, "spec", "diskPath")
			r.FailedAt, _, _ = unstructured.NestedString(o, "spec", "failedAt")
			r.Active, _, _ = unstructured.NestedBool(o, "spec", "active")
			r.State, _, _ = unstructured.NestedString(o, "status", "currentState")
			vol, _, _ := unstructured.NestedString(o, "spec", "volumeName")
			replicasOf[vol] = append(replicasOf[vol], r)
		}
	}
	engineOf := map[string]lhEngineFacts{}
	if engines != nil {
		for _, it := range engines.Items {
			o := it.Object
			active, _, _ := unstructured.NestedBool(o, "spec", "active")
			vol, _, _ := unstructured.NestedString(o, "spec", "volumeName")
			if prev, ok := engineOf[vol]; ok && !active && prev.state != "" {
				continue // a migration/upgrade engine: keep the active one
			}
			ef := lhEngineFacts{modes: map[string]string{}, rebuild: map[string]int{}}
			ef.state, _, _ = unstructured.NestedString(o, "status", "currentState")
			ef.node, _, _ = unstructured.NestedString(o, "spec", "nodeID")
			ef.expansion, _, _ = unstructured.NestedString(o, "status", "lastExpansionError")
			if m, _, _ := unstructured.NestedStringMap(o, "status", "replicaModeMap"); m != nil {
				ef.modes = m
			}
			if rb, _, _ := unstructured.NestedMap(o, "status", "rebuildStatus"); rb != nil {
				for addr, v := range rb {
					st, _ := v.(map[string]any)
					if st == nil {
						continue
					}
					name := replicaByAddress(o, addr)
					if name == "" {
						name = addr
					}
					if p, ok := st["progress"]; ok {
						ef.rebuild[name] = int(toInt64(p))
					}
					if e, _ := st["error"].(string); e != "" {
						ef.rebuild[name] = -1
					}
				}
			}
			if snaps, _, _ := unstructured.NestedMap(o, "status", "snapshots"); snaps != nil {
				ef.snapshots = len(snaps)
				if _, ok := snaps["volume-head"]; ok {
					ef.snapshots--
				}
			}
			engineOf[vol] = ef
		}
		c.cacheMu.Lock()
		c.lhEngines, c.lhEnginesAt = engineOf, time.Now()
		c.cacheMu.Unlock()
		li.EnginesFrom = c.lhEnginesAt
	} else {
		c.cacheMu.Lock()
		engineOf, li.EnginesFrom = c.lhEngines, c.lhEnginesAt
		c.cacheMu.Unlock()
	}
	shareOf := map[string][2]string{}
	if shares != nil {
		for _, it := range shares.Items {
			st, _, _ := unstructured.NestedString(it.Object, "status", "state")
			ep, _, _ := unstructured.NestedString(it.Object, "status", "endpoint")
			shareOf[it.GetName()] = [2]string{st, ep}
		}
	}
	for _, it := range vols.Items {
		o := it.Object
		v := LonghornVolume{Name: it.GetName()}
		v.State, _, _ = unstructured.NestedString(o, "status", "state")
		v.Robustness, _, _ = unstructured.NestedString(o, "status", "robustness")
		v.Node, _, _ = unstructured.NestedString(o, "status", "currentNodeID")
		v.WantNode, _, _ = unstructured.NestedString(o, "spec", "nodeID")
		v.AccessMode, _, _ = unstructured.NestedString(o, "spec", "accessMode")
		v.Frontend, _, _ = unstructured.NestedString(o, "spec", "frontend")
		v.DataLocality, _, _ = unstructured.NestedString(o, "spec", "dataLocality")
		v.Image, _, _ = unstructured.NestedString(o, "spec", "image")
		v.CurrentImage, _, _ = unstructured.NestedString(o, "status", "currentImage")
		v.Encrypted, _, _ = unstructured.NestedBool(o, "spec", "encrypted")
		v.Standby, _, _ = unstructured.NestedBool(o, "spec", "Standby")
		v.LastBackup, _, _ = unstructured.NestedString(o, "status", "lastBackup")
		if n, _, _ := unstructured.NestedInt64(o, "spec", "numberOfReplicas"); n > 0 {
			v.Replicas = int(n)
		}
		if n, _, _ := unstructured.NestedInt64(o, "spec", "snapshotMaxCount"); n > 0 {
			v.SnapshotMax = int(n)
		}
		if sz, _, _ := unstructured.NestedFieldNoCopy(o, "spec", "size"); sz != nil {
			v.Size = toInt64(sz)
		}
		if sz, _, _ := unstructured.NestedFieldNoCopy(o, "status", "actualSize"); sz != nil {
			v.ActualSize = toInt64(sz)
		}
		if t, _, _ := unstructured.NestedString(o, "status", "lastBackupAt"); t != "" {
			v.LastBackupAt, _ = time.Parse(time.RFC3339, t)
		}
		if t, _, _ := unstructured.NestedString(o, "status", "lastDegradedAt"); t != "" {
			v.LastDegraded, _ = time.Parse(time.RFC3339, t)
		}
		ns, _, _ := unstructured.NestedString(o, "status", "kubernetesStatus", "namespace")
		pvc, _, _ := unstructured.NestedString(o, "status", "kubernetesStatus", "pvcName")
		if pvc != "" {
			v.PVC = ns + "/" + pvc
		}
		v.PV, _, _ = unstructured.NestedString(o, "status", "kubernetesStatus", "pvName")
		if ws, _, _ := unstructured.NestedSlice(o, "status", "kubernetesStatus", "workloadsStatus"); ws != nil {
			for _, w := range ws {
				if m, _ := w.(map[string]any); m != nil {
					if p, _ := m["podName"].(string); p != "" {
						v.Workloads = append(v.Workloads, p)
					}
				}
			}
		}
		v.Scheduled = true
		for name, c := range conditionsOf(o, "status", "conditions") {
			switch name {
			case "Scheduled":
				v.Scheduled = c.Status
				if !c.Status {
					v.SchedMessage = c.Message
				}
			case "TooManySnapshots":
				v.TooManySnaps = c.Status
			}
		}
		if sh, ok := shareOf[v.Name]; ok {
			v.ShareState, v.ShareEndpoint = sh[0], sh[1]
		} else {
			v.ShareState, _, _ = unstructured.NestedString(o, "status", "shareState")
			v.ShareEndpoint, _, _ = unstructured.NestedString(o, "status", "shareEndpoint")
		}
		if ef, ok := engineOf[v.Name]; ok {
			v.EngineState, v.EngineNode, v.ReplicaMode, v.Rebuilding, v.Snapshots, v.ExpansionErr = ef.state, ef.node, ef.modes, ef.rebuild, ef.snapshots, ef.expansion
		}
		v.ReplicaList = replicasOf[v.Name]
		for i := range v.ReplicaList {
			r := &v.ReplicaList[i]
			r.Mode = v.ReplicaMode[r.Name]
			if p, ok := v.Rebuilding[r.Name]; ok {
				r.Rebuild = p
			}
		}
		sort.Slice(v.ReplicaList, func(i, j int) bool { return v.ReplicaList[i].Name < v.ReplicaList[j].Name })
		li.Volumes = append(li.Volumes, v)
	}
	sort.Slice(li.Volumes, func(i, j int) bool { return li.Volumes[i].Name < li.Volumes[j].Name })

	// instance managers, by node
	imState := map[string]string{}
	if ims != nil {
		for _, it := range ims.Items {
			o := it.Object
			im := LonghornInstanceManager{Name: it.GetName()}
			im.Node, _, _ = unstructured.NestedString(o, "spec", "nodeID")
			im.Type, _, _ = unstructured.NestedString(o, "spec", "type")
			im.Image, _, _ = unstructured.NestedString(o, "spec", "image")
			im.State, _, _ = unstructured.NestedString(o, "status", "currentState")
			if m, _, _ := unstructured.NestedMap(o, "status", "instanceEngines"); m != nil {
				im.Engines = len(m)
			}
			if m, _, _ := unstructured.NestedMap(o, "status", "instanceReplicas"); m != nil {
				im.Replicas = len(m)
			}
			li.InstanceManagers = append(li.InstanceManagers, im)
			if im.Type == "aio" || im.Type == "engine" || imState[im.Node] == "" {
				imState[im.Node] = im.State
			}
		}
		sort.Slice(li.InstanceManagers, func(i, j int) bool { return li.InstanceManagers[i].Node < li.InstanceManagers[j].Node })
	}

	// nodes and disks
	if nodes != nil {
		for _, it := range nodes.Items {
			o := it.Object
			if li.Namespace == "" {
				li.Namespace = it.GetNamespace()
			}
			n := LonghornNode{Name: it.GetName(), Conditions: map[string]LonghornCond{}, InstanceManager: imState[it.GetName()]}
			n.AllowScheduling, _, _ = unstructured.NestedBool(o, "spec", "allowScheduling")
			n.Eviction, _, _ = unstructured.NestedBool(o, "spec", "evictionRequested")
			n.Zone, _, _ = unstructured.NestedString(o, "status", "zone")
			n.Region, _, _ = unstructured.NestedString(o, "status", "region")
			for name, c := range conditionsOf(o, "status", "conditions") {
				switch name {
				case "Ready":
					n.Ready, n.ReadyMsg = c.Status, c.Message
				case "Schedulable":
					n.Schedulable, n.SchedulableMsg = c.Status, c.Message
				default:
					n.Conditions[name] = c
				}
			}
			specDisks, _, _ := unstructured.NestedMap(o, "spec", "disks")
			statDisks, _, _ := unstructured.NestedMap(o, "status", "diskStatus")
			for name, sd := range specDisks {
				spec, _ := sd.(map[string]any)
				d := LonghornDisk{Name: name}
				d.Path, _ = spec["path"].(string)
				d.Type, _ = spec["diskType"].(string)
				d.AllowScheduling, _ = spec["allowScheduling"].(bool)
				d.Eviction, _ = spec["evictionRequested"].(bool)
				d.Reserved = toInt64(spec["storageReserved"])
				if st, _ := statDisks[name].(map[string]any); st != nil {
					d.Maximum = toInt64(st["storageMaximum"])
					d.Available = toInt64(st["storageAvailable"])
					d.Scheduled = toInt64(st["storageScheduled"])
					if sr, _ := st["scheduledReplica"].(map[string]any); sr != nil {
						d.Replicas = len(sr)
					}
					if p, _ := st["diskPath"].(string); p != "" && d.Path == "" {
						d.Path = p
					}
					for cname, c := range conditionsOf(st, "conditions") {
						switch cname {
						case "Ready":
							d.Ready, d.ReadyMsg = c.Status, c.Message
						case "Schedulable":
							d.Schedulable, d.SchedulableMsg = c.Status, c.Message
						}
					}
				}
				n.Disks = append(n.Disks, d)
			}
			sort.Slice(n.Disks, func(i, j int) bool { return n.Disks[i].Path < n.Disks[j].Path })
			li.Nodes = append(li.Nodes, n)
		}
		sort.Slice(li.Nodes, func(i, j int) bool { return li.Nodes[i].Name < li.Nodes[j].Name })
	}

	if images != nil {
		for _, it := range images.Items {
			o := it.Object
			ei := LonghornEngineImage{Name: it.GetName()}
			ei.Image, _, _ = unstructured.NestedString(o, "spec", "image")
			ei.Version, _, _ = unstructured.NestedString(o, "status", "version")
			ei.State, _, _ = unstructured.NestedString(o, "status", "state")
			ei.RefCount, _, _ = unstructured.NestedInt64(o, "status", "refCount")
			ei.Incompatible, _, _ = unstructured.NestedBool(o, "status", "incompatible")
			if m, _, _ := unstructured.NestedMap(o, "status", "nodeDeploymentMap"); m != nil {
				for node, ok := range m {
					if b, _ := ok.(bool); !b {
						ei.NotOn = append(ei.NotOn, node)
					}
				}
				sort.Strings(ei.NotOn)
			}
			li.EngineImages = append(li.EngineImages, ei)
		}
		sort.Slice(li.EngineImages, func(i, j int) bool { return li.EngineImages[i].Name < li.EngineImages[j].Name })
	}

	if targets != nil {
		for _, it := range targets.Items {
			o := it.Object
			bt := LonghornBackupTarget{Name: it.GetName()}
			bt.URL, _, _ = unstructured.NestedString(o, "spec", "backupTargetURL")
			bt.Credential, _, _ = unstructured.NestedString(o, "spec", "credentialSecret")
			bt.Available, _, _ = unstructured.NestedBool(o, "status", "available")
			if t, _, _ := unstructured.NestedString(o, "status", "lastSyncedAt"); t != "" {
				bt.LastSynced, _ = time.Parse(time.RFC3339, t)
			}
			for _, c := range conditionsOf(o, "status", "conditions") {
				if c.Message != "" && !bt.Available {
					bt.Message = c.Message
				}
			}
			li.BackupTargets = append(li.BackupTargets, bt)
		}
		sort.Slice(li.BackupTargets, func(i, j int) bool { return li.BackupTargets[i].Name < li.BackupTargets[j].Name })
	}

	if backups != nil {
		for _, it := range backups.Items {
			o := it.Object
			b := LonghornBackup{Name: it.GetName()}
			b.Volume, _, _ = unstructured.NestedString(o, "status", "volumeName")
			if b.Volume == "" {
				b.Volume = it.GetLabels()["backup-volume"]
			}
			b.Snapshot, _, _ = unstructured.NestedString(o, "spec", "snapshotName")
			b.State, _, _ = unstructured.NestedString(o, "status", "state")
			b.Error, _, _ = unstructured.NestedString(o, "status", "error")
			if t, _, _ := unstructured.NestedString(o, "status", "backupCreatedAt"); t != "" {
				b.Created, _ = time.Parse(time.RFC3339, t)
			}
			if b.Created.IsZero() {
				b.Created = it.GetCreationTimestamp().Time
			}
			if sz, _, _ := unstructured.NestedFieldNoCopy(o, "status", "size"); sz != nil {
				b.Size = toInt64(sz)
			}
			li.Backups = append(li.Backups, b)
		}
		sort.Slice(li.Backups, func(i, j int) bool { return li.Backups[i].Created.After(li.Backups[j].Created) })
	}
	if jobs != nil {
		for _, it := range jobs.Items {
			o := it.Object
			j := LonghornRecurringJob{Name: it.GetName()}
			j.Task, _, _ = unstructured.NestedString(o, "spec", "task")
			j.Cron, _, _ = unstructured.NestedString(o, "spec", "cron")
			if n, _, _ := unstructured.NestedInt64(o, "spec", "retain"); n > 0 {
				j.Retain = int(n)
			}
			j.Groups, _, _ = unstructured.NestedStringSlice(o, "spec", "groups")
			li.RecurringJobs = append(li.RecurringJobs, j)
		}
		sort.Slice(li.RecurringJobs, func(i, j int) bool { return li.RecurringJobs[i].Name < li.RecurringJobs[j].Name })
	}

	if orphans != nil {
		for _, it := range orphans.Items {
			o := it.Object
			or := LonghornOrphan{Name: it.GetName()}
			or.Type, _, _ = unstructured.NestedString(o, "spec", "orphanType")
			or.Node, _, _ = unstructured.NestedString(o, "spec", "nodeID")
			or.DataName, _, _ = unstructured.NestedString(o, "spec", "parameters", "DataName")
			li.Orphans = append(li.Orphans, or)
		}
		sort.Slice(li.Orphans, func(i, j int) bool {
			return li.Orphans[i].Node+li.Orphans[i].Name < li.Orphans[j].Node+li.Orphans[j].Name
		})
	}

	if set != nil {
		for _, it := range set.Items {
			if !longhornSettings[it.GetName()] {
				continue
			}
			v, _, _ := unstructured.NestedString(it.Object, "value")
			li.Settings[it.GetName()] = v
		}
		c.cacheMu.Lock()
		c.lhSettings, c.lhSettingsAt = li.Settings, time.Now()
		c.cacheMu.Unlock()
	} else {
		c.cacheMu.Lock()
		if c.lhSettings != nil {
			li.Settings = c.lhSettings
		}
		c.cacheMu.Unlock()
	}
	// the legacy backup-target setting (pre-1.8) when no BackupTarget CR exists
	if len(li.BackupTargets) == 0 {
		if url, ok := li.Settings["backup-target"]; ok {
			li.BackupTargets = append(li.BackupTargets, LonghornBackupTarget{Name: "default", URL: url, Available: url != ""})
		}
	}
	return li
}

// FailedBackups returns the backups in Error state, newest first.
func (li *LonghornInfo) FailedBackups() []LonghornBackup {
	if li == nil {
		return nil
	}
	var out []LonghornBackup
	for _, b := range li.Backups {
		if b.State == "Error" || b.Error != "" {
			out = append(out, b)
		}
	}
	return out
}

// Setting returns a Longhorn setting; the per-data-engine JSON form
// ({"v1":"3","v2":"3"}) is reduced to the v1 value.
func (li *LonghornInfo) Setting(name string) string {
	if li == nil {
		return ""
	}
	v := li.Settings[name]
	if strings.HasPrefix(v, "{") {
		if i := strings.Index(v, `"v1":"`); i >= 0 {
			rest := v[i+6:]
			if j := strings.Index(rest, `"`); j >= 0 {
				return rest[:j]
			}
		}
	}
	return v
}

// SettingInt is Setting as an integer (def when unset or not a number).
func (li *LonghornInfo) SettingInt(name string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(li.Setting(name))); err == nil {
		return n
	}
	return def
}

// Node returns the Longhorn node object for a Kubernetes node.
func (li *LonghornInfo) Node(name string) *LonghornNode {
	if li == nil {
		return nil
	}
	for i := range li.Nodes {
		if li.Nodes[i].Name == name {
			return &li.Nodes[i]
		}
	}
	return nil
}

// VolumeForPVC returns the volume backing namespace/name, if any.
func (li *LonghornInfo) VolumeForPVC(ns, name string) *LonghornVolume {
	if li == nil {
		return nil
	}
	key := ns + "/" + name
	for i := range li.Volumes {
		if li.Volumes[i].PVC == key {
			return &li.Volumes[i]
		}
	}
	return nil
}

// Counts summarizes the volumes by robustness.
func (li *LonghornInfo) Counts() (healthy, degraded, faulted, unknown int) {
	if li == nil {
		return
	}
	for _, v := range li.Volumes {
		switch v.Robustness {
		case "healthy":
			healthy++
		case "degraded":
			degraded++
		case "faulted":
			faulted++
		default:
			if v.State == "attached" || v.Robustness == "unknown" {
				unknown++
			} else {
				healthy++ // detached volumes report robustness "unknown"
			}
		}
	}
	return
}

// conditionsOf reads a Longhorn condition list into a map by type.
func conditionsOf(o map[string]any, fields ...string) map[string]LonghornCond {
	out := map[string]LonghornCond{}
	conds, _, _ := unstructured.NestedSlice(o, fields...)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m == nil {
			continue
		}
		t, _ := m["type"].(string)
		st, _ := m["status"].(string)
		reason, _ := m["reason"].(string)
		msg, _ := m["message"].(string)
		out[t] = LonghornCond{Status: st == "True", Reason: reason, Message: msg}
	}
	return out
}

// replicaByAddress maps a tcp://ip:port key of the engine's rebuild status
// to the replica name through spec.replicaAddressMap.
func replicaByAddress(engine map[string]any, addr string) string {
	addr = strings.TrimPrefix(addr, "tcp://")
	m, _, _ := unstructured.NestedStringMap(engine, "status", "currentReplicaAddressMap")
	if len(m) == 0 {
		m, _, _ = unstructured.NestedStringMap(engine, "spec", "replicaAddressMap")
	}
	for name, a := range m {
		if a == addr {
			return name
		}
	}
	return ""
}

// toInt64 converts the number forms unstructured yields (int64, float64,
// json.Number-ish strings) to int64.
func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	}
	return 0
}
