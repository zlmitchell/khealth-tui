package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/strutil"
)

// CSI backend health: what the driver's own control plane says about the
// volumes, beyond "the pods run". Longhorn from its CRs (volume robustness
// and replicas, node/disk conditions, instance managers, engine images,
// backup target, orphans, settings), Trident from the operator, backend
// configs, node registrations and volume publications, and for every driver
// the VolumeAttachments the attach/detach controller holds - a volume still
// attached to a NotReady node while the workload moved is the split-brain
// case where two kubelets can end up writing the same volume.

// evalVolumeAttachments raises the attachment findings that do not need a
// driver: stale attachments to NotReady nodes with the pod elsewhere, and
// attach/detach errors the controller reports.
func evalVolumeAttachments(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	if len(s.VolumeAttachments) == 0 {
		return
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	ready := map[string]bool{}
	for i := range s.Nodes {
		ready[s.Nodes[i].Name] = k8s.NodeReady(&s.Nodes[i])
	}
	// pods per PV: who uses the volume and where
	claimPV := map[string]string{} // ns/claim -> pv
	for i := range s.PVCs {
		p := &s.PVCs[i]
		claimPV[p.Namespace+"/"+p.Name] = p.Spec.VolumeName
	}
	type user struct {
		pod, node, status string
	}
	usersOf := map[string][]user{}
	for i := range s.Pods {
		p := &s.Pods[i]
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim == nil {
				continue
			}
			pv := claimPV[p.Namespace+"/"+v.PersistentVolumeClaim.ClaimName]
			if pv != "" {
				usersOf[pv] = append(usersOf[pv], user{p.Namespace + "/" + p.Name, p.Spec.NodeName, k8s.PodStatus(p)})
			}
		}
	}
	pvClaim := map[string]string{}
	shared := map[string]bool{} // PVs mountable by several nodes at once (RWX / ROX)
	for i := range s.PVs {
		pv := &s.PVs[i]
		if r := pv.Spec.ClaimRef; r != nil {
			pvClaim[pv.Name] = r.Namespace + "/" + r.Name
		}
		for _, m := range pv.Spec.AccessModes {
			if m == corev1.ReadWriteMany || m == corev1.ReadOnlyMany {
				shared[pv.Name] = true
			}
		}
	}
	for i := range s.VolumeAttachments {
		va := &s.VolumeAttachments[i]
		if va.Spec.Source.PersistentVolumeName == nil {
			continue
		}
		pv := *va.Spec.Source.PersistentVolumeName
		obj := pvClaim[pv]
		if obj == "" {
			obj = pv
		}
		if e := va.Status.AttachError; e != nil && !va.Status.Attached {
			add(SevWarn, "storage", obj, fmt.Sprintf("attach to %s failing since %s: %s", va.Spec.NodeName, strutil.HumanDur(now.Sub(e.Time.Time)), strutil.FirstLine(e.Message)), "kubectl describe volumeattachment "+va.Name+"; "+va.Spec.Attacher+" controller logs")
		}
		if e := va.Status.DetachError; e != nil {
			add(SevWarn, "storage", obj, fmt.Sprintf("detach from %s failing since %s: %s - the volume cannot move to another node until it succeeds", va.Spec.NodeName, strutil.HumanDur(now.Sub(e.Time.Time)), strutil.FirstLine(e.Message)), "kubectl describe volumeattachment "+va.Name+"; if the node is gone: kubectl delete volumeattachment "+va.Name+" (after making sure nothing writes to the volume there)")
		}
		if !va.Status.Attached || va.DeletionTimestamp != nil {
			continue
		}
		if isReady, known := ready[va.Spec.NodeName]; known && isReady {
			continue
		}
		// attached to a NotReady (or vanished) node: who wants it now?
		var elsewhere, stuck []string
		for _, u := range usersOf[pv] {
			switch {
			case u.node == va.Spec.NodeName:
				stuck = append(stuck, u.pod+" ("+u.status+")")
			case u.node != "":
				elsewhere = append(elsewhere, u.pod+" on "+u.node+" ("+u.status+")")
			default:
				elsewhere = append(elsewhere, u.pod+" (unscheduled)")
			}
		}
		state := "NotReady"
		if _, known := ready[va.Spec.NodeName]; !known {
			state = "no longer in the cluster"
		}
		switch {
		case shared[pv]:
			add(SevInfo, "storage", obj, fmt.Sprintf("shared (RWX/ROX) volume still attached to %s (%s); the other nodes keep their own attachment", va.Spec.NodeName, state), "kubectl delete volumeattachment "+va.Name+" when the node will not return")
		case len(elsewhere) > 0:
			add(SevCrit, "storage", obj, fmt.Sprintf("volume is still attached to %s (%s) while %s waits for it: RWO volumes cannot attach twice, and if the old kubelet still runs the pod there both nodes write the same volume once the attachment is forced", va.Spec.NodeName, state, strutil.TruncList(elsewhere, 2)), "confirm the node is really down (power/console), then let the attach/detach controller force-detach (6 min) or kubectl delete volumeattachment "+va.Name+"; never force while the old node may still be writing")
		case len(stuck) > 0:
			add(SevWarn, "storage", obj, fmt.Sprintf("volume attached to %s (%s) with %s still bound there: the pod cannot be rescheduled until the node returns or is deleted", va.Spec.NodeName, state, strutil.TruncList(stuck, 2)), "StatefulSet pods are never force-deleted automatically: kubectl delete pod --force --grace-period=0 once the node is confirmed down (or fence the node)")
		default:
			add(SevInfo, "storage", obj, fmt.Sprintf("volume attached to %s (%s) with no pod using it", va.Spec.NodeName, state), "kubectl delete volumeattachment "+va.Name+" when the node will not return")
		}
	}
}

// evalSnapshots covers the CSI snapshot objects for every driver: a
// snapshot that errored or never became ready, a class whose driver is not
// installed, contents stuck deleting, and snapshots piling up with no
// controller to serve them.
func evalSnapshots(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	si := s.Snapshots
	if si == nil {
		return
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	drivers := map[string]bool{}
	for i := range s.CSIDrivers {
		drivers[s.CSIDrivers[i].Name] = true
	}
	// the external snapshot-controller (rke2: rke2-snapshot-controller) turns
	// VolumeSnapshots into contents; without it every snapshot stays pending
	controller := false
	for i := range s.Deployments {
		if strings.Contains(s.Deployments[i].Name, "snapshot-controller") {
			controller = true
		}
	}
	if !controller && len(si.Snapshots) > 0 {
		add(SevCrit, "storage", "snapshot-controller", fmt.Sprintf("%d VolumeSnapshots exist but no snapshot-controller Deployment runs: none of them will ever be taken", len(si.Snapshots)), "install the CSI external snapshot-controller (rke2: the rke2-snapshot-controller chart; upstream: kubernetes-csi/external-snapshotter deploy/kubernetes/snapshot-controller)")
	}
	for _, c := range si.Classes {
		if !drivers[c.Driver] {
			add(SevWarn, "storage", "volumesnapshotclass/"+c.Name, "VolumeSnapshotClass "+c.Name+" names driver "+c.Driver+" which is not installed: snapshots with this class stay pending", "install the driver or delete the class")
		}
	}
	for _, vs := range si.Snapshots {
		obj := vs.Namespace + "/" + vs.Name
		if vs.Ready || vs.Deleting {
			continue
		}
		age := now.Sub(vs.Created)
		switch {
		case vs.Error != "":
			if age < 2*time.Minute {
				continue // the controller retries; give it a moment
			}
			hint := "kubectl -n " + vs.Namespace + " describe volumesnapshot " + vs.Name + "; the driver's csi-snapshotter sidecar logs"
			switch {
			case strings.Contains(vs.Error, "cannot get claim"):
				hint = "the source PVC " + vs.SourcePVC + " does not exist in " + vs.Namespace + ": recreate the snapshot from an existing claim"
			case strings.Contains(vs.Error, "default snapshot class"):
				hint = "set volumeSnapshotClassName on the snapshot, or annotate one class for the claim's driver with snapshot.storage.kubernetes.io/is-default-class=true (the default is per driver)"
			}
			add(SevWarn, "storage", obj, fmt.Sprintf("VolumeSnapshot %s of claim %s failed (%s ago): %s", vs.Name, strutil.FirstNonEmpty(vs.SourcePVC, vs.SourceContent), strutil.HumanDur(age), strutil.TruncStr(strutil.FirstLine(vs.Error), 160)), hint)
		case age > 10*time.Minute:
			add(SevWarn, "storage", obj, fmt.Sprintf("VolumeSnapshot %s of claim %s is not ready after %s and reports no error", vs.Name, strutil.FirstNonEmpty(vs.SourcePVC, vs.SourceContent), strutil.HumanDur(age)), "kubectl -n "+vs.Namespace+" describe volumesnapshot "+vs.Name+"; is the snapshot-controller running and does the driver's csi-snapshotter sidecar log errors?")
		}
	}
	for _, c := range si.Contents {
		obj := "volumesnapshotcontent/" + c.Name
		if c.Snapshot != "" {
			obj = c.Snapshot
		}
		switch {
		case c.Deleting && now.Sub(c.DeletedAt) > 10*time.Minute:
			add(SevWarn, "storage", obj, fmt.Sprintf("VolumeSnapshotContent %s has been deleting for %s (driver %s): the driver did not delete the snapshot on the backend, so its finalizer stays", c.Name, strutil.HumanDur(now.Sub(c.DeletedAt)), c.Driver), "csi-snapshotter sidecar logs of "+c.Driver+"; if the backend snapshot is gone: remove the finalizer (kubectl patch volumesnapshotcontent "+c.Name+" -p '{\"metadata\":{\"finalizers\":null}}' --type=merge)")
		case c.Error != "" && !c.Ready && now.Sub(c.Created) > 2*time.Minute:
			add(SevWarn, "storage", obj, fmt.Sprintf("VolumeSnapshotContent %s (driver %s) failed: %s", c.Name, c.Driver, strutil.TruncStr(strutil.FirstLine(c.Error), 160)), "csi-snapshotter sidecar logs of "+c.Driver)
		}
	}
}

// evalTridentProtect covers Trident Protect: vaults that are not
// Available, applications whose protection is unhealthy, failed or stuck
// runs (a run with reclaimPolicy Delete cannot finish deleting while its
// vault is unreachable, and holds the application lock so every later run
// stays Blocked), and schedules with nothing usable to write to.
func evalTridentProtect(in Input, add func(Severity, string, string, string, string)) {
	tp := in.Snap.Protect
	if tp == nil {
		return
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	vaultOK := map[string]bool{}
	for _, v := range tp.Vaults {
		obj := v.Namespace + "/" + v.Name
		where := v.Provider
		if v.Endpoint != "" || v.Bucket != "" {
			where += " " + v.Endpoint + "/" + v.Bucket
		}
		switch {
		case strings.EqualFold(v.State, "Available"):
			vaultOK[v.Name] = true
		case strings.EqualFold(v.State, "Terminating"):
			add(SevWarn, "storage", obj, "Trident Protect AppVault "+v.Name+" ("+where+") is being deleted"+problemSuffix(v.Error), "runs still referencing it keep it; with the bucket gone remove the finalizer")
		default:
			add(SevCrit, "storage", obj, fmt.Sprintf("Trident Protect AppVault %s (%s) is %s: %s - every snapshot, backup and restore using it fails, and runs with reclaimPolicy Delete cannot even be deleted", v.Name, where, strutil.FirstNonEmpty(v.State, "not ready"), strutil.FirstNonEmpty(strutil.TruncStr(strutil.FirstLine(strutil.FirstNonEmpty(v.Error, v.Message)), 160), "no detail")), "kubectl -n "+v.Namespace+" describe appvault "+v.Name+"; endpoint reachability from the trident-protect controller, bucket name and the credentials secret (Access Denied = wrong keys or bucket policy)")
		}
	}
	for _, a := range tp.Applications {
		if strings.EqualFold(a.ProtectionHealth, "Unhealthy") || (a.ProtectionState != "" && !strings.EqualFold(a.ProtectionState, "Full") && len(a.Details) > 0) {
			sev := SevInfo
			if strings.EqualFold(a.ProtectionHealth, "Unhealthy") {
				sev = SevWarn
			}
			add(sev, "storage", a.Namespace+"/"+a.Name, fmt.Sprintf("Trident Protect application %s protection is %s (%s): %s", a.Name, strutil.FirstNonEmpty(a.ProtectionState, "unknown"), strutil.FirstNonEmpty(a.ProtectionHealth, "health unknown"), strutil.TruncList(a.Details, 3)), "kubectl -n "+a.Namespace+" describe application.protect.trident.netapp.io "+a.Name+"; a Schedule with a usable AppVault gives Full protection")
		}
	}
	// runs: the newest failure per app and kind, stuck deletions; the
	// Blocked ones are grouped by the lock they wait for, with its holder
	type key struct{ ns, app, kind string }
	seenFail := map[key]bool{}
	for _, list := range [][]k8s.ProtectRun{tp.Snapshots, tp.Backups} {
		for _, r := range list {
			obj := r.Namespace + "/" + r.Name
			k := key{r.Namespace, r.App, r.Kind}
			switch {
			case r.Deleting && now.Sub(r.DeletedAt) > 5*time.Minute:
				why := "the controller must delete its archive from the vault first"
				if !vaultOK[r.Vault] {
					why = "its vault " + r.Vault + " is not Available, so the archive cannot be removed"
				}
				add(SevWarn, "storage", obj, fmt.Sprintf("Trident Protect %s %s has been deleting for %s: %s; while it exists it holds the application lock and later runs stay Blocked", r.Kind, r.Name, strutil.HumanDur(now.Sub(r.DeletedAt)), why), "fix the vault, or if its data is gone for good: kubectl -n "+r.Namespace+" patch "+strings.ToLower(r.Kind)+"s.protect.trident.netapp.io "+r.Name+" --type=merge -p '{\"metadata\":{\"finalizers\":null}}'")
			case r.Failed():
				if seenFail[k] {
					continue
				}
				seenFail[k] = true
				hint := "kubectl -n " + r.Namespace + " describe " + strings.ToLower(r.Kind) + "s.protect.trident.netapp.io " + r.Name + "; the vault state and the trident-protect controller log"
				if strings.Contains(r.Error, "does not support VolumeSnapshots") {
					hint = "the application includes a PVC on a driver without CSI snapshot support (nfs.csi.k8s.io, local-path, hostPath): narrow the Application with includedNamespaces[].labelSelector or resourceFilter so only snapshot-capable claims are in it, or move that claim to a snapshot-capable class - backups snapshot first, so they fail the same way"
				}
				add(SevWarn, "storage", obj, fmt.Sprintf("Trident Protect %s %s of application %s failed: %s", r.Kind, r.Name, r.App, strutil.TruncStr(strutil.FirstLine(r.Error), 160)), hint)
			case strings.EqualFold(r.State, "Blocked"):
			case strings.EqualFold(r.State, "Running") && now.Sub(r.Created) > 2*time.Hour:
				add(SevInfo, "storage", obj, fmt.Sprintf("Trident Protect %s %s of application %s has been running for %s", r.Kind, r.Name, r.App, strutil.HumanDur(now.Sub(r.Created))), "kopia/restic data movement of large volumes takes long; the kopiavolumebackups CRs show per-volume progress")
			}
		}
	}
	for _, b := range tp.BlockedLocks() {
		if h := b.Holder; h != nil {
			state := h.State
			switch {
			case h.Deleting:
				state = fmt.Sprintf("%s, deleting for %s", h.State, strutil.HumanDur(now.Sub(h.DeletedAt)))
				if !vaultOK[h.Vault] {
					state += " because vault " + h.Vault + " is not Available"
				}
			case strings.EqualFold(h.State, "Running"):
				state = "Running for " + strutil.HumanDur(now.Sub(h.Created))
			}
			hint := "wait for it to finish, or clear it"
			if h.Deleting {
				hint = "fix the vault so the archive can be deleted, or drop the finalizer: kubectl -n " + h.Namespace + " patch " + strings.ToLower(h.Kind) + "s.protect.trident.netapp.io " + h.Name + " --type=merge -p '{\"metadata\":{\"finalizers\":null}}'"
			}
			add(SevWarn, "storage", b.Namespace+"/"+b.App, fmt.Sprintf("%d Trident Protect runs of application %s are Blocked on lock %s, held by %s %s (%s): %s", len(b.Waiting), b.App, b.Lock, strings.ToLower(h.Kind), h.Name, state, strutil.TruncList(b.Waiting, 3)), hint)
		} else if b.Stale && b.Lease != nil {
			l := b.Lease
			until := "already expired"
			if exp := l.Expires(); exp.After(now) {
				until = "expires in " + strutil.HumanDur(exp.Sub(now)) + " (leaseDurationSeconds " + fmt.Sprint(int(l.Duration.Seconds())) + ")"
			}
			add(SevWarn, "storage", b.Namespace+"/"+b.App, fmt.Sprintf("%d Trident Protect runs of application %s are Blocked on lock %s whose holder %s no longer exists (deleted while it held the lock): nothing releases the Lease, it %s; %s", len(b.Waiting), b.App, b.Lock, l.Holder, until, strutil.TruncList(b.Waiting, 3)), "kubectl -n "+b.Namespace+" delete lease "+b.Lock+" unblocks them now (safe: the holder is gone)")
		} else {
			add(SevWarn, "storage", b.Namespace+"/"+b.App, fmt.Sprintf("%d Trident Protect runs of application %s are Blocked on lock %s and no run of that kind is in flight: the lock may be stale (controller restarted mid-run)", len(b.Waiting), b.App, b.Lock), "kubectl -n "+b.Namespace+" get lease "+b.Lock+" shows the holder; delete it when that run no longer exists")
		}
	}
	for _, s := range tp.Schedules {
		obj := s.Namespace + "/" + s.Name
		switch {
		case !s.Enabled:
			add(SevInfo, "storage", obj, "Trident Protect schedule "+s.Name+" is disabled: application "+s.App+" gets no automatic snapshots or backups", "")
		case s.Vault != "" && !vaultOK[s.Vault]:
			add(SevWarn, "storage", obj, "Trident Protect schedule "+s.Name+" ("+s.Granularity+") writes to AppVault "+s.Vault+" which is not Available: every scheduled backup of "+s.App+" fails", "see the vault finding")
		case s.Error != "":
			add(SevWarn, "storage", obj, "Trident Protect schedule "+s.Name+": "+strutil.TruncStr(strutil.FirstLine(s.Error), 160), "")
		}
	}
}

// evalLonghorn raises the Longhorn findings for the driver.longhorn.io
// CSIStatus. Attribution: volumes to their PVC, node facts to the node.
func evalLonghorn(in Input, d k8s.CSIStatus, add func(Severity, string, string, string, string)) {
	li := d.Longhorn
	s := in.Snap
	if li == nil {
		return
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	k8sReady := map[string]bool{}
	for i := range s.Nodes {
		k8sReady[s.Nodes[i].Name] = k8s.NodeReady(&s.Nodes[i])
	}
	lhNodes := map[string]*k8s.LonghornNode{}
	schedulable, allowed := 0, 0 // nodes taking replicas now / nodes meant to
	for i := range li.Nodes {
		n := &li.Nodes[i]
		lhNodes[n.Name] = n
		if n.AllowScheduling {
			allowed++
		}
		if n.Ready && n.Schedulable && n.AllowScheduling {
			schedulable++
		}
	}

	// ---- nodes, disks, instance managers ----
	for i := range li.Nodes {
		n := &li.Nodes[i]
		if !n.Ready {
			if k8sReady[n.Name] {
				add(SevCrit, "storage", n.Name, "Longhorn node not ready although the Kubernetes node is: "+strutil.FirstNonEmpty(n.ReadyMsg, "longhorn-manager on the node is down"), "kubectl -n longhorn-system get pods -o wide --field-selector spec.nodeName="+n.Name+"; longhorn-manager logs on that node")
			}
			// a NotReady Kubernetes node is reported by the node checks; the volumes on it below
		} else {
			if n.InstanceManager != "" && n.InstanceManager != "running" {
				add(SevCrit, "storage", n.Name, "Longhorn instance manager on the node is "+n.InstanceManager+": no engine or replica process can run here, every volume with a replica on this node is degraded and volumes attached here are down", "kubectl -n longhorn-system get instancemanagers -l longhorn.io/node="+n.Name+"; kubectl -n longhorn-system logs instance-manager-<id>; check the priority class / resource requests")
			}
			if !n.Schedulable && n.AllowScheduling {
				add(SevWarn, "storage", n.Name, "Longhorn cannot schedule replicas on the node: "+strutil.FirstNonEmpty(n.SchedulableMsg, "no schedulable disk"), "kubectl -n longhorn-system describe nodes.longhorn.io "+n.Name)
			}
			for cname, c := range n.Conditions {
				if c.Status {
					continue
				}
				switch cname {
				case "MountPropagation":
					add(SevCrit, "storage", n.Name, "kubelet mount propagation is not enabled on the node: Longhorn cannot mount volumes for pods there", "the kubelet needs the mount-propagation feature (default on rke2/k3s); check the longhorn-manager DaemonSet mountPropagation: Bidirectional and that /var/lib/kubelet is not a private mount")
				case "RequiredPackages", "NFSClientInstalled", "KernelModulesLoaded", "Multipathd":
					sev := SevWarn
					if cname == "RequiredPackages" {
						sev = SevCrit
					}
					add(sev, "storage", n.Name, "Longhorn "+cname+" condition failed: "+strutil.FirstNonEmpty(c.Message, c.Reason), longhornPackageHint(cname))
				}
			}
		}
		if n.Eviction {
			add(SevInfo, "storage", n.Name, "Longhorn eviction requested for the node: replicas are being moved off it", "")
		}
		for _, disk := range n.Disks {
			obj := n.Name + ":" + disk.Path
			switch {
			case !disk.Ready && n.Ready:
				add(SevCrit, "storage", obj, "Longhorn disk not ready: "+strutil.FirstNonEmpty(disk.ReadyMsg, "disk path missing or unreadable"), "mount the disk at "+disk.Path+" or remove it from the node (Longhorn UI > Node > Edit disks, or kubectl -n longhorn-system edit nodes.longhorn.io "+n.Name+")")
			case !disk.Schedulable && disk.AllowScheduling && n.Ready:
				add(SevWarn, "storage", obj, "Longhorn disk not schedulable: "+strutil.FirstNonEmpty(disk.SchedulableMsg, "insufficient storage")+fmt.Sprintf(" (available %s of %s, scheduled %s, reserved %s)", strutil.HumanBytes(float64(disk.Available)), strutil.HumanBytes(float64(disk.Maximum)), strutil.HumanBytes(float64(disk.Scheduled)), strutil.HumanBytes(float64(disk.Reserved))), "free space on the disk, lower storage-reserved, or raise storage-over-provisioning-percentage (replicas are thin: scheduled != used)")
			}
			if disk.Maximum > 0 && disk.Ready {
				freePct := disk.Available * 100 / disk.Maximum
				if freePct < 10 {
					add(SevCrit, "storage", obj, fmt.Sprintf("Longhorn disk %d%% full (%s free of %s): replicas here stop growing and go to error when it fills", 100-freePct, strutil.HumanBytes(float64(disk.Available)), strutil.HumanBytes(float64(disk.Maximum))), "free space or add a disk; volumes are thin-provisioned, actual usage grows with writes and snapshots")
				}
			}
		}
	}
	// instance managers on nodes without a Longhorn node object
	for _, im := range li.InstanceManagers {
		if _, ok := lhNodes[im.Node]; !ok && im.State != "running" {
			add(SevWarn, "storage", im.Node, "Longhorn instance manager "+im.Name+" is "+im.State, "")
		}
	}

	// ---- engine images ----
	for _, ei := range li.EngineImages {
		if ei.Incompatible && ei.RefCount > 0 {
			add(SevCrit, "storage", d.Driver, fmt.Sprintf("engine image %s (%s) is incompatible with this Longhorn version and %d volumes still use it", ei.Name, ei.Version, ei.RefCount), "upgrade those volumes' engine (Longhorn UI > Volume > Upgrade Engine) before the next Longhorn upgrade")
		}
		var notOnReady []string
		for _, n := range ei.NotOn {
			if k8sReady[n] {
				notOnReady = append(notOnReady, n)
			}
		}
		if ei.State != "deployed" && ei.RefCount > 0 && len(notOnReady) > 0 {
			add(SevWarn, "storage", d.Driver, fmt.Sprintf("engine image %s (%s) is %s, missing on %s: volumes cannot attach or place replicas on those nodes", ei.Name, ei.Version, strutil.FirstNonEmpty(ei.State, "not deployed"), strutil.TruncList(notOnReady, 4)), "kubectl -n longhorn-system get pods -l longhorn.io/component=engine-image -o wide; image pull / fapolicyd / disk space on those nodes")
		}
	}

	// ---- volumes ----
	nodeDown := func(n string) bool {
		if n == "" {
			return false
		}
		if r, ok := k8sReady[n]; ok && !r {
			return true
		}
		if ln := lhNodes[n]; ln != nil && !ln.Ready {
			return true
		}
		return false
	}
	podsByName := map[string]*corev1.Pod{}
	for i := range s.Pods {
		podsByName[s.Pods[i].Name] = &s.Pods[i]
	}
	var singles []string
	for i := range li.Volumes {
		v := &li.Volumes[i]
		obj := v.PVC
		if obj == "" {
			obj = v.Name
		}
		healthy := v.Healthy()
		var failedOn, rebuilding []string
		for _, r := range v.ReplicaList {
			switch {
			case r.Rebuild >= 0:
				rebuilding = append(rebuilding, fmt.Sprintf("%s %d%%", strutil.FirstNonEmpty(r.Node, "?"), r.Rebuild))
			case r.Mode == "WO":
				rebuilding = append(rebuilding, strutil.FirstNonEmpty(r.Node, "?"))
			case r.FailedAt != "" || r.Mode == "ERR" || r.State == "error" || r.State == "unknown":
				failedOn = append(failedOn, strutil.FirstNonEmpty(r.Node, "unscheduled"))
			case r.Node == "":
				failedOn = append(failedOn, "unscheduled")
			case r.Mode == "" && len(v.ReplicaMode) > 0 && (r.State == "running" || r.State == "starting"):
				// a fresh replica the engine has not admitted yet (rebuild about to start)
				rebuilding = append(rebuilding, r.Node+" (joining)")
			}
		}
		sort.Strings(failedOn)
		detail := fmt.Sprintf("%d/%d replicas healthy", healthy, v.Replicas)
		if len(failedOn) > 0 {
			detail += " (failed: " + strutil.TruncList(strutil.Uniq(failedOn), 3) + ")"
		}
		if len(rebuilding) > 0 {
			detail += ", rebuilding on " + strutil.TruncList(rebuilding, 3)
		}
		pods := ""
		if len(v.Workloads) > 0 {
			pods = " used by " + strutil.TruncList(v.Workloads, 2)
		}
		everScheduled := false
		for _, r := range v.ReplicaList {
			if r.Node != "" {
				everScheduled = true
			}
		}
		switch v.Robustness {
		case "faulted":
			if !v.Scheduled && !everScheduled {
				break // no replica was ever placed: the scheduling finding below says why
			}
			add(SevCrit, "storage", obj, fmt.Sprintf("Longhorn volume %s is FAULTED: every replica failed (%s)%s - the data is unavailable until a replica is salvaged", v.Name, detail, pods), "Longhorn UI > Volume > Salvage (pick the replica with the newest data); if auto-salvage is on and it stays faulted, check the replica directories on the nodes' disks")
		case "degraded":
			sev := SevWarn
			msg := fmt.Sprintf("Longhorn volume %s degraded: %s%s", v.Name, detail, pods)
			if !v.Scheduled {
				msg += "; cannot rebuild: " + strutil.FirstNonEmpty(v.SchedMessage, "replica scheduling failed")
				if v.Replicas > schedulable {
					msg += fmt.Sprintf(" (%d replicas requested, %d schedulable nodes)", v.Replicas, schedulable)
				}
			} else if !v.LastDegraded.IsZero() && now.Sub(v.LastDegraded) > 30*time.Minute && len(rebuilding) == 0 {
				sev = SevWarn
				msg += fmt.Sprintf("; degraded for %s with no rebuild in progress", strutil.HumanDur(now.Sub(v.LastDegraded)))
			}
			if healthy <= 1 && v.Replicas > 1 {
				sev = SevCrit
				msg = "one healthy replica left: " + msg
			}
			hint := "kubectl -n longhorn-system get replicas -l longhornvolume=" + v.Name + "; a rebuild needs a schedulable disk on another node (replica-soft-anti-affinity, node tags, disk space)"
			if !v.Scheduled && v.Replicas > schedulable {
				hint = "lower numberOfReplicas on the volume (or StorageClass), add a node, or set replica-soft-anti-affinity=true (replicas on the same node give no redundancy)"
			}
			add(sev, "storage", obj, msg, hint)
		case "unknown":
			if v.State == "attached" {
				if nodeDown(v.Node) {
					add(SevCrit, "storage", obj, fmt.Sprintf("Longhorn volume %s is attached on %s which is down: the engine there is unreachable, robustness unknown (%s)%s", v.Name, v.Node, detail, pods), "when the node is confirmed down: delete its pods (node-down-pod-deletion-policy is "+strutil.FirstNonEmpty(li.Setting("node-down-pod-deletion-policy"), "do-nothing")+") so the volume can reattach elsewhere from the surviving replicas; if the node is only partitioned its kubelet may still be writing")
				} else {
					add(SevWarn, "storage", obj, fmt.Sprintf("Longhorn volume %s robustness unknown while attached on %s (engine %s, %s)", v.Name, v.Node, strutil.FirstNonEmpty(v.EngineState, "?"), detail), "kubectl -n longhorn-system get engines -l longhornvolume="+v.Name+"; instance-manager logs on "+v.Node)
				}
			}
		}
		if v.State == "attached" && v.Robustness != "unknown" && nodeDown(v.Node) {
			add(SevCrit, "storage", obj, fmt.Sprintf("Longhorn volume %s is attached on %s which is NotReady%s", v.Name, v.Node, pods), "see the VolumeAttachment finding for this volume")
		}
		if !v.Scheduled && v.Robustness != "degraded" {
			msg := fmt.Sprintf("Longhorn volume %s cannot schedule its replicas: %s", v.Name, strutil.FirstNonEmpty(v.SchedMessage, "replica scheduling failed"))
			hint := "kubectl -n longhorn-system describe volumes.longhorn.io " + v.Name + "; disk space (storage-over-provisioning-percentage, storage-minimal-available-percentage), node/disk tags, replica count vs nodes"
			if strings.Contains(v.SchedMessage, "insufficient storage") {
				msg += fmt.Sprintf(" - the %s volume does not fit the schedulable disks (the PVC is Bound anyway, so the pod will hang in ContainerCreating)", strutil.HumanBytes(float64(v.Size)))
			}
			add(SevCrit, "storage", obj, msg, hint)
		}
		if v.AccessMode == "rwx" && v.State == "attached" && v.ShareState != "" && v.ShareState != "running" {
			add(SevCrit, "storage", obj, fmt.Sprintf("Longhorn RWX volume %s share manager is %s: the NFS export is down, every pod mounting it hangs", v.Name, v.ShareState), "kubectl -n longhorn-system get pods -l longhorn.io/share-manager="+v.Name+"; share-manager logs; nfs-utils on the nodes")
		}
		snapMax := v.SnapshotMax
		if snapMax == 0 {
			snapMax = li.SettingInt("snapshot-max-count", 250)
		}
		switch {
		case v.TooManySnaps || (snapMax > 0 && v.Snapshots > snapMax):
			add(SevWarn, "storage", obj, fmt.Sprintf("Longhorn volume %s has too many snapshots (%d, max %d): new snapshots and backups fail until some are deleted", v.Name, v.Snapshots, snapMax), "delete or purge snapshots (recurring snapshot-cleanup job, or a snapshot job with retain), or raise snapshotMaxCount on the volume")
		case snapMax > 0 && v.Snapshots >= snapMax*9/10:
			add(SevInfo, "storage", obj, fmt.Sprintf("Longhorn volume %s is at %d of %d snapshots: the chain is long (slower rebuilds, more space) and creation stops at the limit", v.Name, v.Snapshots, snapMax), "a recurring snapshot job with retain keeps the chain short")
		}
		if v.ExpansionErr != "" {
			add(SevWarn, "storage", obj, "Longhorn volume "+v.Name+" expansion failed: "+strutil.FirstLine(v.ExpansionErr), "kubectl -n longhorn-system describe engines -l longhornvolume="+v.Name)
		}
		if v.Replicas == 1 && v.PVC != "" && !v.Standby {
			singles = append(singles, v.PVC)
		}
		if v.Image != "" && v.CurrentImage != "" && v.Image != v.CurrentImage {
			add(SevInfo, "storage", obj, fmt.Sprintf("Longhorn volume %s engine upgrade pending (%s -> %s)", v.Name, imageTag(v.CurrentImage), imageTag(v.Image)), "live upgrade happens when the volume is attached and healthy")
		}
		// pods wanting the volume on another node than the engine
		if v.State == "attached" && v.AccessMode != "rwx" {
			for _, w := range v.Workloads {
				if p := podsByName[w]; p != nil && p.Spec.NodeName != "" && p.Spec.NodeName != v.Node && p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodPending {
					add(SevWarn, "storage", obj, fmt.Sprintf("pod %s/%s is scheduled on %s but Longhorn volume %s is attached on %s: the pod waits until the volume detaches there", p.Namespace, p.Name, p.Spec.NodeName, v.Name, v.Node), "kubectl -n longhorn-system get volumeattachments.longhorn.io "+v.Name+" (attachment tickets); the previous pod must terminate first")
				}
			}
		}
	}
	if len(singles) > 0 {
		add(SevInfo, "storage", d.Driver, fmt.Sprintf("%d Longhorn volumes have a single replica (no redundancy: %s)", len(singles), strutil.TruncList(singles, 3)), "numberOfReplicas on the StorageClass or volume; a node loss loses the data")
	}

	// ---- backup target, orphans ----
	for _, bt := range li.BackupTargets {
		switch {
		case bt.URL == "":
			add(SevInfo, "storage", d.Driver, "Longhorn has no backup target: no backups, no DR volumes, snapshots stay on the same disks as the data", "set the backup target (s3://, nfs://, cifs://) and its credential secret in Longhorn settings")
		case !bt.Available:
			add(SevWarn, "storage", d.Driver, "Longhorn backup target "+bt.URL+" unavailable: "+strutil.TruncStr(strutil.FirstNonEmpty(strutil.FirstLine(bt.Message), "not reachable"), 160)+" - scheduled backups fail", "kubectl -n longhorn-system describe backuptargets.longhorn.io "+bt.Name+"; credentials secret "+strutil.FirstNonEmpty(bt.Credential, "(none)")+", endpoint reachability from the longhorn-manager pods (nfs: the export must allow the node IPs; s3: bucket, region, endpoint and the secret's keys)")
		}
	}
	// backups that failed, per volume (the newest error each)
	if failed := li.FailedBackups(); len(failed) > 0 {
		seen := map[string]bool{}
		for _, b := range failed {
			if seen[b.Volume] {
				continue
			}
			seen[b.Volume] = true
			obj := b.Volume
			for _, v := range li.Volumes {
				if v.Name == b.Volume && v.PVC != "" {
					obj = v.PVC
				}
			}
			n := 0
			for _, x := range failed {
				if x.Volume == b.Volume {
					n++
				}
			}
			add(SevWarn, "storage", obj, fmt.Sprintf("Longhorn backup %s of volume %s failed (%d failed backups for this volume): %s", b.Name, b.Volume, n, strutil.TruncStr(strutil.FirstNonEmpty(lastCause(b.Error), b.State), 160)), "kubectl -n longhorn-system describe backups.longhorn.io "+b.Name+"; delete the failed backup CRs once the cause (target reachability, credentials, space) is fixed")
		}
	}
	// a recurring backup job with nowhere to ship to
	for _, j := range li.RecurringJobs {
		if j.Task != "backup" && j.Task != "backup-force-create" {
			continue
		}
		targetOK := false
		for _, bt := range li.BackupTargets {
			if bt.URL != "" && bt.Available {
				targetOK = true
			}
		}
		if !targetOK {
			add(SevWarn, "storage", d.Driver, fmt.Sprintf("recurring backup job %s (%s) is scheduled but the backup target is %s: every run fails", j.Name, j.Cron, backupTargetState(li)), "fix the backup target or delete the job")
			break
		}
	}
	if len(li.Orphans) > 0 {
		byNode := map[string]int{}
		for _, o := range li.Orphans {
			byNode[o.Node]++
		}
		var parts []string
		for _, n := range strutil.SortedKeys(byNode) {
			parts = append(parts, fmt.Sprintf("%s x%d", n, byNode[n]))
		}
		add(SevWarn, "storage", d.Driver, fmt.Sprintf("%d orphaned replica directories on the Longhorn disks (%s): leftover data of deleted or failed replicas taking space", len(li.Orphans), strings.Join(parts, ", ")), "kubectl -n longhorn-system get orphans; delete them (kubectl delete orphan <name>) or enable orphan-resource-auto-deletion")
	}

	// ---- settings ----
	if rc := li.SettingInt("default-replica-count", 3); rc > allowed && allowed > 0 {
		add(SevWarn, "storage", d.Driver, fmt.Sprintf("default-replica-count is %d but only %d Longhorn nodes allow scheduling: every new volume with the default class starts degraded", rc, allowed), "lower default-replica-count / numberOfReplicas, or add schedulable nodes")
	}
	if li.Setting("replica-soft-anti-affinity") == "true" && allowed > 1 {
		add(SevInfo, "storage", d.Driver, "replica-soft-anti-affinity is on: replicas of one volume may land on the same node, so a node loss can take every copy", "keep it off unless the cluster has fewer nodes than replicas")
	}
	if li.SettingInt("concurrent-replica-rebuild-per-node-limit", 5) == 0 {
		add(SevWarn, "storage", d.Driver, "concurrent-replica-rebuild-per-node-limit is 0: degraded volumes never rebuild", "set it back to 5 (default)")
	}
	if li.Setting("auto-salvage") == "false" {
		add(SevInfo, "storage", d.Driver, "auto-salvage is off: a volume whose replicas all fail stays faulted until salvaged by hand", "")
	}
	if li.Setting("upgrade-checker") == "true" {
		add(SevInfo, "storage", d.Driver, "Longhorn upgrade-checker is on: longhorn-manager contacts longhorn.io for version checks", "set upgrade-checker=false on air-gapped or restricted clusters")
	}
	if li.Setting("node-down-pod-deletion-policy") == "do-nothing" {
		for i := range s.StatefulSets {
			if statefulSetUsesLonghorn(&s.StatefulSets[i], s) {
				add(SevInfo, "storage", d.Driver, "node-down-pod-deletion-policy is do-nothing: StatefulSet pods on a lost node stay Terminating and their Longhorn volumes stay attached there until deleted by hand", "delete-statefulset-pod (or delete-both-statefulset-and-deployment-pod) lets Longhorn force-delete them once the node is down")
				break
			}
		}
	}
}

// evalCeph raises the Rook-Ceph findings for the rbd / cephfs CSI drivers:
// the Ceph health checks themselves, the operator phase and the pools the
// classes provision from. Called once per driver, so the cluster findings
// are attributed to the CephCluster object rather than the driver.
func evalCeph(in Input, d k8s.CSIStatus, seen map[string]bool, add func(Severity, string, string, string, string)) {
	ci := d.Ceph
	if ci == nil {
		return
	}
	for _, cc := range ci.Clusters {
		obj := cc.Namespace + "/" + cc.Name
		if seen[obj] {
			continue
		}
		seen[obj] = true
		var errs, warns []string
		for _, det := range cc.Details {
			txt := det.Name + ": " + strutil.TruncStr(strutil.FirstLine(det.Message), 100)
			if det.Severity == "HEALTH_ERR" {
				errs = append(errs, txt)
			} else {
				warns = append(warns, txt)
			}
		}
		switch cc.Health {
		case "HEALTH_ERR":
			add(SevCrit, "storage", obj, "Ceph reports HEALTH_ERR: "+strutil.TruncList(append(errs, warns...), 3)+" - I/O on the affected pools stalls or fails", "kubectl -n "+cc.Namespace+" exec deploy/rook-ceph-tools -- ceph health detail; ceph -s")
		case "HEALTH_WARN":
			if crit, why := cc.Critical(); crit {
				add(SevCrit, "storage", obj, "Ceph reports HEALTH_WARN but "+why+" - PGs inactive, OSDs full or a monitor down mean I/O stalls or data at risk", "kubectl -n "+cc.Namespace+" exec deploy/rook-ceph-tools -- ceph health detail; ceph osd df; ceph mon stat")
			} else {
				add(SevWarn, "storage", obj, "Ceph reports HEALTH_WARN: "+strutil.TruncList(warns, 3), "kubectl -n "+cc.Namespace+" exec deploy/rook-ceph-tools -- ceph health detail")
			}
		case "":
			if cc.Phase != "" && !strings.EqualFold(cc.Phase, "Ready") {
				add(SevCrit, "storage", obj, "Rook has not reached the Ceph cluster yet (phase "+cc.Phase+", no health reported): "+strutil.FirstNonEmpty(strutil.FirstLine(cc.Message), "see the operator log"), "kubectl -n "+cc.Namespace+" logs deploy/rook-ceph-operator")
			}
		}
		if cc.Health != "" && cc.Phase != "" && !strings.EqualFold(cc.Phase, "Ready") && !strings.EqualFold(cc.Phase, "Progressing") && !strings.EqualFold(cc.Phase, "Updating") {
			add(SevWarn, "storage", obj, "Rook CephCluster phase is "+cc.Phase+": "+strutil.FirstNonEmpty(strutil.FirstLine(cc.Message), "the operator cannot reconcile the cluster"), "kubectl -n "+cc.Namespace+" logs deploy/rook-ceph-operator")
		}
		if cc.Capacity.Total > 0 {
			if pct := cc.Capacity.Used * 100 / cc.Capacity.Total; pct >= 85 {
				sev := SevWarn
				if pct >= 95 {
					sev = SevCrit
				}
				add(sev, "storage", obj, fmt.Sprintf("Ceph raw capacity %d%% used (%s of %s): OSDs go read-only at the full ratio (95%%) and every PV on the cluster with them", pct, strutil.HumanBytes(float64(cc.Capacity.Used)), strutil.HumanBytes(float64(cc.Capacity.Total))), "add OSDs or free space; ceph osd df; the nearfull/full ratios (ceph osd dump | grep ratio)")
			}
		}
	}
	for _, r := range ci.Unhealthy() {
		obj := r.Namespace + "/" + r.Name
		if seen[obj] {
			continue
		}
		seen[obj] = true
		add(SevWarn, "storage", obj, fmt.Sprintf("Rook %s %s is in phase %s: StorageClasses on it cannot provision", r.Kind, r.Name, strutil.FirstNonEmpty(r.Phase, "unknown")), "kubectl -n "+r.Namespace+" describe "+strings.ToLower(r.Kind)+" "+r.Name+"; rook-ceph-operator logs")
	}
}

// evalTridentExtra covers the Trident CRs beyond TridentBackend.
func evalTridentExtra(in Input, d k8s.CSIStatus, add func(Severity, string, string, string, string)) {
	ti := d.TridentX
	s := in.Snap
	for _, b := range d.Trident {
		if strings.EqualFold(b.UserState, "suspended") {
			add(SevInfo, "storage", d.Driver, "Trident backend "+b.BackendName+" is suspended by the user: no new volumes are provisioned on it", "tridentctl update backend-state "+b.BackendName+" --user-state normal")
		}
	}
	if ti == nil {
		return
	}
	if o := ti.Orchestrator; o != nil {
		switch strings.ToLower(o.Status) {
		case "installed", "":
		case "installing", "updating":
			add(SevInfo, "cloud", "tridentorchestrator/"+o.Name, "Trident operator is "+o.Status+": "+strutil.FirstLine(o.Message), "")
		default:
			add(SevCrit, "storage", "tridentorchestrator/"+o.Name, "Trident operator reports "+o.Status+": "+strutil.FirstNonEmpty(strutil.FirstLine(o.Message), "installation failed")+" - the CSI driver is not (fully) installed", "kubectl -n "+strutil.FirstNonEmpty(o.Namespace, "trident")+" logs deploy/trident-operator; kubectl describe tridentorchestrator "+o.Name)
		}
	}
	for _, bc := range ti.BackendConfigs {
		obj := bc.Namespace + "/" + bc.Name
		switch strings.ToLower(bc.Phase) {
		case "bound":
			if strings.EqualFold(bc.LastOperation, "failed") {
				add(SevWarn, "storage", obj, "TridentBackendConfig last update failed: "+strutil.FirstNonEmpty(strutil.FirstLine(bc.Message), "see status")+" (the backend keeps its previous config)", "kubectl -n "+bc.Namespace+" describe tridentbackendconfig "+bc.Name)
			}
		case "":
			// no phase yet: creation is what failed (lastOperationStatus Failed with the driver's error)
			what := "has not been processed"
			if strings.EqualFold(bc.LastOperation, "failed") {
				what = "creation failed"
			}
			add(SevCrit, "storage", obj, fmt.Sprintf("TridentBackendConfig %s (%s) %s: %s - no backend, so no volume can be provisioned from it", bc.Name, bc.Driver, what, strutil.FirstNonEmpty(headTail(bc.Message, 90, 90), "see status")), "check the credentials secret "+strutil.FirstNonEmpty(bc.Credentials, "(inline)")+", the management LIF reachability from the trident-controller pod and the SVM permissions; kubectl -n "+bc.Namespace+" describe tridentbackendconfig "+bc.Name)
		case "unbound", "failed", "lost":
			add(SevCrit, "storage", obj, fmt.Sprintf("TridentBackendConfig %s (%s) is %s: %s - no backend, so no volume can be provisioned from it", bc.Name, bc.Driver, bc.Phase, strutil.FirstNonEmpty(headTail(bc.Message, 90, 90), "see status")), "check the credentials secret "+strutil.FirstNonEmpty(bc.Credentials, "(inline)")+", the management LIF reachability from the trident-controller pod and the SVM permissions; kubectl -n "+bc.Namespace+" describe tridentbackendconfig "+bc.Name)
		case "deleting":
			add(SevWarn, "storage", obj, "TridentBackendConfig is deleting; the backend "+bc.BackendName+" is removed once no volume uses it", "")
		}
	}
	if len(ti.Nodes) > 0 {
		var missing, dirty []string
		for i := range s.Nodes {
			n := &s.Nodes[i]
			tn := ti.TridentNode(n.Name)
			switch {
			case tn == nil || tn.Deleted:
				if d.NodePlugin != nil && k8s.NodeReady(n) {
					missing = append(missing, n.Name)
				}
			case !tn.Registered:
				missing = append(missing, n.Name)
			case strings.EqualFold(tn.PublicationState, "dirty"):
				dirty = append(dirty, n.Name)
			}
		}
		if len(missing) > 0 {
			add(SevWarn, "storage", d.Driver, "no TridentNode registration for "+strutil.TruncList(missing, 4)+": the node plugin there never registered with the controller, so volumes cannot be published to those nodes", "kubectl -n trident logs ds/trident-node-linux -c trident-main on that node; the controller must be reachable from the node pods")
		}
		if len(dirty) > 0 {
			add(SevWarn, "storage", d.Driver, "TridentNode publication state is dirty on "+strutil.TruncList(dirty, 4)+": volumes were force-detached from the node and Trident refuses new publications there until it is cleaned", "once the node is healthy: tridentctl node cleanup, or restart the trident node pod on it (Trident 23.10+ cleans automatically with enableForceDetach)")
		}
		// Trident's own host inventory against the backend protocols in use
		san, nas, nvme := false, false, false
		for _, b := range d.Trident {
			dr := strings.ToLower(b.Driver)
			switch {
			case strings.Contains(dr, "nvme"):
				nvme = true
			case strings.Contains(dr, "san") || strings.Contains(dr, "solidfire"):
				san = true
			case strings.Contains(dr, "nas") || strings.Contains(dr, "nfs"):
				nas = true
			}
		}
		var noISCSI, noNFS, noNVMe []string
		for _, tn := range ti.Nodes {
			if len(tn.Services) == 0 || tn.Deleted {
				continue
			}
			if san && !tn.HasService("iSCSI") {
				noISCSI = append(noISCSI, tn.Name)
			}
			if nas && !tn.HasService("NFS") {
				noNFS = append(noNFS, tn.Name)
			}
			if nvme && !tn.HasService("NVMe") {
				noNVMe = append(noNVMe, tn.Name)
			}
		}
		if len(noISCSI) > 0 {
			add(SevWarn, "storage", d.Driver, "Trident found no usable iSCSI on "+strutil.TruncList(noISCSI, 4)+" (TridentNode hostInfo.services) while a SAN backend is configured: SAN volumes cannot attach there", "iscsi-initiator-utils / open-iscsi installed and iscsid running on those nodes, then restart the trident node pod")
		}
		if len(noNFS) > 0 {
			add(SevWarn, "storage", d.Driver, "Trident found no NFS client on "+strutil.TruncList(noNFS, 4)+" (TridentNode hostInfo.services) while a NAS backend is configured: NFS volumes cannot mount there", "nfs-utils / nfs-common on those nodes, then restart the trident node pod")
		}
		if len(noNVMe) > 0 {
			add(SevWarn, "storage", d.Driver, "Trident found no NVMe on "+strutil.TruncList(noNVMe, 4)+" (TridentNode hostInfo.services) while an NVMe backend is configured", "nvme-cli and the nvme-tcp module on those nodes")
		}
	}
	// StorageClasses: what each one can provision on
	for _, r := range ti.ResolveStorageClasses(s.StorageClasses, d.Trident) {
		sel := "backendType=" + strutil.FirstNonEmpty(r.BackendType, "any")
		if r.Selector != "" {
			sel += " selector=" + r.Selector
		}
		if r.PoolsParam != "" {
			sel += " storagePools=" + r.PoolsParam
		}
		switch {
		case !r.Registered:
			add(SevCrit, "storage", r.Name, "StorageClass "+r.Name+" is not registered with Trident (no TridentStorageClass): Trident rejected its parameters or was down when it was created, so PVCs using it stay Pending", "kubectl -n trident logs deploy/trident-controller -c trident-main | grep "+r.Name+"; fix the parameters and recreate the StorageClass")
		case len(r.Matches) == 0:
			add(SevCrit, "storage", r.Name, "StorageClass "+r.Name+" selects no Trident backend ("+sel+"): nothing matches its parameters, so PVCs using it stay Pending"+problemSuffix(strings.Join(r.Problems, "; ")), "tridentctl -n trident get storageclass "+r.Name+" -o json shows the pools it resolved to; check backendType against the backends' storageDriverName, the selector against the virtual pool labels, and storagePools backend names")
		case r.Online() == 0:
			add(SevCrit, "storage", r.Name, fmt.Sprintf("every backend StorageClass %s can provision on is offline (%s): PVCs using it stay Pending", r.Name, tridentMatchNames(r)), "see the backend findings")
		case r.Online() < len(r.Matches):
			add(SevWarn, "storage", r.Name, fmt.Sprintf("StorageClass %s: %d of %d backends it can use are offline (%s)", r.Name, len(r.Matches)-r.Online(), len(r.Matches), tridentMatchNames(r)), "")
		case len(r.Problems) > 0:
			add(SevWarn, "storage", r.Name, "StorageClass "+r.Name+" storagePools parameter names things that do not exist: "+strings.Join(r.Problems, "; "), "")
		}
	}
	if ti.StorageClassesListed {
		known := map[string]bool{}
		for i := range s.StorageClasses {
			known[s.StorageClasses[i].Name] = true
		}
		for _, tsc := range ti.StorageClasses {
			if !known[tsc.Name] {
				add(SevInfo, "storage", tsc.Name, "Trident still holds StorageClass "+tsc.Name+" which no longer exists in Kubernetes", "harmless; kubectl delete tridentstorageclass "+tsc.Name+" to tidy up")
			}
		}
	}
	for vol, nodes := range ti.MultiPublished() {
		add(SevCrit, "storage", vol, "Trident published the single-writer volume to "+strings.Join(nodes, " and ")+" at the same time: two hosts can write the same LUN/export (split brain)", "kubectl get tridentvolumepublications -l volumeID="+vol+"; detach the stale one from the node that no longer runs the pod (tridentctl force-detach is Trident 23.10+ with enableForceDetach)")
	}
	if o := ti.Orchestrator; o != nil && !o.ForceDetach {
		add(SevInfo, "storage", d.Driver, "Trident enableForceDetach is off: a volume on a node that went down stays published there until the node comes back, so its pod cannot restart elsewhere", "set enableForceDetach: true on the TridentOrchestrator (needs the node to be tainted out-of-service / NotReady for 6 min)")
	}
}

func longhornPackageHint(cond string) string {
	switch cond {
	case "RequiredPackages":
		return "install nfs-utils/nfs-common, iscsi-initiator-utils/open-iscsi, cryptsetup, device-mapper on the node"
	case "NFSClientInstalled":
		return "install nfs-utils / nfs-common (RWX volumes mount over NFS)"
	case "KernelModulesLoaded":
		return "modprobe dm_crypt (and iscsi_tcp), persist in /etc/modules-load.d"
	case "Multipathd":
		return "multipathd claims Longhorn devices: blacklist them in /etc/multipath.conf or stop multipathd"
	}
	return ""
}

func statefulSetUsesLonghorn(ss interface{ GetName() string }, s *k8s.Snapshot) bool {
	// a StatefulSet uses Longhorn when any PVC of its volumeClaimTemplates is a Longhorn PV
	name := ss.GetName()
	for i := range s.PVCs {
		p := &s.PVCs[i]
		if !strings.HasSuffix(p.Name, "-"+name+"-0") && !strings.Contains(p.Name, "-"+name+"-") {
			continue
		}
		for j := range s.PVs {
			if s.PVs[j].Name == p.Spec.VolumeName && s.PVs[j].Spec.CSI != nil && s.PVs[j].Spec.CSI.Driver == "driver.longhorn.io" {
				return true
			}
		}
	}
	return false
}

func imageTag(img string) string {
	if i := strings.LastIndex(img, ":"); i >= 0 && !strings.Contains(img[i:], "/") {
		return img[i+1:]
	}
	return img
}

// evalStorageNode cross-checks a node's storage facts with the cluster:
// network mounts that stopped answering, and Longhorn block devices the
// node still presents for volumes the cluster has attached elsewhere or
// given up on (the split-brain case after a partition).
func evalStorageNode(name string, ni *nodeinfo.Info, in Input, add func(Severity, string, string, string, string)) {
	// one finding per export: the same NFS source is mounted twice per pod
	// (the CSI globalmount and the pod's own mount)
	bySource := map[string][]nodeinfo.StaleMount{}
	for _, m := range ni.StaleMounts {
		bySource[m.Source] = append(bySource[m.Source], m)
	}
	for _, src := range strutil.SortedKeys(bySource) {
		ms := bySource[src]
		hint := "the server behind the mount is unreachable from this node; processes in D state cannot be killed until it answers or the mount is forced off (umount -f -l)"
		if in.Snap.IsServiceIP(strings.SplitN(src, ":", 2)[0]) || strings.Contains(ms[0].Mountpoint, "driver.longhorn.io") {
			hint = "a Longhorn RWX export: the share-manager pod (kubectl -n longhorn-system get pods -l longhorn.io/component=share-manager) is unreachable from this node - node partitioned, share manager down, or kube-proxy/CNI broken on this node"
		}
		where := ms[0].Mountpoint
		if len(ms) > 1 {
			where = fmt.Sprintf("%d mountpoints under /var/lib/kubelet", len(ms))
		}
		add(SevCrit, "storage", name, fmt.Sprintf("network mount %s (%s, %s) is hung: stat blocks on it, df stalls, every pod with that volume hangs and cannot terminate", src, ms[0].FSType, where), hint)
	}
	li := in.Snap.Longhorn
	if li == nil || len(ni.Preflight.CSI.LonghornDevs) == 0 {
		return
	}
	session := map[string]string{}
	for _, s := range ni.Preflight.CSI.ISCSISessions {
		if v := s.LonghornVolume(); v != "" {
			session[v] = s.State
		}
	}
	byName := map[string]*k8s.LonghornVolume{}
	for i := range li.Volumes {
		byName[li.Volumes[i].Name] = &li.Volumes[i]
	}
	for _, dev := range ni.Preflight.CSI.LonghornDevs {
		v := byName[dev]
		st := session[dev]
		if st != "" {
			st = " (iSCSI session " + st + ")"
		}
		switch {
		case v == nil:
			add(SevWarn, "storage", name, fmt.Sprintf("/dev/longhorn/%s is still present on the node but the Longhorn volume no longer exists%s", dev, st), "iscsiadm -m session; log out of the stale target (iscsiadm -m node -T iqn.2019-10.io.longhorn:"+dev+" -u) once nothing uses the device")
		case v.State == "attached" && v.Node == name:
		default:
			where := "detached"
			if v.Node != "" {
				where = v.State + " on " + v.Node
			} else if v.State != "detached" {
				where = v.State
			}
			obj := v.PVC
			if obj == "" {
				obj = dev
			}
			add(SevCrit, "storage", obj, fmt.Sprintf("node %s still presents /dev/longhorn/%s%s while the cluster has the volume %s: the engine on this node can keep writing to its local replica, and once the volume is attached elsewhere the two copies diverge (split brain) - whatever is written here is discarded when the node rejoins", name, dev, st, where), "stop the pods on this node (or fence it) before the volume is reattached elsewhere; when the node is back, Longhorn rebuilds its replica from the surviving ones - do not salvage the replica from this node unless it is the only one with the data")
		}
	}
}

func backupTargetState(li *k8s.LonghornInfo) string {
	for _, bt := range li.BackupTargets {
		if bt.URL == "" {
			return "not set"
		}
		if !bt.Available {
			return "unavailable (" + bt.URL + ")"
		}
	}
	return "not set"
}

// lastCause strips the gRPC wrapping Longhorn puts around an error
// ("proxyServer=... destination=...: failed to X: rpc error: code = Internal
// desc = failed to Y: rpc error: ... desc = <the cause>") down to the cause.
func lastCause(msg string) string {
	msg, _, _ = strings.Cut(strings.TrimSpace(msg), "\n")
	if i := strings.LastIndex(msg, "desc = "); i >= 0 {
		msg = msg[i+len("desc = "):]
	}
	return strings.TrimSpace(msg)
}

func tridentMatchNames(r k8s.TridentSCResolution) string {
	var parts []string
	for _, m := range r.Matches {
		st := "online"
		if !m.Backend.Online || (m.Backend.State != "" && m.Backend.State != "online") {
			st = strutil.FirstNonEmpty(m.Backend.State, "offline")
		}
		parts = append(parts, m.Backend.BackendName+" "+st)
	}
	return strings.Join(parts, ", ")
}

// headTail keeps the start and the end of a long message ("... "
// between): Trident's errors put the driver context first and the cause
// (dial tcp ...: no route to host) last.
func headTail(msg string, head, tail int) string {
	msg = strings.TrimSpace(msg)
	if len(msg) <= head+tail+5 {
		return msg
	}
	return msg[:head] + " ... " + msg[len(msg)-tail:]
}
