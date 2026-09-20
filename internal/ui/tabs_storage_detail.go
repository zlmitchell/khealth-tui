package ui

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/checks"
	"k8s-health-tui/internal/k8s"
)

// Storage tab detail: enter on a PVC or PV row gathers everything the
// snapshot, the node probes and the backend CRs know about that one volume,
// so a stuck or degraded claim can be triaged without leaving the tab.

// storageDetail dispatches on the selected row id: pvc:<ns>/<name>,
// pv:<name> or node:<name> (a node filesystem row opens the node detail).
func (a *App) storageDetail(id string) (string, []string) {
	kind, rest, _ := strings.Cut(id, ":")
	switch kind {
	case "node":
		return a.nodeDetail(rest)
	case "pvc":
		ns, name, _ := strings.Cut(rest, "/")
		for i := range a.snap.PVCs {
			if p := &a.snap.PVCs[i]; p.Namespace == ns && p.Name == name {
				return "PersistentVolumeClaim " + ns + "/" + name, a.volumeDetail(p, a.pvByName(p.Spec.VolumeName))
			}
		}
	case "pv":
		pv := a.pvByName(rest)
		if pv == nil {
			return "", nil
		}
		var claim *corev1.PersistentVolumeClaim
		if r := pv.Spec.ClaimRef; r != nil {
			for i := range a.snap.PVCs {
				if p := &a.snap.PVCs[i]; p.Namespace == r.Namespace && p.Name == r.Name {
					claim = p
				}
			}
		}
		return "PersistentVolume " + rest, a.volumeDetail(claim, pv)
	}
	return "", nil
}

func (a *App) pvByName(name string) *corev1.PersistentVolume {
	for i := range a.snap.PVs {
		if a.snap.PVs[i].Name == name {
			return &a.snap.PVs[i]
		}
	}
	return nil
}

// volumeDetail renders one claim/volume pair (either may be nil): the
// Kubernetes objects, who mounts it and where, measured usage, the
// attachments the controller holds, the backend's own view (Longhorn
// replicas and backups, the Trident backend and publications, the Ceph
// pool), recent events and the findings raised for it.
func (a *App) volumeDetail(pvc *corev1.PersistentVolumeClaim, pv *corev1.PersistentVolume) []string {
	s := a.snap
	w := a.width - 6
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	table := func(cols []column, rows [][]string) {
		h, lines := renderTable(w, cols, rows)
		add(h)
		add(lines...)
	}
	key, pvName := "", ""
	if pvc != nil {
		key = pvc.Namespace + "/" + pvc.Name
		pvName = pvc.Spec.VolumeName
	}
	if pv != nil {
		pvName = pv.Name
	}

	// ---- the claim ----
	if pvc != nil {
		st := string(pvc.Status.Phase)
		switch pvc.Status.Phase {
		case corev1.ClaimBound:
			st = styleOK.Render(st)
		case corev1.ClaimPending:
			st = styleWarn.Render(st)
		default:
			st = styleCrit.Render(st)
		}
		modes := make([]string, 0, len(pvc.Spec.AccessModes))
		for _, m := range pvc.Spec.AccessModes {
			modes = append(modes, string(m))
		}
		req, capa := "", ""
		if q, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			req = q.String()
		}
		if q, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
			capa = q.String()
		}
		sc := ""
		if pvc.Spec.StorageClassName != nil {
			sc = *pvc.Spec.StorageClassName
		}
		mode := "Filesystem"
		if pvc.Spec.VolumeMode != nil {
			mode = string(*pvc.Spec.VolumeMode)
		}
		add(styleTitle.Render("Claim") + "  " + kv("status", st) + "  " + kv("class", sc) + "  " + kv("access", strings.Join(modes, ",")) + "  " + kv("mode", mode) + "  " + kv("requested", req) + "  " + kv("capacity", capa) + "  " + kv("age", age(pvc.CreationTimestamp.Time)))
		if pvc.Status.Phase == corev1.ClaimPending {
			why := "no PV bound yet"
			if sc == "" {
				why = "no StorageClass on the claim and no default class"
			} else if n := a.provisionerFor(sc); n == "" {
				why = "StorageClass " + sc + " does not exist"
			} else {
				why = "waiting for provisioner " + n + " (WaitForFirstConsumer classes bind when a pod is scheduled)"
			}
			add("  " + styleWarn.Render(why))
		}
		if sel := pvc.Annotations["volume.kubernetes.io/selected-node"]; sel != "" {
			add("  " + kv("selected node", sel) + styleDim.Render("  (WaitForFirstConsumer: the volume is provisioned for this node)"))
		}
		if ds := pvc.Spec.DataSource; ds != nil {
			add("  " + kv("data source", ds.Kind+"/"+ds.Name))
		}
		for _, c := range pvc.Status.Conditions {
			txt := string(c.Type) + "=" + string(c.Status)
			if c.Message != "" {
				txt += " " + c.Message
			}
			add("  " + styleWarn.Render(txt) + styleDim.Render("  since "+age(c.LastTransitionTime.Time)+" ago"))
		}
	}

	// ---- the volume ----
	driver := ""
	if pv != nil {
		st := string(pv.Status.Phase)
		switch pv.Status.Phase {
		case corev1.VolumeBound, corev1.VolumeAvailable:
			st = styleOK.Render(st)
		case corev1.VolumeReleased:
			st = styleWarn.Render(st)
		default:
			st = styleCrit.Render(st)
		}
		capa := ""
		if q, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
			capa = q.String()
		}
		src := pv.Spec.PersistentVolumeSource
		kind, where := "other", ""
		switch {
		case src.CSI != nil:
			driver = src.CSI.Driver
			kind, where = "csi "+driver, "handle "+src.CSI.VolumeHandle
			if src.CSI.FSType != "" {
				where += "  fstype " + src.CSI.FSType
			}
		case src.HostPath != nil:
			kind, where = "hostPath", src.HostPath.Path
		case src.Local != nil:
			kind, where = "local", src.Local.Path
		case src.NFS != nil:
			kind, where = "nfs", src.NFS.Server+":"+src.NFS.Path
		case src.ISCSI != nil:
			kind, where = "iscsi", src.ISCSI.TargetPortal+" "+src.ISCSI.IQN
		}
		add("", styleTitle.Render("Volume "+pv.Name)+"  "+kv("status", st)+"  "+kv("capacity", capa)+"  "+kv("reclaim", string(pv.Spec.PersistentVolumeReclaimPolicy))+"  "+kv("backend", kind)+"  "+kv("age", age(pv.CreationTimestamp.Time)))
		if where != "" {
			add("  " + styleDim.Render(where))
		}
		if pv.Status.Phase == corev1.VolumeReleased {
			add("  " + styleWarn.Render("released: the claim was deleted; with reclaim Retain the data stays until the PV is deleted or its claimRef cleared"))
		}
		if pv.Status.Message != "" {
			add("  " + styleCrit.Render(pv.Status.Reason+": "+pv.Status.Message))
		}
		if src.CSI != nil && len(src.CSI.VolumeAttributes) > 0 {
			var attrs []string
			for _, k := range sortedKeys(src.CSI.VolumeAttributes) {
				lk := strings.ToLower(k)
				if strings.Contains(lk, "secret") || strings.Contains(lk, "password") || strings.Contains(lk, "token") || strings.HasPrefix(k, "storage.kubernetes.io/") {
					continue
				}
				attrs = append(attrs, k+"="+trunc(src.CSI.VolumeAttributes[k], 60))
			}
			for _, l := range wrap(strings.Join(attrs, "  "), w-2) {
				add("  " + styleDim.Render(l))
			}
		}
		if na := pv.Spec.NodeAffinity; na != nil && na.Required != nil {
			var terms []string
			for _, t := range na.Required.NodeSelectorTerms {
				for _, e := range t.MatchExpressions {
					terms = append(terms, e.Key+" "+string(e.Operator)+" "+strings.Join(e.Values, ","))
				}
			}
			add("  " + kv("node affinity", strings.Join(terms, "; ")))
		}
		if pv.Spec.ClaimRef != nil && pvc == nil {
			add("  " + kv("claim", pv.Spec.ClaimRef.Namespace+"/"+pv.Spec.ClaimRef.Name) + styleDim.Render("  (not in the snapshot: deleted, or outside the namespace filter)"))
		}
	} else if pvc != nil && pvName != "" {
		add("", styleCrit.Render("Volume "+pvName+" is not in the snapshot: the PV was deleted under the claim"))
	}

	// ---- usage ----
	if key != "" {
		if u, ok := checks.MergePVCUsage(s, a.nodes)[key]; ok {
			thr := a.cfg.Thresholds
			line := styleTitle.Render("Usage") + "  " + gauge(u.UsedPct(), 20, thr.DiskWarnPct, thr.DiskCritPct) + "  " + kv("used", humanBytes(float64(u.Used))) + "  " + kv("capacity", humanBytes(float64(u.Capacity))) + "  " + kv("available", humanBytes(float64(u.Available)))
			if u.Inodes > 0 {
				line += "  " + kv("inodes", fmt.Sprintf("%d%% (%d/%d)", u.InodesUsed*100/u.Inodes, u.InodesUsed, u.Inodes))
			}
			if u.Node != "" {
				line += "  " + kv("measured on", u.Node)
			}
			add("", line)
		} else {
			add("", styleTitle.Render("Usage")+"  "+styleDim.Render("no measurement: not mounted by a running pod, the driver reports no stats, or the node probe has not run (R)"))
		}
	}

	// ---- pods mounting it ----
	add("", styleTitle.Render("Pods"))
	var podRows [][]string
	for i := range s.Pods {
		p := &s.Pods[i]
		if pvc == nil || p.Namespace != pvc.Namespace {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim == nil || v.PersistentVolumeClaim.ClaimName != pvc.Name {
				continue
			}
			var mounts []string
			for _, c := range p.Spec.Containers {
				for _, m := range c.VolumeMounts {
					if m.Name == v.Name {
						t := c.Name + ":" + m.MountPath
						if m.ReadOnly {
							t += " (ro)"
						}
						mounts = append(mounts, t)
					}
				}
			}
			st := k8s.PodStatus(p)
			switch {
			case st == "Running":
				st = styleOK.Render(st)
			case strings.Contains(st, "Terminating") || strings.Contains(st, "Pending") || strings.Contains(st, "ContainerCreating"):
				st = styleWarn.Render(st)
			default:
				st = styleCrit.Render(st)
			}
			podRows = append(podRows, []string{p.Name, st, orStr(p.Spec.NodeName, styleDim.Render("unscheduled")), strings.Join(mounts, ", "), age(p.CreationTimestamp.Time)})
		}
	}
	if len(podRows) == 0 {
		add(styleDim.Render("  no pod references this claim"))
	} else {
		table([]column{{title: "POD", max: 44}, {title: "STATUS"}, {title: "NODE", max: 24}, {title: "MOUNTS", max: 60}, {title: "AGE"}}, podRows)
	}

	// ---- attachments ----
	ready := map[string]bool{}
	for i := range s.Nodes {
		ready[s.Nodes[i].Name] = k8s.NodeReady(&s.Nodes[i])
	}
	var vaRows [][]string
	for i := range s.VolumeAttachments {
		va := &s.VolumeAttachments[i]
		if va.Spec.Source.PersistentVolumeName == nil || *va.Spec.Source.PersistentVolumeName != pvName || pvName == "" {
			continue
		}
		st := okText(va.Status.Attached, "attached", "not attached")
		node := va.Spec.NodeName
		if r, known := ready[node]; !known {
			node = styleCrit.Render(node + " (gone)")
		} else if !r {
			node = styleCrit.Render(node + " NotReady")
		}
		errTxt := ""
		if e := va.Status.AttachError; e != nil {
			errTxt = styleCrit.Render("attach: " + trunc(e.Message, 70))
		}
		if e := va.Status.DetachError; e != nil {
			errTxt = styleCrit.Render("detach: " + trunc(e.Message, 70))
		}
		if va.DeletionTimestamp != nil {
			st += styleDim.Render(" detaching")
		}
		vaRows = append(vaRows, []string{node, st, age(va.CreationTimestamp.Time), errTxt})
	}
	if len(vaRows) > 0 {
		add("", styleTitle.Render("VolumeAttachments")+styleDim.Render("  (what the attach/detach controller holds)"))
		table([]column{{title: "NODE", max: 30}, {title: "STATE"}, {title: "AGE"}, {title: "ERROR"}}, vaRows)
	}

	// ---- backend ----
	switch {
	case driver == "driver.longhorn.io" && s.Longhorn != nil:
		out = append(out, a.longhornVolumeDetail(pvName, ready)...)
	case driver == "csi.trident.netapp.io":
		out = append(out, a.tridentVolumeDetail(pv, pvc)...)
	case (driver == "rbd.csi.ceph.com" || driver == "cephfs.csi.ceph.com") && s.Ceph != nil:
		out = append(out, cephVolumeDetail(pv, s.Ceph)...)
	}

	// ---- CSI snapshots of this claim ----
	if pvc != nil {
		if snaps := s.Snapshots.ForPVC(pvc.Namespace, pvc.Name); len(snaps) > 0 {
			add("", styleTitle.Render("VolumeSnapshots"))
			var rows [][]string
			for i, vs := range snaps {
				if i == 8 {
					add(styleDim.Render(fmt.Sprintf("  ... %d more", len(snaps)-8)))
					break
				}
				st := styleOK.Render("ready")
				switch {
				case vs.Deleting:
					st = styleDim.Render("deleting")
				case vs.Error != "":
					st = styleCrit.Render("ERROR")
				case !vs.Ready:
					st = styleWarn.Render("pending")
				}
				detail := ""
				if vs.Error != "" {
					detail = trunc(firstLine(vs.Error), 80)
				} else if vs.Content != "" {
					detail = vs.Content
				}
				rows = append(rows, []string{vs.Name, st, vs.Class, vs.RestoreSize, age(vs.Created), detail})
			}
			table([]column{{title: "SNAPSHOT", max: 36}, {title: "STATUS"}, {title: "CLASS"}, {title: "SIZE"}, {title: "AGE"}, {title: "CONTENT / ERROR"}}, rows)
		}
	}

	// ---- events ----
	var evRows [][]string
	cutoff := time.Now().Add(-2 * time.Hour)
	for i := range s.Events {
		e := &s.Events[i]
		hit := (pvc != nil && e.InvolvedObject.Kind == "PersistentVolumeClaim" && e.InvolvedObject.Namespace == pvc.Namespace && e.InvolvedObject.Name == pvc.Name) ||
			(pvName != "" && (e.InvolvedObject.Name == pvName || strings.Contains(e.Message, pvName)))
		if !hit || k8s.EventTime(e).Before(cutoff) {
			continue
		}
		t := e.Type
		if t == corev1.EventTypeWarning {
			t = styleWarn.Render(t)
		}
		evRows = append(evRows, []string{age(k8s.EventTime(e)), t, e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name, e.Reason, fmt.Sprint(k8s.EventCount(e)), trunc(firstLine(e.Message), 110)})
		if len(evRows) == 12 {
			break
		}
	}
	if len(evRows) > 0 {
		add("", styleTitle.Render("Events")+styleDim.Render("  (last 2 h, newest first)"))
		table([]column{{title: "LAST", right: true}, {title: "TYPE"}, {title: "OBJECT", max: 40}, {title: "REASON", max: 24}, {title: "N", right: true}, {title: "MESSAGE"}}, evRows)
	}

	// ---- findings ----
	var fl []string
	for _, f := range a.findings {
		if f.Area != "storage" && f.Area != "workload" {
			continue
		}
		if (key != "" && f.Object == key) || (pvName != "" && (f.Object == pvName || strings.Contains(f.Message, pvName))) {
			fl = append(fl, sevText(f.Severity)+" "+f.Message)
			if f.Hint != "" {
				fl = append(fl, styleDim.Render("    hint: ")+f.Hint)
			}
		}
	}
	if len(fl) > 0 {
		add("", styleTitle.Render("Findings"))
		for _, l := range fl {
			add(wrap(l, w)...)
		}
	}
	return out
}

func (a *App) provisionerFor(sc string) string {
	for i := range a.snap.StorageClasses {
		if a.snap.StorageClasses[i].Name == sc {
			return a.snap.StorageClasses[i].Provisioner
		}
	}
	return ""
}

// longhornVolumeDetail is the Longhorn view of the volume: engine placement,
// robustness, every replica with its node/disk/state/rebuild, snapshot and
// backup state, and the settings that shape it.
func (a *App) longhornVolumeDetail(name string, ready map[string]bool) []string {
	li := a.snap.Longhorn
	var v *k8s.LonghornVolume
	for i := range li.Volumes {
		if li.Volumes[i].Name == name {
			v = &li.Volumes[i]
		}
	}
	var out []string
	if v == nil {
		return []string{"", styleTitle.Render("Longhorn") + "  " + styleCrit.Render("no volumes.longhorn.io object for "+name+": the PV outlived its volume")}
	}
	rob := v.Robustness
	switch v.Robustness {
	case "healthy":
		rob = styleOK.Render(rob)
	case "degraded":
		rob = styleWarn.Render(rob)
	default:
		rob = styleCrit.Render(strings.ToUpper(rob))
	}
	state := v.State
	if v.Node != "" {
		state += "@" + v.Node
		if r, known := ready[v.Node]; known && !r {
			state = styleCrit.Render(state + " (node NotReady)")
		}
	}
	line := styleTitle.Render("Longhorn") + "  " + kv("state", state) + "  " + kv("robustness", rob) + "  " + kv("replicas", fmt.Sprintf("%d/%d healthy", v.Healthy(), v.Replicas)) + "  " + kv("size", humanBytes(float64(v.Size))) + "  " + kv("actual", humanBytes(float64(v.ActualSize)))
	if v.EngineState != "" {
		line += "  " + kv("engine", v.EngineState)
	}
	out = append(out, "", line)
	facts := []string{kv("access", v.AccessMode), kv("frontend", orStr(v.Frontend, "-")), kv("data locality", orStr(v.DataLocality, "disabled")), kv("engine image", imageTagUI(v.CurrentImage))}
	if v.Image != v.CurrentImage && v.Image != "" {
		facts = append(facts, styleInfo.Render("upgrade pending to "+imageTagUI(v.Image)))
	}
	if v.Encrypted {
		facts = append(facts, "encrypted")
	}
	if v.Standby {
		facts = append(facts, styleWarn.Render("DR standby volume"))
	}
	if v.AccessMode == "rwx" {
		facts = append(facts, kv("share", okText(v.ShareState == "running", v.ShareState, strings.ToUpper(orStr(v.ShareState, "not running")))+" "+styleDim.Render(v.ShareEndpoint)))
	}
	out = append(out, "  "+strings.Join(facts, "  "))
	if !v.Scheduled {
		out = append(out, "  "+styleCrit.Render("replica scheduling failed: "+orStr(v.SchedMessage, "see the volume conditions")))
	}
	if !v.LastDegraded.IsZero() && v.Robustness == "degraded" {
		out = append(out, "  "+styleWarn.Render("degraded since "+age(v.LastDegraded)+" ago"))
	}
	var rows [][]string
	for _, r := range v.ReplicaList {
		st := r.State
		switch {
		case r.FailedAt != "" || r.Mode == "ERR" || r.State == "error" || r.State == "unknown":
			st = styleCrit.Render(strings.ToUpper(orStr(r.State, "failed")))
		case r.Rebuild >= 0:
			st = styleInfo.Render(fmt.Sprintf("rebuilding %d%%", r.Rebuild))
		case r.Mode == "WO":
			st = styleInfo.Render("rebuilding")
		case r.Mode == "RW":
			st = styleOK.Render("running RW")
		case r.State == "running":
			st = styleWarn.Render("running (joining)")
		}
		node := orStr(r.Node, styleCrit.Render("unscheduled"))
		if rd, known := ready[r.Node]; known && !rd {
			node = styleCrit.Render(r.Node + " NotReady")
		}
		failed := ""
		if r.FailedAt != "" {
			if t, err := time.Parse(time.RFC3339, r.FailedAt); err == nil {
				failed = age(t) + " ago"
			} else {
				failed = r.FailedAt
			}
		}
		rows = append(rows, []string{r.Name, node, r.DiskPath, st, failed, okText(r.Active, "yes", "no")})
	}
	h, lines := renderTable(a.width-6, []column{{title: "REPLICA", max: 50}, {title: "NODE", max: 26}, {title: "DISK", max: 30}, {title: "STATE"}, {title: "FAILED"}, {title: "ACTIVE"}}, rows)
	out = append(out, h)
	out = append(out, lines...)
	// snapshots and backups
	snapMax := v.SnapshotMax
	if snapMax == 0 {
		snapMax = li.SettingInt("snapshot-max-count", 250)
	}
	snaps := fmt.Sprintf("%d of %d", v.Snapshots, snapMax)
	if v.Snapshots > snapMax || v.TooManySnaps {
		snaps = styleWarn.Render(snaps + " TOO MANY")
	}
	line = "  " + kv("snapshots", snaps)
	if v.LastBackup != "" {
		line += "  " + kv("last backup", v.LastBackup+" "+styleDim.Render(age(v.LastBackupAt)+" ago"))
	} else {
		line += "  " + kv("last backup", styleDim.Render("never"))
	}
	var bk []string
	for _, b := range li.Backups {
		if b.Volume != name {
			continue
		}
		t := b.Name + " " + b.State + " " + age(b.Created) + " ago"
		if b.State == "Error" || b.Error != "" {
			t = styleCrit.Render(b.Name+" ERROR "+age(b.Created)+" ago") + " " + styleDim.Render(trunc(lastCauseUI(b.Error), 80))
		} else if b.Size > 0 {
			t += " " + humanBytes(float64(b.Size))
		}
		bk = append(bk, t)
		if len(bk) == 5 {
			break
		}
	}
	out = append(out, line)
	for _, b := range bk {
		out = append(out, "    "+b)
	}
	if len(v.Workloads) > 0 {
		out = append(out, "  "+kv("workloads (Longhorn)", strings.Join(v.Workloads, ", ")))
	}
	return out
}

// tridentVolumeDetail is the Trident view: the backend the volume lives on
// (from the PV's backendUUID), its state and pool policies, and the nodes
// the volume is published to.
func (a *App) tridentVolumeDetail(pv *corev1.PersistentVolume, pvc *corev1.PersistentVolumeClaim) []string {
	s := a.snap
	var out []string
	attrs := map[string]string{}
	if pv != nil && pv.Spec.CSI != nil {
		attrs = pv.Spec.CSI.VolumeAttributes
	}
	line := styleTitle.Render("Trident")
	if n := attrs["internalName"]; n != "" {
		line += "  " + kv("ontap volume", n)
	}
	if p := attrs["protocol"]; p != "" {
		line += "  " + kv("protocol", p)
	}
	var backend *k8s.TridentBackend
	for i := range s.TridentBackends {
		b := &s.TridentBackends[i]
		if (attrs["backendUUID"] != "" && b.UUID == attrs["backendUUID"]) || (attrs["backend"] != "" && b.BackendName == attrs["backend"]) {
			backend = b
		}
	}
	if backend != nil {
		st := okText(backend.Online && (backend.State == "" || backend.State == "online"), "online", strings.ToUpper(orStr(backend.State, "offline")))
		line += "  " + kv("backend", backend.BackendName+" ("+backend.Driver+") "+st)
		if backend.StateReason != "" && !backend.Online {
			line += " " + styleDim.Render(trunc(backend.StateReason, 60))
		}
	} else if attrs["backendUUID"] != "" {
		line += "  " + styleCrit.Render("backend "+attrs["backendUUID"]+" no longer exists")
	}
	out = append(out, "", line)
	if backend != nil && pvc != nil && pvc.Spec.StorageClassName != nil {
		for _, r := range s.Trident.ResolveStorageClasses(s.StorageClasses, s.TridentBackends) {
			if r.Name != *pvc.Spec.StorageClassName {
				continue
			}
			var pol []string
			for _, k := range []string{"snapshotPolicy", "exportPolicy", "qosPolicy", "adaptiveQosPolicy", "tieringPolicy", "spaceReserve", "snapshotReserve", "encryption"} {
				if v, ok := r.Policies()[k]; ok {
					pol = append(pol, k+"="+v)
				}
			}
			if len(pol) > 0 {
				out = append(out, "  "+kv("policies from the class's pools", strings.Join(pol, "  ")))
			}
		}
	}
	if s.Trident != nil && pv != nil {
		var pubs []string
		for _, p := range s.Trident.Publications {
			if p.Volume == pv.Name || (pv.Spec.CSI != nil && p.Volume == pv.Spec.CSI.VolumeHandle) {
				t := p.Node
				if p.ReadOnly {
					t += " (ro)"
				}
				pubs = append(pubs, t)
			}
		}
		if len(pubs) > 0 {
			txt := strings.Join(pubs, ", ")
			if len(pubs) > 1 && pv.Spec.AccessModes != nil && len(pv.Spec.AccessModes) == 1 && pv.Spec.AccessModes[0] == corev1.ReadWriteOnce {
				txt = styleCrit.Render(txt + "  RWO PUBLISHED TWICE")
			}
			out = append(out, "  "+kv("published to", txt))
		}
	}
	return out
}

// cephVolumeDetail names the pool / image / subvolume behind a Ceph PV and
// the cluster health it depends on.
func cephVolumeDetail(pv *corev1.PersistentVolume, ci *k8s.CephInfo) []string {
	if pv == nil || pv.Spec.CSI == nil {
		return nil
	}
	attrs := pv.Spec.CSI.VolumeAttributes
	line := styleTitle.Render("Ceph")
	for _, k := range []string{"clusterID", "pool", "imageName", "fsName", "subvolumeName", "imageFeatures"} {
		if v := attrs[k]; v != "" {
			line += "  " + kv(k, v)
		}
	}
	for _, cc := range ci.Clusters {
		h := cc.Health
		switch cc.Health {
		case "HEALTH_OK":
			h = styleOK.Render(h)
		case "HEALTH_WARN":
			h = styleWarn.Render(h)
		default:
			h = styleCrit.Render(orStr(h, "unknown"))
		}
		line += "  " + kv("cluster "+cc.Name, h)
	}
	out := []string{"", line}
	for _, p := range ci.Pools {
		if p.Name == attrs["pool"] && !strings.EqualFold(p.Phase, "Ready") {
			out = append(out, "  "+styleCrit.Render("pool "+p.Name+" is "+orStr(p.Phase, "not ready")))
		}
	}
	return out
}

func imageTagUI(img string) string {
	if i := strings.LastIndex(img, ":"); i >= 0 && !strings.Contains(img[i:], "/") {
		return img[i+1:]
	}
	return img
}

// lastCauseUI mirrors checks.lastCause: the last "desc = " segment of a
// gRPC-wrapped Longhorn error.
func lastCauseUI(msg string) string {
	msg = firstLine(msg)
	if i := strings.LastIndex(msg, "desc = "); i >= 0 {
		msg = msg[i+len("desc = "):]
	}
	return strings.TrimSpace(msg)
}
