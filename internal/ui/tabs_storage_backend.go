package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/strutil"
)

// CSI backend detail for the Addons tab: what Longhorn's and Trident's own
// control planes report, under the driver's controller / node plugin
// lines of cloudLines.

// longhornLines renders the Longhorn backend: the volume tally, every node
// with its disks, the backup target and the volumes that are not healthy.
func (a *App) longhornLines(s *k8s.Snapshot, li *k8s.LonghornInfo) []string {
	var out []string
	healthy, degraded, faulted, unknown := li.Counts()
	tally := fmt.Sprintf("%d volumes: %s", len(li.Volumes), styleOK.Render(fmt.Sprintf("%d healthy", healthy)))
	if degraded > 0 {
		tally += ", " + styleWarn.Render(fmt.Sprintf("%d degraded", degraded))
	}
	if faulted > 0 {
		tally += ", " + styleCrit.Render(fmt.Sprintf("%d faulted", faulted))
	}
	if unknown > 0 {
		tally += ", " + styleCrit.Render(fmt.Sprintf("%d unknown", unknown))
	}
	readyNodes := 0
	for _, n := range li.Nodes {
		if n.Ready {
			readyNodes++
		}
	}
	nodes := fmt.Sprintf("%d/%d", readyNodes, len(li.Nodes))
	if readyNodes < len(li.Nodes) {
		nodes = styleCrit.Render(nodes)
	} else {
		nodes = styleOK.Render(nodes)
	}
	line := "      " + styleBold.Render("longhorn") + "  " + tally + "  " + kv("nodes ready", nodes)
	for _, bt := range li.BackupTargets {
		switch {
		case bt.URL == "":
			line += "  " + kv("backup target", styleDim.Render("none"))
		case bt.Available:
			line += "  " + kv("backup target", styleOK.Render(bt.URL))
		default:
			line += "  " + kv("backup target", styleCrit.Render(bt.URL+" unavailable"))
		}
	}
	if len(li.Backups) > 0 || len(li.RecurringJobs) > 0 {
		b := fmt.Sprintf("%d backups", len(li.Backups))
		if f := li.FailedBackups(); len(f) > 0 {
			b = styleWarn.Render(fmt.Sprintf("%d backups, %d failed", len(li.Backups), len(f)))
		}
		line += "  " + b + styleDim.Render(fmt.Sprintf(", %d recurring jobs", len(li.RecurringJobs)))
	}
	if len(li.Orphans) > 0 {
		line += "  " + styleWarn.Render(fmt.Sprintf("%d orphans", len(li.Orphans)))
	}
	if rc := li.Setting("default-replica-count"); rc != "" {
		line += "  " + kv("default replicas", rc)
	}
	out = append(out, line)
	for _, n := range li.Nodes {
		st := styleOK.Render("ready")
		if !n.Ready {
			st = styleCrit.Render("NOT READY")
		} else if !n.Schedulable || !n.AllowScheduling {
			st = styleWarn.Render("unschedulable")
		}
		parts := []string{st}
		if n.InstanceManager != "" && n.InstanceManager != "running" {
			parts = append(parts, styleCrit.Render("instance manager "+n.InstanceManager))
		}
		for _, d := range n.Disks {
			txt := fmt.Sprintf("%s %s free of %s (%d replicas)", d.Path, humanBytes(float64(d.Available)), humanBytes(float64(d.Maximum)), d.Replicas)
			switch {
			case !d.Ready:
				txt = styleCrit.Render(d.Path + " NOT READY")
			case !d.Schedulable:
				txt = styleWarn.Render(txt + " unschedulable")
			}
			parts = append(parts, txt)
		}
		out = append(out, "        "+styleBold.Render(n.Name)+"  "+strings.Join(parts, "  "))
	}
	// volumes that need attention, worst first
	var bad []k8s.LonghornVolume
	for _, v := range li.Volumes {
		if v.Robustness != "healthy" && !(v.State == "detached" && v.Robustness == "unknown" && v.Scheduled) || !v.Scheduled || (v.AccessMode == "rwx" && v.State == "attached" && v.ShareState != "" && v.ShareState != "running") {
			bad = append(bad, v)
		}
	}
	rank := map[string]int{"faulted": 0, "unknown": 1, "degraded": 2}
	sort.SliceStable(bad, func(i, j int) bool {
		ri, ok := rank[bad[i].Robustness]
		if !ok {
			ri = 3
		}
		rj, ok := rank[bad[j].Robustness]
		if !ok {
			rj = 3
		}
		return ri < rj
	})
	for i, v := range bad {
		if i == 8 {
			out = append(out, styleDim.Render(fmt.Sprintf("        ... %d more volumes need attention (Overview findings list them all)", len(bad)-8)))
			break
		}
		out = append(out, "        "+longhornVolumeLine(v))
	}
	return out
}

// longhornVolumeLine is one volume: name (PVC), state@node, robustness with
// the replica tally and the failed / rebuilding nodes.
func longhornVolumeLine(v k8s.LonghornVolume) string {
	name := v.Name
	if v.PVC != "" {
		name = v.PVC + styleDim.Render(" ("+trunc(v.Name, 20)+")")
	}
	state := v.State
	if v.Node != "" {
		state += "@" + v.Node
	}
	rob := v.Robustness
	switch v.Robustness {
	case "healthy":
		rob = styleOK.Render(rob)
	case "degraded":
		rob = styleWarn.Render(rob)
	case "faulted", "unknown":
		rob = styleCrit.Render(strings.ToUpper(rob))
	}
	var failed, rebuilding []string
	for _, r := range v.ReplicaList {
		switch {
		case r.Rebuild >= 0:
			rebuilding = append(rebuilding, fmt.Sprintf("%s %d%%", r.Node, r.Rebuild))
		case r.Mode == "WO":
			rebuilding = append(rebuilding, r.Node)
		case r.FailedAt != "" || r.Mode == "ERR" || r.State == "error" || r.State == "unknown":
			failed = append(failed, strutil.FirstNonEmpty(r.Node, "unscheduled"))
		case r.Node == "":
			failed = append(failed, "unscheduled")
		}
	}
	txt := fmt.Sprintf("%s  %s  %s %d/%d", name, state, rob, v.Healthy(), v.Replicas)
	if len(failed) > 0 {
		txt += styleDim.Render(" failed: " + strings.Join(strutil.Uniq(failed), ","))
	}
	if len(rebuilding) > 0 {
		txt += "  " + styleInfo.Render("rebuilding "+strings.Join(rebuilding, ","))
	}
	if !v.Scheduled {
		txt += "  " + styleCrit.Render("unscheduled: "+trunc(v.SchedMessage, 60))
	}
	if v.AccessMode == "rwx" && v.ShareState != "" {
		txt += "  " + kv("share", okText(v.ShareState == "running", v.ShareState, strings.ToUpper(v.ShareState)))
	}
	return txt
}

// tridentLines renders the Trident control plane beyond the backends:
// operator state, backend configs, node registrations, publications.
func (a *App) tridentLines(s *k8s.Snapshot, ti *k8s.TridentInfo, backends []k8s.TridentBackend) []string {
	var out []string
	if ti == nil {
		return nil
	}
	if o := ti.Orchestrator; o != nil {
		st := o.Status
		if strings.EqualFold(st, "installed") {
			st = styleOK.Render(st)
		} else {
			st = styleCrit.Render(strings.ToUpper(strutil.FirstNonEmpty(st, "unknown")))
		}
		line := "      " + kv("operator", st) + "  " + kv("version", o.Version)
		if o.Message != "" && !strings.EqualFold(o.Status, "installed") {
			line += "  " + styleDim.Render(trunc(o.Message, 80))
		}
		line += "  " + kv("force-detach", okText(o.ForceDetach, "on", "off"))
		out = append(out, line)
	}
	for _, bc := range ti.BackendConfigs {
		st := bc.Phase
		switch {
		case strings.EqualFold(bc.Phase, "bound"):
			st = styleOK.Render(st)
		case bc.Phase == "" && strings.EqualFold(bc.LastOperation, "failed"):
			st = styleCrit.Render("CREATION FAILED")
		default:
			st = styleCrit.Render(strings.ToUpper(strutil.FirstNonEmpty(st, "unprocessed")))
		}
		line := fmt.Sprintf("      backendconfig %s  %s  %s", styleBold.Render(bc.Namespace+"/"+bc.Name), bc.Driver, st)
		if strings.EqualFold(bc.LastOperation, "failed") {
			line += "  " + styleWarn.Render("last update failed")
		}
		if bc.Message != "" && !strings.EqualFold(bc.Phase, "bound") {
			line += "  " + styleDim.Render(trunc(bc.Message, 70))
		}
		out = append(out, line)
	}
	// storage classes -> backends / pools and the policies volumes inherit
	for _, r := range ti.ResolveStorageClasses(s.StorageClasses, backends) {
		sel := strutil.FirstNonEmpty(r.BackendType, "any backend")
		if r.Selector != "" {
			sel += "  selector " + r.Selector
		}
		if r.PoolsParam != "" {
			sel += "  pools " + trunc(r.PoolsParam, 40)
		}
		line := fmt.Sprintf("      sc %s  %s  ", styleBold.Render(r.Name), styleDim.Render(sel))
		switch {
		case !r.Registered:
			line += styleCrit.Render("NOT REGISTERED with Trident")
		case len(r.Matches) == 0:
			line += styleCrit.Render("matches no backend")
		default:
			var ms []string
			for _, m := range r.Matches {
				txt := fmt.Sprintf("%s (%d pools)", m.Backend.BackendName, len(m.Pools))
				if !m.Backend.Online || (m.Backend.State != "" && m.Backend.State != "online") {
					txt = styleCrit.Render(txt + " " + strings.ToUpper(strutil.FirstNonEmpty(m.Backend.State, "offline")))
				}
				ms = append(ms, txt)
			}
			line += "-> " + strings.Join(ms, ", ")
			var pol []string
			p := r.Policies()
			for _, k := range []string{"snapshotPolicy", "exportPolicy", "qosPolicy", "adaptiveQosPolicy", "tieringPolicy", "spaceReserve", "snapshotReserve", "encryption"} {
				if v, ok := p[k]; ok {
					pol = append(pol, strings.TrimSuffix(k, "Policy")+"="+v)
				}
			}
			if len(pol) > 0 {
				line += "  " + styleDim.Render(strings.Join(pol, " "))
			}
		}
		if len(r.Problems) > 0 {
			line += "  " + styleWarn.Render(trunc(strings.Join(r.Problems, "; "), 60))
		}
		out = append(out, line)
	}
	if len(ti.Nodes) > 0 {
		registered, dirty := 0, 0
		for _, n := range ti.Nodes {
			if n.Registered && !n.Deleted {
				registered++
			}
			if strings.EqualFold(n.PublicationState, "dirty") {
				dirty++
			}
		}
		nodes := fmt.Sprintf("%d/%d", registered, len(s.Nodes))
		if registered < len(s.Nodes) {
			nodes = styleWarn.Render(nodes)
		} else {
			nodes = styleOK.Render(nodes)
		}
		line := "      " + kv("nodes registered", nodes) + "  " + kv("publications", fmt.Sprint(len(ti.Publications)))
		svc := map[string]int{}
		for _, n := range ti.Nodes {
			for _, sv := range n.Services {
				svc[sv]++
			}
		}
		if len(svc) > 0 {
			var parts []string
			for _, k := range strutil.SortedKeys(svc) {
				parts = append(parts, fmt.Sprintf("%s %d/%d", k, svc[k], len(ti.Nodes)))
			}
			line += "  " + kv("host services", strings.Join(parts, ", "))
		}
		if dirty > 0 {
			line += "  " + styleWarn.Render(fmt.Sprintf("%d nodes dirty", dirty))
		}
		for vol, nodes := range ti.MultiPublished() {
			line += "  " + styleCrit.Render(vol+" published to "+strings.Join(nodes, "+"))
		}
		out = append(out, line)
	}
	return out
}

// protectLines renders Trident Protect: vaults, applications, the latest
// runs and the schedules.
func protectLines(tp *k8s.TridentProtect) []string {
	if tp == nil {
		return nil
	}
	var out []string
	out = append(out, "      "+styleBold.Render("trident protect")+"  "+kv("vaults", fmt.Sprint(len(tp.Vaults)))+"  "+kv("applications", fmt.Sprint(len(tp.Applications)))+"  "+kv("snapshots", fmt.Sprint(len(tp.Snapshots)))+"  "+kv("backups", fmt.Sprint(len(tp.Backups)))+"  "+kv("schedules", fmt.Sprint(len(tp.Schedules))))
	for _, v := range tp.Vaults {
		st := okText(strings.EqualFold(v.State, "Available"), v.State, strings.ToUpper(strutil.FirstNonEmpty(v.State, "not ready")))
		line := fmt.Sprintf("        vault %s  %s %s/%s  %s", styleBold.Render(v.Name), v.Provider, v.Endpoint, v.Bucket, st)
		if v.Error != "" && !strings.EqualFold(v.State, "Available") {
			line += "  " + styleDim.Render(trunc(strutil.FirstLine(v.Error), 70))
		}
		out = append(out, line)
	}
	for _, a := range tp.Applications {
		st := okText(strings.EqualFold(a.ProtectionHealth, "Healthy") || strings.EqualFold(a.ProtectionState, "Full"), a.ProtectionState, strutil.FirstNonEmpty(a.ProtectionState, "unknown")+" / "+strutil.FirstNonEmpty(a.ProtectionHealth, "?"))
		line := fmt.Sprintf("        app %s  %s  %s", styleBold.Render(a.Namespace+"/"+a.Name), kv("namespaces", strings.Join(a.Namespaces, ",")), st)
		if len(a.Details) > 0 {
			line += "  " + styleDim.Render(strings.Join(a.Details, "; "))
		}
		for _, kind := range []string{"Snapshot", "Backup"} {
			if r := tp.LatestRun(kind, a.Namespace, a.Name); r != nil {
				t := strings.ToLower(kind) + " " + r.State + " " + age(r.Created) + " ago"
				if r.Failed() {
					t = styleCrit.Render(strings.ToLower(kind) + " " + strings.ToUpper(r.State) + " " + age(r.Created) + " ago")
				} else if r.Deleting {
					t = styleWarn.Render(t + " (deleting)")
				}
				line += "  " + t
			}
		}
		out = append(out, line)
	}
	for _, b := range tp.BlockedLocks() {
		line := "        " + styleWarn.Render(fmt.Sprintf("%d runs blocked on %s", len(b.Waiting), b.Lock))
		switch {
		case b.Holder != nil:
			what := b.Holder.State
			if b.Holder.Deleting {
				what += ", deleting"
			}
			line += "  " + kv("held by", strings.ToLower(b.Holder.Kind)+" "+styleBold.Render(b.Holder.Name)+" ("+what+")")
		case b.Stale && b.Lease != nil:
			exp := "expired"
			if t := b.Lease.Expires(); t.After(time.Now()) {
				exp = "expires in " + strutil.HumanDur(time.Until(t))
			}
			line += "  " + styleCrit.Render("STALE lease: holder "+b.Lease.Holder+" is gone, "+exp) + styleDim.Render("  kubectl -n "+b.Namespace+" delete lease "+b.Lock)
		default:
			line += "  " + styleDim.Render("holder not found")
		}
		out = append(out, line)
	}
	for _, s := range tp.Schedules {
		st := okText(s.Enabled, s.Granularity, "disabled")
		out = append(out, fmt.Sprintf("        schedule %s  %s  %s -> %s", styleBold.Render(s.Namespace+"/"+s.Name), st, s.App, s.Vault))
	}
	return out
}

// cephLines renders the Rook-Ceph cluster(s): health with the check names,
// operator phase, capacity, and the pools that are not Ready.
func cephLines(ci *k8s.CephInfo) []string {
	var out []string
	for _, cc := range ci.Clusters {
		health := cc.Health
		switch cc.Health {
		case "HEALTH_OK":
			health = styleOK.Render(health)
		case "HEALTH_WARN":
			health = styleWarn.Render(health)
		case "":
			health = styleDim.Render("no health yet")
		default:
			health = styleCrit.Render(health)
		}
		line := "      " + styleBold.Render("ceph "+cc.Namespace+"/"+cc.Name) + "  " + health + "  " + kv("phase", okText(strings.EqualFold(cc.Phase, "Ready"), cc.Phase, cc.Phase)) + "  " + kv("version", cc.Version)
		if cc.Capacity.Total > 0 {
			line += "  " + kv("raw", fmt.Sprintf("%s of %s used", humanBytes(float64(cc.Capacity.Used)), humanBytes(float64(cc.Capacity.Total))))
		}
		if cc.External {
			line += "  " + styleDim.Render("external")
		}
		out = append(out, line)
		for i, det := range cc.Details {
			if i == 4 {
				out = append(out, styleDim.Render(fmt.Sprintf("        ... %d more checks", len(cc.Details)-4)))
				break
			}
			out = append(out, "        "+okText(det.Severity != "HEALTH_ERR", det.Name, det.Name)+"  "+styleDim.Render(trunc(det.Message, 90)))
		}
	}
	ready := 0
	all := len(ci.Pools) + len(ci.Filesys) + len(ci.Stores)
	for _, r := range ci.Unhealthy() {
		out = append(out, fmt.Sprintf("        %s %s  %s", r.Kind, styleBold.Render(r.Name), styleCrit.Render(strutil.FirstNonEmpty(r.Phase, "no phase"))))
	}
	if all > 0 {
		ready = all - len(ci.Unhealthy())
		out = append(out, "        "+kv("pools/filesystems/stores ready", okText(ready == all, fmt.Sprintf("%d/%d", ready, all), fmt.Sprintf("%d/%d", ready, all))))
	}
	return out
}

// backendHealth is the Storage tab's BACKEND HEALTH cell for a PVC: what
// the driver's control plane says about the volume behind it.
func backendHealth(s *k8s.Snapshot, ns, name string) string {
	if v := s.Longhorn.VolumeForPVC(ns, name); v != nil {
		txt := fmt.Sprintf("%s %d/%d", v.Robustness, v.Healthy(), v.Replicas)
		switch {
		case !v.Scheduled && v.Robustness != "degraded":
			return styleCrit.Render("unscheduled")
		case v.Robustness == "faulted":
			return styleCrit.Render("FAULTED")
		case v.Robustness == "healthy":
			return styleOK.Render(txt)
		case v.Robustness == "degraded":
			return styleWarn.Render(txt)
		case v.State == "detached":
			return styleDim.Render("detached")
		default:
			return styleCrit.Render(strings.ToUpper(txt))
		}
	}
	return ""
}
