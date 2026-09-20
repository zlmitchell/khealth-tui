package ui

import (
	"fmt"
	"math"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/checks"
	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/k8s"
)

// ---------- Overview ----------

func (a *App) overviewContent() content {
	s := a.snap
	thr := a.cfg.Thresholds
	var hdr []string
	cp, ready := 0, 0
	for i := range s.Nodes {
		if k8s.IsControlPlane(&s.Nodes[i]) {
			cp++
		}
		if k8s.NodeReady(&s.Nodes[i]) {
			ready++
		}
	}
	running, pending, failed, unhealthy := 0, 0, 0, 0
	for i := range s.Pods {
		p := &s.Pods[i]
		switch p.Status.Phase {
		case corev1.PodRunning:
			running++
		case corev1.PodPending:
			pending++
		case corev1.PodFailed:
			failed++
		}
		if !k8s.PodHealthy(p) && p.Status.Phase != corev1.PodSucceeded {
			unhealthy++
		}
	}
	hdr = append(hdr, styleTitle.Render("Cluster")+"  "+kv("context", a.client.Context)+"  "+kv("server", a.client.Host)+"  "+kv("version", s.Version)+"  "+kv("distribution", s.Distribution)+"  "+kv("namespaces", fmt.Sprint(len(s.Namespaces)))+"  "+kv("control-plane", fmt.Sprint(cp)))

	// ---- tiles ----
	cpu, mem, disk := a.clusterUsage()
	crit, warn, info := 0, 0, 0
	for _, f := range a.findings {
		switch f.Severity {
		case checks.SevCrit:
			crit++
		case checks.SevWarn:
			warn++
		default:
			info++
		}
	}
	etcdSum := a.etcdSummarize()
	etcdDB, etcdFsync, etcdNode := etcdSum.dbPct, etcdSum.fsync, etcdSum.dbNode
	etcdHealthy, etcdProbed := etcdSum.healthy, etcdSum.probed
	tw, n := tileWidths(a.width, 6)
	gw := tw - 4 - 5 // gauge bar width inside a tile (padding + "100%")
	if gw < 6 {
		gw = 6
	}
	sw := tw - 4
	readyPct := 100.0
	if len(s.Nodes) > 0 {
		readyPct = float64(ready) * 100 / float64(len(s.Nodes))
	}
	podSegs := []seg{{float64(running - unhealthy), styleOK, "ok"}, {float64(unhealthy), styleCrit, "bad"}, {float64(pending), styleWarn, "pend"}, {float64(failed), styleCrit, "fail"}}
	notReady := 100 - readyPct
	tiles := []string{
		tile(tw, "Nodes",
			okText(ready == len(s.Nodes), fmt.Sprintf("%d/%d ready", ready, len(s.Nodes)), fmt.Sprintf("%d/%d ready", ready, len(s.Nodes)))+styleDim.Render(fmt.Sprintf("  %d cp", cp)),
			bar(readyPct/100, gw, pctStyle(notReady, 1, 50))+pctStyle(notReady, 1, 50).Render(fmt.Sprintf("%4.0f%%", readyPct)),
			styleDim.Render("ssh ")+sshSummary(a)),
		tile(tw, "Pods",
			fmt.Sprintf("%d run  %s", running, colorCount(unhealthy, "bad", styleCrit)),
			stacked(gw+5, podSegs),
			styleDim.Render("bad ")+sparkStyled(a.values("pods.unhealthy"), sw-4, 0, 1, 5)),
		tile(tw, "CPU (avg)",
			gauge(cpu, gw, thr.CPUWarnPct, 95),
			sparkStyled(a.values("cluster.cpu"), sw, 100, thr.CPUWarnPct, 95),
			styleDim.Render(usageSource(a))),
		tile(tw, "Memory (avg)",
			gauge(mem, gw, thr.MemWarnPct, thr.MemCritPct),
			sparkStyled(a.values("cluster.mem"), sw, 100, thr.MemWarnPct, thr.MemCritPct),
			styleDim.Render(usageSource(a))),
		tile(tw, "Disk (worst fs)",
			gauge(disk, gw, thr.DiskWarnPct, thr.DiskCritPct),
			sparkStyled(a.values("cluster.disk"), sw, 100, thr.DiskWarnPct, thr.DiskCritPct),
			styleDim.Render(worstDisk(a))),
		tile(tw, "etcd",
			etcdTileLine(etcdProbed, etcdHealthy, etcdFsync, etcdSum.noProbeReason, thr),
			gauge(etcdDB, gw, thr.EtcdDBWarnPct, 95),
			sparkStyled(a.values("etcd.db:"+etcdNode), sw, 100, thr.EtcdDBWarnPct, 95)),
	}
	hdr = append(hdr, tileRow(tiles[:n])...)

	readyFail, liveFail := 0, 0
	for _, c := range s.Readyz {
		if !c.OK {
			readyFail++
		}
	}
	for _, c := range s.Livez {
		if !c.OK {
			liveFail++
		}
	}
	api := kv("readyz", okText(readyFail == 0 && len(s.Readyz) > 0, fmt.Sprintf("ok (%d checks)", len(s.Readyz)), fmt.Sprintf("%d failing", readyFail))) + "  " + kv("livez", okText(liveFail == 0 && len(s.Livez) > 0, "ok", fmt.Sprintf("%d failing", liveFail)))
	api += "  " + kv("metrics-server", okText(s.MetricsAvailable, "yes", "no"))
	if s.Rancher != nil && s.Rancher.Managed {
		api += "  " + kv("rancher", okText(s.Rancher.ClusterAgentOK, "connected "+s.Rancher.Server, "disconnected "+s.Rancher.Server))
	}
	api += "  " + kv("warning events", fmt.Sprint(len(s.WarningEvents()))) + " " + styleInfo.Render(sparkline(a.values("events.warn"), 12, 0))
	hdr = append(hdr, api)

	fsegs := []seg{{float64(crit), styleCrit, "critical"}, {float64(warn), styleWarn, "warning"}, {float64(info), styleInfo, "info"}}
	trend := sparkStyled(a.values("findings.crit"), 12, 0, 1, 1)
	note := "   (a toggles info, enter shows hint; first seen = this khealth session)"
	if len(a.resolved) > 0 {
		note = fmt.Sprintf("   (a toggles info, enter shows hint; %d resolved kept %s)", len(a.resolved), humanDur(resolvedKeep))
	}
	hdr = append(hdr, styleTitle.Render("Findings")+"  "+stacked(30, fsegs)+"  "+legend(fsegs)+"  "+styleDim.Render("crit trend ")+trend+styleDim.Render(note))

	// current findings ranked as evaluated, then the ones that went away
	// since an earlier refresh, dimmed, so a fix (or a flap) is visible
	var rows [][]string
	var ids []string
	for i, f := range a.findings {
		if a.problemOnly && f.Severity == checks.SevInfo {
			continue
		}
		rows = append(rows, []string{sevText(f.Severity), "ongoing", age(a.firstSeen(f)) + " ago", f.Area, f.Object, f.Message})
		ids = append(ids, fmt.Sprint(i))
	}
	for i, r := range a.resolved {
		if a.problemOnly && r.Severity == checks.SevInfo {
			continue
		}
		rows = append(rows, []string{styleDim.Render(fmt.Sprintf("%-4s", r.Severity.String())), styleOK.Render("resolved ") + styleDim.Render(age(r.Resolved)+" ago"), styleDim.Render(age(r.First) + " ago"), styleDim.Render(r.Area), styleDim.Render(r.Object), styleDim.Render(r.Message)})
		ids = append(ids, "r:"+fmt.Sprint(i))
	}
	h, lines := renderTable(a.width, []column{{title: "SEV"}, {title: "STATE"}, {title: "FIRST SEEN"}, {title: "AREA"}, {title: "OBJECT", max: 48}, {title: "MESSAGE"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: styleOK.Render("no findings - cluster looks healthy")}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

func sshSummary(a *App) string {
	if !a.sshEnabled {
		if a.sshErr != "" {
			return styleWarn.Render("error")
		}
		return "off"
	}
	okN, errN := 0, 0
	for _, ni := range a.nodes {
		if ni.Err != nil {
			errN++
		} else {
			okN++
		}
	}
	out := styleOK.Render(fmt.Sprintf("%d ok", okN))
	if errN > 0 {
		out += " " + styleCrit.Render(fmt.Sprintf("%d err", errN))
	}
	if len(a.pending) > 0 {
		out += styleDim.Render(fmt.Sprintf(" %d pending", len(a.pending)))
	}
	return out
}

func usageSource(a *App) string {
	ssh := 0
	for _, ni := range a.nodes {
		if ni.Err == nil {
			ssh++
		}
	}
	switch {
	case ssh > 0 && a.snap.MetricsAvailable:
		return fmt.Sprintf("ssh %d nodes + metrics-server", ssh)
	case ssh > 0:
		return fmt.Sprintf("ssh %d nodes", ssh)
	case a.snap.MetricsAvailable:
		return "metrics-server"
	}
	return "no usage source"
}

func worstDisk(a *App) string {
	worst := -1
	where := ""
	for _, n := range sortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		for _, m := range ni.Mounts {
			if m.UsePct > worst {
				worst = m.UsePct
				where = n + ":" + m.Mountpoint
			}
		}
	}
	if worst < 0 {
		return "needs ssh"
	}
	return where
}

func etcdTileLine(probed, healthy int, fsync float64, noProbe string, thr config.Thresholds) string {
	if probed == 0 {
		return styleDim.Render("no probes: " + noProbe)
	}
	out := okText(healthy == probed, fmt.Sprintf("%d/%d ok", healthy, probed), fmt.Sprintf("%d/%d ok", healthy, probed))
	if !math.IsNaN(fsync) {
		out += styleDim.Render(" fsync ") + pctStyle(fsync, int(thr.EtcdFsyncWarnMs), int(thr.EtcdFsyncWarnMs*3)).Render(fmt.Sprintf("%.0fms", fsync))
	}
	return out
}

func colorCount(n int, label string, st interface{ Render(...string) string }) string {
	t := fmt.Sprintf("%d %s", n, label)
	if n == 0 {
		return t
	}
	return st.Render(t)
}

// ---------- Nodes ----------

func (a *App) nodesContent() content {
	s := a.snap
	thr := a.cfg.Thresholds
	var rows [][]string
	var ids []string
	for i := range s.Nodes {
		n := &s.Nodes[i]
		roles := strings.Join(k8s.NodeRoles(n), ",")
		status := okText(k8s.NodeReady(n), "Ready", "NotReady")
		if n.Spec.Unschedulable {
			status += styleDim.Render(",Sched✗")
		}
		for _, ct := range []corev1.NodeConditionType{corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure} {
			if st, _ := k8s.NodeCondition(n, ct); st == corev1.ConditionTrue {
				status += styleWarn.Render("," + strings.TrimSuffix(string(ct), "Pressure") + "!")
			}
		}
		bw := 6
		if a.width < 120 {
			bw = 4
		}
		cpu, mem, load, root, data, kubelet, uptime, ssh := gauge(nan(), bw, 0, 0), gauge(nan(), bw, 0, 0), "-", gauge(nan(), bw, 0, 0), "-", "-", "-", styleDim.Render("-")
		trend := sparkStyled(a.values("node.cpu:"+n.Name), 10, 100, thr.CPUWarnPct, 95)
		if ni, ok := a.nodes[n.Name]; ok && ni.Err == nil {
			cpu = gauge(ni.CPUPct, bw, thr.CPUWarnPct, 95)
			mem = gauge(ni.MemPct, bw, thr.MemWarnPct, thr.MemCritPct)
			load = fmt.Sprintf("%.1f", ni.Load1)
			if ni.CPUs > 0 && ni.Load1/float64(ni.CPUs) >= thr.LoadPerCPUWarn {
				load = styleWarn.Render(load)
			}
			if m := ni.MountFor("/"); m != nil {
				root = gauge(float64(m.UsePct), bw, thr.DiskWarnPct, thr.DiskCritPct)
			}
			if m := ni.DataMount(); m != nil && m.Mountpoint != "/" {
				data = gauge(float64(m.UsePct), bw, thr.DiskWarnPct, thr.DiskCritPct) + styleDim.Render(" "+m.Mountpoint)
			} else {
				data = styleDim.Render("(root)")
			}
			// the unit that carries the kubelet: kubelet itself, or the
			// rke2/k3s supervisor it runs under
			for _, u := range []string{"kubelet", "rke2-server", "rke2-agent", "k3s", "k3s-agent"} {
				if svc := ni.Service(u); svc != nil {
					label := "active"
					if u != "kubelet" {
						label = u
					}
					kubelet = okText(svc.Active == "active", label, u+":"+svc.Active)
					break
				}
			}
			uptime = humanDur(ni.Uptime)
			ssh = styleOK.Render("ok")
			if ni.Heavy {
				ssh = styleOK.Render("ok+")
			}
		} else if ok && ni.Err != nil {
			ssh = styleCrit.Render("err")
		} else if a.pending[n.Name] {
			ssh = styleDim.Render("…")
		}
		if ni, ok := a.nodes[n.Name]; (!ok || ni.Err != nil) && s.MetricsAvailable {
			if m, ok := s.NodeMetrics[n.Name]; ok {
				if alloc := k8s.QuantityMilli(n.Status.Allocatable, corev1.ResourceCPU); alloc > 0 {
					cpu = gauge(float64(m.CPUMilli)*100/float64(alloc), bw, thr.CPUWarnPct, 95) + styleDim.Render("m")
				}
				if alloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourceMemory); alloc > 0 {
					mem = gauge(float64(m.MemBytes)*100/float64(alloc), bw, thr.MemWarnPct, thr.MemCritPct) + styleDim.Render("m")
				}
			}
		}
		rows = append(rows, []string{n.Name, a.nodeAddress(n), roles, status, age(n.CreationTimestamp.Time), n.Status.NodeInfo.KubeletVersion, cpu, trend, mem, load, root, data, kubelet, uptime, ssh})
		ids = append(ids, n.Name)
	}
	h, lines := renderTable(a.width, []column{{title: "NAME"}, {title: "IP"}, {title: "ROLES", max: 20}, {title: "STATUS"}, {title: "AGE", right: true}, {title: "VERSION"}, {title: "CPU"}, {title: "CPU TREND"}, {title: "MEM"}, {title: "LOAD", right: true}, {title: "ROOT"}, {title: "DATA DISK"}, {title: "KUBELET"}, {title: "UPTIME"}, {title: "SSH"}}, rows)
	cpuAvg, memAvg, _ := a.clusterUsage()
	summary := styleTitle.Render("Nodes") + "  " + kv("cpu avg", gauge(cpuAvg, 12, thr.CPUWarnPct, 95)) + "  " + kv("mem avg", gauge(memAvg, 12, thr.MemWarnPct, thr.MemCritPct)) + "  " + kv("cpu trend", sparkStyled(a.values("cluster.cpu"), 20, 100, thr.CPUWarnPct, 95)) + "  " + kv("mem trend", sparkStyled(a.values("cluster.mem"), 20, 100, thr.MemWarnPct, thr.MemCritPct))
	c := content{header: []string{summary, styleDim.Render("m = metrics-server value, ok+ = full collection done; trend = last refreshes; enter for details"), h}, selectable: true, empty: "no nodes"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// openEvent shows an event in the inspector with its involved object as a reference.
func (a *App) openEvent(id string) {
	var idx int
	if _, err := fmt.Sscan(id, &idx); err != nil || idx < 0 || idx >= len(a.snap.Events) {
		return
	}
	e := &a.snap.Events[idx]
	meta := []string{
		kv("reason", styleWarn.Render(e.Reason)) + "  " + kv("count", fmt.Sprint(k8s.EventCount(e))) + "  " + kv("first", age(e.FirstTimestamp.Time)+" ago") + "  " + kv("last", age(k8s.EventTime(e))+" ago") + "  " + kv("source", e.Source.Component+" "+e.Source.Host),
	}
	meta = append(meta, wrap(e.Message, a.width-6)...)
	refs := []k8s.ObjRef{{APIVersion: e.InvolvedObject.APIVersion, Kind: e.InvolvedObject.Kind, Namespace: e.InvolvedObject.Namespace, Name: e.InvolvedObject.Name, Via: "involved object"}}
	a.openInspectList("Event "+e.Namespace+"/"+e.Name, meta, refs)
}

// ---------- Events ----------

func (a *App) eventsContent() content {
	s := a.snap
	var rows [][]string
	var ids []string
	warnings := 0
	for i := range s.Events {
		e := &s.Events[i]
		if !a.inNamespace(e.Namespace) {
			continue
		}
		if e.Type == "Warning" {
			warnings++
		} else if a.problemOnly {
			continue
		}
		obj := e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name
		typ := styleDim.Render(e.Type)
		reason := e.Reason
		if e.Type == "Warning" {
			typ = styleWarn.Render("Warning")
			reason = styleWarn.Render(e.Reason)
		}
		rows = append(rows, []string{age(k8s.EventTime(e)), typ, e.Namespace, obj, reason, fmt.Sprint(k8s.EventCount(e)), firstLine(e.Message)})
		ids = append(ids, fmt.Sprint(i))
	}
	h, lines := renderTable(a.width, []column{{title: "LAST", right: true}, {title: "TYPE"}, {title: "NAMESPACE", max: 24}, {title: "OBJECT", max: 44}, {title: "REASON", max: 26}, {title: "N", right: true}, {title: "MESSAGE"}}, rows)
	mode := "all types"
	if a.problemOnly {
		mode = "warnings only (a toggles)"
	}
	c := content{header: []string{styleTitle.Render("Events") + "  " + kv("in scope", fmt.Sprint(len(rows))) + "  " + kv("warnings", colorCount(warnings, "", styleWarn)) + "  " + styleDim.Render(mode+"; newest first; enter opens the involved object. The apiserver drops events after event-ttl (1h on rke2), so only recent activity is visible."), h}, selectable: true, empty: styleOK.Render("no events in the retention window")}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// ---------- Storage ----------

func (a *App) storageContent() content {
	s := a.snap
	thr := a.cfg.Thresholds
	var out []string
	add := func(l ...string) { out = append(out, l...) }

	pvcSegs := []seg{{0, styleOK, "bound"}, {0, styleWarn, "pending"}, {0, styleCrit, "lost"}}
	for i := range s.PVCs {
		switch s.PVCs[i].Status.Phase {
		case corev1.ClaimBound:
			pvcSegs[0].n++
		case corev1.ClaimPending:
			pvcSegs[1].n++
		default:
			pvcSegs[2].n++
		}
	}
	pvSegs := []seg{{0, styleOK, "bound"}, {0, styleInfo, "available"}, {0, styleWarn, "released"}, {0, styleCrit, "failed"}}
	var pvBytes float64
	for i := range s.PVs {
		switch s.PVs[i].Status.Phase {
		case corev1.VolumeBound:
			pvSegs[0].n++
		case corev1.VolumeAvailable:
			pvSegs[1].n++
		case corev1.VolumeReleased:
			pvSegs[2].n++
		default:
			pvSegs[3].n++
		}
		if q, ok := s.PVs[i].Spec.Capacity[corev1.ResourceStorage]; ok {
			pvBytes += float64(q.Value())
		}
	}
	var usedBytes, capBytes float64
	usageAll := checks.MergePVCUsage(s, a.nodes)
	for _, u := range usageAll {
		usedBytes += float64(u.Used)
		capBytes += float64(u.Capacity)
	}
	usedTxt := styleDim.Render("n/a")
	if capBytes > 0 {
		usedTxt = gauge(usedBytes/capBytes*100, 12, thr.DiskWarnPct, thr.DiskCritPct) + styleDim.Render(fmt.Sprintf(" %s of %s across %d mounted claims", humanBytes(usedBytes), humanBytes(capBytes), len(usageAll)))
	}
	add(styleTitle.Render("Storage") + "  " + kv("PVCs", stacked(24, pvcSegs)) + " " + legend(pvcSegs) + "  " + kv("PVs", stacked(24, pvSegs)) + " " + legend(pvSegs) + "  " + kv("provisioned", humanBytes(pvBytes)))
	add(kv("PVC usage", usedTxt))
	add("", styleTitle.Render("StorageClasses"))
	var rows [][]string
	for i := range s.StorageClasses {
		sc := &s.StorageClasses[i]
		def := ""
		if sc.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
			def = styleOK.Render("default")
		}
		reclaim, bind := "", ""
		if sc.ReclaimPolicy != nil {
			reclaim = string(*sc.ReclaimPolicy)
		}
		if sc.VolumeBindingMode != nil {
			bind = string(*sc.VolumeBindingMode)
		}
		expand := ""
		if sc.AllowVolumeExpansion != nil && *sc.AllowVolumeExpansion {
			expand = "yes"
		}
		rows = append(rows, []string{sc.Name, sc.Provisioner, reclaim, bind, expand, def})
	}
	if len(rows) == 0 {
		add(styleDim.Render("  none"))
	} else {
		h, lines := renderTable(a.width, []column{{title: "NAME"}, {title: "PROVISIONER"}, {title: "RECLAIM"}, {title: "BINDING"}, {title: "EXPAND"}, {title: ""}}, rows)
		add(h)
		add(lines...)
	}

	add("", styleTitle.Render("CSI drivers"))
	rows = nil
	nodesPer := map[string]int{}
	for i := range s.CSINodes {
		for _, d := range s.CSINodes[i].Spec.Drivers {
			nodesPer[d.Name]++
		}
	}
	for i := range s.CSIDrivers {
		d := &s.CSIDrivers[i]
		attach, podInfo := "", ""
		if d.Spec.AttachRequired != nil {
			attach = fmt.Sprint(*d.Spec.AttachRequired)
		}
		if d.Spec.PodInfoOnMount != nil {
			podInfo = fmt.Sprint(*d.Spec.PodInfoOnMount)
		}
		modes := make([]string, 0, len(d.Spec.VolumeLifecycleModes))
		for _, m := range d.Spec.VolumeLifecycleModes {
			modes = append(modes, string(m))
		}
		rows = append(rows, []string{d.Name, fmt.Sprintf("%d/%d", nodesPer[d.Name], len(s.Nodes)), attach, podInfo, strings.Join(modes, ",")})
	}
	if len(rows) == 0 {
		add(styleDim.Render("  no CSI drivers registered (in-tree or hostPath storage only)"))
	} else {
		h, lines := renderTable(a.width, []column{{title: "DRIVER"}, {title: "NODES"}, {title: "ATTACH"}, {title: "PODINFO"}, {title: "MODES"}}, rows)
		add(h)
		add(lines...)
	}

	usage := checks.MergePVCUsage(s, a.nodes)
	usedNote := "used = kubelet stats/summary, or over SSH: df of the mount / du of hostPath dirs (local-path: request not enforced)"
	if len(usage) == 0 {
		usedNote = "no usage data yet: kubelet reports only CSI/block volumes; hostPath/local-path dirs are measured with du on the full SSH cycle (R)"
		if s.PVCUsageErr != "" {
			usedNote += "; stats/summary error: " + firstLine(s.PVCUsageErr)
		}
	}
	add("", styleTitle.Render("PersistentVolumeClaims")+styleDim.Render("  (namespace filter applies; "+usedNote+")"))
	rows = nil
	// which claims are mounted by a running pod, and what backs each PV
	mountedBy := map[string]string{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				mountedBy[p.Namespace+"/"+v.PersistentVolumeClaim.ClaimName] = p.Spec.NodeName
			}
		}
	}
	pvKind := map[string]string{}
	for i := range s.PVs {
		pv := &s.PVs[i]
		src := pv.Spec.PersistentVolumeSource
		switch {
		case src.CSI != nil:
			pvKind[pv.Name] = "csi:" + src.CSI.Driver
		case src.HostPath != nil:
			pvKind[pv.Name] = "hostPath"
		case src.Local != nil:
			pvKind[pv.Name] = "local"
		case src.NFS != nil:
			pvKind[pv.Name] = "nfs"
		default:
			pvKind[pv.Name] = "other"
		}
	}
	for i := range s.PVCs {
		p := &s.PVCs[i]
		if !a.inNamespace(p.Namespace) {
			continue
		}
		st := string(p.Status.Phase)
		switch p.Status.Phase {
		case corev1.ClaimBound:
			st = styleOK.Render(st)
		case corev1.ClaimPending:
			st = styleWarn.Render(st)
		default:
			st = styleCrit.Render(st)
		}
		sc := ""
		if p.Spec.StorageClassName != nil {
			sc = *p.Spec.StorageClassName
		}
		capacity := ""
		if q, ok := p.Status.Capacity[corev1.ResourceStorage]; ok {
			capacity = q.String()
		} else if q, ok := p.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			capacity = q.String() + styleDim.Render(" (req)")
		}
		var used string
		mounted := ""
		key := p.Namespace + "/" + p.Name
		kind := pvKind[p.Spec.VolumeName]
		if u, ok := usage[key]; ok {
			used = gauge(u.UsedPct(), 10, thr.DiskWarnPct, thr.DiskCritPct) + styleDim.Render(" "+humanBytes(float64(u.Used))+"/"+humanBytes(float64(u.Capacity)))
			mounted = u.Node
			if u.Capacity == 0 {
				used = styleDim.Render(humanBytes(float64(u.Used)) + " used (no capacity known)")
			}
		} else {
			switch {
			case p.Status.Phase != corev1.ClaimBound:
				used = styleDim.Render("not bound")
			case mountedBy[key] == "" && (kind == "hostPath" || kind == "local"):
				used = styleDim.Render("du on next full cycle (R)")
			case mountedBy[key] == "":
				used = styleDim.Render("not mounted by a running pod")
			case kind == "hostPath" || kind == "local":
				used = styleDim.Render("du on next full cycle (R)")
			case strings.HasPrefix(kind, "csi:"):
				used = styleDim.Render("mounted on " + mountedBy[key] + ", driver reported no stats yet")
			default:
				used = styleDim.Render("no stats")
			}
		}
		rows = append(rows, []string{p.Namespace, p.Name, st, used, mounted, kind, p.Spec.VolumeName, capacity, sc, age(p.CreationTimestamp.Time)})
	}
	if len(rows) == 0 {
		add(styleDim.Render("  none"))
	} else {
		h, lines := renderTable(a.width, []column{{title: "NAMESPACE", max: 24}, {title: "NAME", max: 36}, {title: "STATUS"}, {title: "USED"}, {title: "NODE", max: 20}, {title: "BACKEND", max: 22}, {title: "VOLUME", max: 30}, {title: "CAPACITY"}, {title: "CLASS"}, {title: "AGE"}}, rows)
		add(h)
		add(lines...)
	}

	add("", styleTitle.Render("PersistentVolumes"))
	rows = nil
	for i := range s.PVs {
		p := &s.PVs[i]
		claim := ""
		if p.Spec.ClaimRef != nil {
			claim = p.Spec.ClaimRef.Namespace + "/" + p.Spec.ClaimRef.Name
		}
		if !a.inNamespace(strings.SplitN(claim, "/", 2)[0]) && claim != "" {
			continue
		}
		st := string(p.Status.Phase)
		switch p.Status.Phase {
		case corev1.VolumeBound, corev1.VolumeAvailable:
			st = styleOK.Render(st)
		case corev1.VolumeReleased:
			st = styleWarn.Render(st)
		default:
			st = styleCrit.Render(st)
		}
		capacity := ""
		if q, ok := p.Spec.Capacity[corev1.ResourceStorage]; ok {
			capacity = q.String()
		}
		rows = append(rows, []string{p.Name, capacity, st, claim, p.Spec.StorageClassName, string(p.Spec.PersistentVolumeReclaimPolicy), age(p.CreationTimestamp.Time)})
	}
	if len(rows) == 0 {
		add(styleDim.Render("  none"))
	} else {
		h, lines := renderTable(a.width, []column{{title: "NAME", max: 44}, {title: "CAPACITY"}, {title: "STATUS"}, {title: "CLAIM", max: 44}, {title: "CLASS"}, {title: "RECLAIM"}, {title: "AGE"}}, rows)
		add(h)
		add(lines...)
	}

	add("", styleTitle.Render("Node filesystems")+styleDim.Render("  (SSH)"))
	rows = nil
	for _, name := range sortedKeys(a.nodes) {
		ni := a.nodes[name]
		if ni.Err != nil {
			rows = append(rows, []string{name, styleCrit.Render("ssh error"), "", "", "", "", "", ""})
			continue
		}
		for _, m := range ni.Mounts {
			rows = append(rows, []string{name, m.Mountpoint, m.Type, humanKB(m.SizeKB), humanKB(m.UsedKB), humanKB(m.AvailKB), gauge(float64(m.UsePct), 12, thr.DiskWarnPct, thr.DiskCritPct), gauge(float64(m.InodePct), 8, thr.InodeWarnPct, 95)})
		}
	}
	if len(rows) == 0 {
		add(styleDim.Render("  no SSH data"))
	} else {
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "MOUNT", max: 40}, {title: "TYPE"}, {title: "SIZE", right: true}, {title: "USED", right: true}, {title: "AVAIL", right: true}, {title: "USE"}, {title: "INODES"}}, rows)
		add(h)
		add(lines...)
	}
	return linesContent(out)
}

func linesContent(lines []string) content {
	c := content{}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: fmt.Sprint(i), text: l})
	}
	return c
}

// ---------- detail views ----------

func (a *App) detailFor(t tab, id string) (string, []string) {
	if a.snap == nil {
		return "", nil
	}
	switch t {
	case tabOverview:
		var idx int
		if rest, ok := strings.CutPrefix(id, "r:"); ok {
			if _, err := fmt.Sscan(rest, &idx); err == nil && idx >= 0 && idx < len(a.resolved) {
				r := a.resolved[idx]
				lines := []string{sevText(r.Severity) + " " + r.Area + " " + styleBold.Render(r.Object), "",
					styleOK.Render("resolved") + " " + age(r.Resolved) + " ago" + styleDim.Render("  (no longer reported by the checks; first seen "+age(r.First)+" ago, kept for "+humanDur(resolvedKeep)+")"), ""}
				lines = append(lines, wrap(r.Message, a.width-6)...)
				if r.Hint != "" {
					lines = append(lines, "", styleDim.Render("hint was: ")+r.Hint)
				}
				return "Resolved finding", lines
			}
			break
		}
		if _, err := fmt.Sscan(id, &idx); err == nil && idx >= 0 && idx < len(a.findings) {
			f := a.findings[idx]
			lines := []string{sevText(f.Severity) + " " + f.Area + " " + styleBold.Render(f.Object), "", kv("state", "ongoing") + "  " + kv("first seen", age(a.firstSeen(f))+" ago"), ""}
			lines = append(lines, wrap(f.Message, a.width-6)...)
			if f.Hint != "" {
				lines = append(lines, "", styleDim.Render("hint: ")+f.Hint)
			}
			if len(f.Steps) > 0 {
				lines = append(lines, "", styleTitle.Render("steps"))
				lines = append(lines, stepLines(f.Steps, a.width-6)...)
			}
			return "Finding", lines
		}
	case tabNodes:
		return a.nodeDetail(id)
	case tabWorkloads:
		return a.podDetail(strings.TrimPrefix(strings.ReplaceAll(id, "|", "/"), "Pod/"))
	case tabEvents:
		var idx int
		if _, err := fmt.Sscan(id, &idx); err == nil && idx >= 0 && idx < len(a.snap.Events) {
			e := &a.snap.Events[idx]
			lines := []string{
				kv("namespace", e.Namespace), kv("object", e.InvolvedObject.Kind+"/"+e.InvolvedObject.Name), kv("reason", e.Reason),
				kv("count", fmt.Sprint(k8s.EventCount(e))), kv("first", age(e.FirstTimestamp.Time)+" ago"), kv("last", age(k8s.EventTime(e))+" ago"),
				kv("source", e.Source.Component+" "+e.Source.Host), "",
			}
			lines = append(lines, wrap(e.Message, a.width-6)...)
			return "Event", lines
		}
	case tabEtcd:
		return a.etcdDetail()
	case tabAddons:
		return a.addonsDetail(id)
	case tabHelm:
		return a.helmDetail(id)
	case tabImages:
		return a.imagesDetail(id)
	case tabSecurity:
		return a.securityDetail(id)
	case tabLogs:
		return a.logsDetail(id)
	case tabRKE2:
		return a.rke2Detail(id)
	}
	return "", nil
}

// nodeDashboard renders the tile row and the security at-a-glance table for a node.
func (a *App) nodeDashboard(n *corev1.Node, w int) []string {
	thr := a.cfg.Thresholds
	name := n.Name
	ni := a.nodes[name]
	var out []string
	tw, cnt := tileWidths(w, 6)
	gw := tw - 9
	sw := tw - 4
	cpu, mem, load, root, data := nan(), nan(), nan(), nan(), nan()
	dataMount := "-"
	podsOn := 0
	for i := range a.snap.Pods {
		if a.snap.Pods[i].Spec.NodeName == name && a.snap.Pods[i].Status.Phase == corev1.PodRunning {
			podsOn++
		}
	}
	maxPods := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourcePods)
	if ni != nil && ni.Err == nil {
		cpu, mem = ni.CPUPct, ni.MemPct
		if ni.CPUs > 0 {
			load = ni.Load1 / float64(ni.CPUs) * 100
		}
		if m := ni.MountFor("/"); m != nil {
			root = float64(m.UsePct)
		}
		if m := ni.DataMount(); m != nil && m.Mountpoint != "/" {
			data, dataMount = float64(m.UsePct), m.Mountpoint
		}
	} else if m, ok := a.snap.NodeMetrics[name]; ok {
		if alloc := k8s.QuantityMilli(n.Status.Allocatable, corev1.ResourceCPU); alloc > 0 {
			cpu = float64(m.CPUMilli) * 100 / float64(alloc)
		}
		if alloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourceMemory); alloc > 0 {
			mem = float64(m.MemBytes) * 100 / float64(alloc)
		}
	}
	podPct := nan()
	if maxPods > 0 {
		podPct = float64(podsOn) * 100 / float64(maxPods)
	}
	tiles := []string{
		tile(tw, "CPU", gauge(cpu, gw, thr.CPUWarnPct, 95), sparkStyled(a.values("node.cpu:"+name), sw, 100, thr.CPUWarnPct, 95)),
		tile(tw, "Memory", gauge(mem, gw, thr.MemWarnPct, thr.MemCritPct), sparkStyled(a.values("node.mem:"+name), sw, 100, thr.MemWarnPct, thr.MemCritPct)),
		tile(tw, "Load / CPU", gauge(load, gw, int(thr.LoadPerCPUWarn*100), 300), sparkStyled(a.values("node.load:"+name), sw, 0, int(thr.LoadPerCPUWarn*100), 300)),
		tile(tw, "Root fs", gauge(root, gw, thr.DiskWarnPct, thr.DiskCritPct), sparkStyled(a.values("node.root:"+name), sw, 100, thr.DiskWarnPct, thr.DiskCritPct)),
		tile(tw, "Data fs", gauge(data, gw, thr.DiskWarnPct, thr.DiskCritPct), styleDim.Render(trunc(dataMount, sw))),
		tile(tw, "Pods", gauge(podPct, gw, 80, 90), styleDim.Render(fmt.Sprintf("%d running / %d max", podsOn, maxPods))),
	}
	out = append(out, tileRow(tiles[:cnt])...)
	out = append(out, "")
	return out
}

func pctOf(v, total int64) string {
	if total <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d%%", v*100/total)
}

func (a *App) podDetail(id string) (string, []string) {
	s := a.snap
	ns, name, _ := strings.Cut(id, "/")
	var p *corev1.Pod
	for i := range s.Pods {
		if s.Pods[i].Namespace == ns && s.Pods[i].Name == name {
			p = &s.Pods[i]
		}
	}
	if p == nil {
		return "", nil
	}
	w := a.width - 6
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	add(kv("status", k8s.PodStatus(p)) + "  " + kv("phase", string(p.Status.Phase)) + "  " + kv("node", p.Spec.NodeName) + "  " + kv("ip", p.Status.PodIP) + "  " + kv("age", age(p.CreationTimestamp.Time)))
	add(kv("service account", p.Spec.ServiceAccountName) + "  " + kv("qos", string(p.Status.QOSClass)) + "  " + kv("priority", fmt.Sprint(ptrInt(p.Spec.Priority))) + "  " + kv("hostNetwork", fmt.Sprint(p.Spec.HostNetwork)))
	if len(p.OwnerReferences) > 0 {
		add(kv("owner", p.OwnerReferences[0].Kind+"/"+p.OwnerReferences[0].Name))
	}
	if p.Status.Message != "" || p.Status.Reason != "" {
		add(kv("reason", p.Status.Reason+" "+p.Status.Message))
	}
	var conds []string
	for _, c := range p.Status.Conditions {
		conds = append(conds, okText(c.Status == corev1.ConditionTrue, string(c.Type), string(c.Type)+"="+string(c.Status)))
	}
	add(kv("conditions", strings.Join(conds, " ")))
	add("", styleTitle.Render("Containers"))
	statuses := map[string]corev1.ContainerStatus{}
	for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		statuses[cs.Name] = cs
	}
	describe := func(c corev1.Container, init bool) {
		cs, ok := statuses[c.Name]
		state := "-"
		if ok {
			switch {
			case cs.State.Running != nil:
				state = styleOK.Render("running since " + age(cs.State.Running.StartedAt.Time) + " ago")
			case cs.State.Waiting != nil:
				state = styleWarn.Render("waiting: " + cs.State.Waiting.Reason + " " + firstLine(cs.State.Waiting.Message))
			case cs.State.Terminated != nil:
				state = fmt.Sprintf("terminated: %s exit=%d", cs.State.Terminated.Reason, cs.State.Terminated.ExitCode)
				if cs.State.Terminated.ExitCode != 0 {
					state = styleCrit.Render(state)
				}
			}
		}
		label := c.Name
		if init {
			label = "init:" + c.Name
		}
		add(styleBold.Render(label) + "  " + kv("image", c.Image))
		add("  " + kv("state", state) + "  " + kv("ready", fmt.Sprint(cs.Ready)) + "  " + kv("restarts", fmt.Sprint(cs.RestartCount)))
		if cs.LastTerminationState.Terminated != nil {
			t := cs.LastTerminationState.Terminated
			add("  " + kv("last termination", fmt.Sprintf("%s exit=%d at %s ago", t.Reason, t.ExitCode, age(t.FinishedAt.Time))))
		}
		var res []string
		for _, r := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
			req, lim := "-", "-"
			if q, ok := c.Resources.Requests[r]; ok {
				req = q.String()
			}
			if q, ok := c.Resources.Limits[r]; ok {
				lim = q.String()
			}
			res = append(res, fmt.Sprintf("%s req=%s lim=%s", r, req, lim))
		}
		add("  " + kv("resources", strings.Join(res, "  ")))
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			add("  " + styleWarn.Render("privileged"))
		}
	}
	for _, c := range p.Spec.InitContainers {
		describe(c, true)
	}
	for _, c := range p.Spec.Containers {
		describe(c, false)
	}
	var evs []string
	for i := range s.Events {
		e := &s.Events[i]
		if e.InvolvedObject.UID == p.UID || (e.InvolvedObject.Kind == "Pod" && e.InvolvedObject.Name == p.Name && e.Namespace == p.Namespace) {
			evs = append(evs, fmt.Sprintf("%s ago  %s x%d  %s", age(k8s.EventTime(e)), styleWarn.Render(e.Reason), k8s.EventCount(e), firstLine(e.Message)))
		}
	}
	if len(evs) > 0 {
		add("", styleTitle.Render("Warning events"))
		for _, e := range evs {
			add(wrap(e, w)...)
		}
	}
	return "Pod " + id, out
}

func ptrInt(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}
