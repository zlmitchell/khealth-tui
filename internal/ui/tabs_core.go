package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/checks"
	"k8s-health-tui/internal/k8s"
)

// ---------- Overview ----------

func (a *App) overviewContent() content {
	s := a.snap
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
	running, pending, failed, other := 0, 0, 0, 0
	for i := range s.Pods {
		switch s.Pods[i].Status.Phase {
		case corev1.PodRunning:
			running++
		case corev1.PodPending:
			pending++
		case corev1.PodFailed:
			failed++
		case corev1.PodSucceeded:
		default:
			other++
		}
	}
	hdr = append(hdr, styleTitle.Render("Cluster")+"  "+kv("context", a.client.Context)+"  "+kv("server", a.client.Host)+"  "+kv("version", s.Version)+"  "+kv("distribution", s.Distribution))
	hdr = append(hdr, kv("nodes", okText(ready == len(s.Nodes), fmt.Sprintf("%d/%d ready", ready, len(s.Nodes)), fmt.Sprintf("%d/%d ready", ready, len(s.Nodes))))+"  "+kv("control-plane", fmt.Sprint(cp))+"  "+kv("pods", fmt.Sprintf("%d running, %s, %s", running, colorCount(pending, "pending", styleWarn), colorCount(failed, "failed", styleCrit)))+"  "+kv("namespaces", fmt.Sprint(len(s.Namespaces))))

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
	hdr = append(hdr, api)
	if a.sshEnabled {
		okN, errN := 0, 0
		for _, ni := range a.nodes {
			if ni.Err != nil {
				errN++
			} else {
				okN++
			}
		}
		hdr = append(hdr, kv("ssh", fmt.Sprintf("%d nodes collected, %s, %d pending", okN, colorCount(errN, "failed", styleWarn), len(a.pending)))+"  "+kv("etcd probes", fmt.Sprint(len(a.etcd))))
	} else {
		note := "disabled"
		if a.sshErr != "" {
			note = styleWarn.Render(a.sshErr)
		}
		hdr = append(hdr, kv("ssh", note))
	}
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
	hdr = append(hdr, "")
	hdr = append(hdr, styleTitle.Render("Findings")+"  "+styleCrit.Render(fmt.Sprintf("%d critical", crit))+"  "+styleWarn.Render(fmt.Sprintf("%d warnings", warn))+"  "+styleInfo.Render(fmt.Sprintf("%d info", info))+styleDim.Render("   (a toggles info, enter shows hint)"))

	var rows [][]string
	var ids []string
	for i, f := range a.findings {
		if a.problemOnly && f.Severity == checks.SevInfo {
			continue
		}
		rows = append(rows, []string{sevText(f.Severity), f.Area, f.Object, f.Message})
		ids = append(ids, fmt.Sprint(i))
	}
	h, lines := renderTable(a.width, []column{{title: "SEV"}, {title: "AREA"}, {title: "OBJECT", max: 48}, {title: "MESSAGE"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: styleOK.Render("no findings - cluster looks healthy")}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
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
		cpu, mem, load, root, data, kubelet, uptime, ssh := "-", "-", "-", "-", "-", "-", "-", styleDim.Render("-")
		if ni, ok := a.nodes[n.Name]; ok && ni.Err == nil {
			cpu = pctText(ni.CPUPct, thr.CPUWarnPct, 95)
			mem = pctText(ni.MemPct, thr.MemWarnPct, thr.MemCritPct)
			load = fmt.Sprintf("%.1f", ni.Load1)
			if ni.CPUs > 0 && ni.Load1/float64(ni.CPUs) >= thr.LoadPerCPUWarn {
				load = styleWarn.Render(load)
			}
			if m := ni.MountFor("/"); m != nil {
				root = pctText(float64(m.UsePct), thr.DiskWarnPct, thr.DiskCritPct)
			}
			if m := ni.DataMount(); m != nil && m.Mountpoint != "/" {
				data = pctText(float64(m.UsePct), thr.DiskWarnPct, thr.DiskCritPct) + styleDim.Render(" "+m.Mountpoint)
			} else {
				data = styleDim.Render("(root)")
			}
			if svc := ni.Service("kubelet"); svc != nil {
				kubelet = okText(svc.Active == "active", "active", svc.Active)
			} else if svc := ni.Service("rke2-server"); svc != nil {
				kubelet = okText(svc.Active == "active", "rke2-server", "rke2-server:"+svc.Active)
			} else if svc := ni.Service("rke2-agent"); svc != nil {
				kubelet = okText(svc.Active == "active", "rke2-agent", "rke2-agent:"+svc.Active)
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
		if m, ok := s.NodeMetrics[n.Name]; ok && cpu == "-" {
			if alloc := k8s.QuantityMilli(n.Status.Allocatable, corev1.ResourceCPU); alloc > 0 {
				cpu = pctText(float64(m.CPUMilli)*100/float64(alloc), thr.CPUWarnPct, 95) + styleDim.Render("m")
			}
			if alloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourceMemory); alloc > 0 {
				mem = pctText(float64(m.MemBytes)*100/float64(alloc), thr.MemWarnPct, thr.MemCritPct) + styleDim.Render("m")
			}
		}
		rows = append(rows, []string{n.Name, roles, status, n.Status.NodeInfo.KubeletVersion, cpu, mem, load, root, data, kubelet, uptime, age(n.CreationTimestamp.Time), ssh})
		ids = append(ids, n.Name)
	}
	h, lines := renderTable(a.width, []column{{title: "NAME"}, {title: "ROLES", max: 24}, {title: "STATUS"}, {title: "VERSION"}, {title: "CPU", right: true}, {title: "MEM", right: true}, {title: "LOAD", right: true}, {title: "ROOT", right: true}, {title: "DATA DISK"}, {title: "KUBELET"}, {title: "UPTIME"}, {title: "AGE"}, {title: "SSH"}}, rows)
	c := content{header: []string{styleDim.Render("m = metrics-server value, ok+ = full collection done; enter for details"), h}, selectable: true, empty: "no nodes"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// ---------- Workloads ----------

func (a *App) workloadsContent() content {
	s := a.snap
	var hdr []string
	var bad []string
	for i := range s.Deployments {
		d := &s.Deployments[i]
		if !a.inNamespace(d.Namespace) {
			continue
		}
		if d.Spec.Replicas != nil && *d.Spec.Replicas > 0 && d.Status.UnavailableReplicas > 0 {
			bad = append(bad, styleWarn.Render(fmt.Sprintf("deploy %s/%s %d/%d", d.Namespace, d.Name, d.Status.AvailableReplicas, *d.Spec.Replicas)))
		}
	}
	for i := range s.DaemonSets {
		d := &s.DaemonSets[i]
		if !a.inNamespace(d.Namespace) {
			continue
		}
		if d.Status.NumberReady < d.Status.DesiredNumberScheduled {
			bad = append(bad, styleWarn.Render(fmt.Sprintf("ds %s/%s %d/%d", d.Namespace, d.Name, d.Status.NumberReady, d.Status.DesiredNumberScheduled)))
		}
	}
	for i := range s.StatefulSets {
		d := &s.StatefulSets[i]
		if !a.inNamespace(d.Namespace) {
			continue
		}
		if d.Spec.Replicas != nil && d.Status.ReadyReplicas < *d.Spec.Replicas {
			bad = append(bad, styleWarn.Render(fmt.Sprintf("sts %s/%s %d/%d", d.Namespace, d.Name, d.Status.ReadyReplicas, *d.Spec.Replicas)))
		}
	}
	nDep, nDS, nSTS, nJob, nCron := 0, 0, 0, 0, 0
	for i := range s.Deployments {
		if a.inNamespace(s.Deployments[i].Namespace) {
			nDep++
		}
	}
	for i := range s.DaemonSets {
		if a.inNamespace(s.DaemonSets[i].Namespace) {
			nDS++
		}
	}
	for i := range s.StatefulSets {
		if a.inNamespace(s.StatefulSets[i].Namespace) {
			nSTS++
		}
	}
	for i := range s.Jobs {
		if a.inNamespace(s.Jobs[i].Namespace) {
			nJob++
		}
	}
	for i := range s.CronJobs {
		if a.inNamespace(s.CronJobs[i].Namespace) {
			nCron++
		}
	}
	hdr = append(hdr, styleTitle.Render("Workloads")+"  "+kv("deployments", fmt.Sprint(nDep))+"  "+kv("daemonsets", fmt.Sprint(nDS))+"  "+kv("statefulsets", fmt.Sprint(nSTS))+"  "+kv("jobs", fmt.Sprint(nJob))+"  "+kv("cronjobs", fmt.Sprint(nCron)))
	if len(bad) > 0 {
		hdr = append(hdr, "unhealthy: "+strings.Join(bad, "  "))
	} else {
		hdr = append(hdr, styleOK.Render("all controllers at desired replicas"))
	}
	var rows [][]string
	var ids []string
	total := 0
	for i := range s.Pods {
		p := &s.Pods[i]
		if !a.inNamespace(p.Namespace) {
			continue
		}
		total++
		healthy := k8s.PodHealthy(p)
		if a.problemOnly && healthy {
			continue
		}
		st := k8s.PodStatus(p)
		stText := st
		switch {
		case st == "Running" || st == "Completed" || st == "Succeeded":
			stText = styleOK.Render(st)
		case st == "CrashLoopBackOff" || strings.Contains(st, "Err") || strings.Contains(st, "BackOff") || st == "Failed" || st == "Error":
			stText = styleCrit.Render(st)
		default:
			stText = styleWarn.Render(st)
		}
		r, t := k8s.PodReady(p)
		readyText := fmt.Sprintf("%d/%d", r, t)
		if r < t && p.Status.Phase == corev1.PodRunning {
			readyText = styleWarn.Render(readyText)
		}
		restarts, last := k8s.PodRestarts(p)
		rsText := fmt.Sprint(restarts)
		if restarts > 0 && !last.IsZero() {
			rsText += styleDim.Render(" (" + age(last) + " ago)")
			if restarts >= a.cfg.Thresholds.RestartWarn {
				rsText = styleWarn.Render(fmt.Sprint(restarts)) + styleDim.Render(" ("+age(last)+" ago)")
			}
		}
		rows = append(rows, []string{p.Namespace, p.Name, readyText, stText, rsText, age(p.CreationTimestamp.Time), p.Spec.NodeName})
		ids = append(ids, p.Namespace+"/"+p.Name)
	}
	mode := "all pods"
	if a.problemOnly {
		mode = "problem pods only (a toggles)"
	}
	hdr = append(hdr, styleDim.Render(fmt.Sprintf("%d pods, showing %d - %s", total, len(rows), mode)))
	h, lines := renderTable(a.width, []column{{title: "NAMESPACE", max: 28}, {title: "NAME", max: 60}, {title: "READY", right: true}, {title: "STATUS"}, {title: "RESTARTS"}, {title: "AGE", right: true}, {title: "NODE"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: styleOK.Render("no pods to show")}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// ---------- Events ----------

func (a *App) eventsContent() content {
	s := a.snap
	var rows [][]string
	var ids []string
	for i := range s.Events {
		e := &s.Events[i]
		if !a.inNamespace(e.Namespace) {
			continue
		}
		obj := e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name
		rows = append(rows, []string{age(k8s.EventTime(e)), e.Namespace, obj, styleWarn.Render(e.Reason), fmt.Sprint(k8s.EventCount(e)), firstLine(e.Message)})
		ids = append(ids, fmt.Sprint(i))
	}
	h, lines := renderTable(a.width, []column{{title: "LAST", right: true}, {title: "NAMESPACE", max: 24}, {title: "OBJECT", max: 44}, {title: "REASON", max: 26}, {title: "N", right: true}, {title: "MESSAGE"}}, rows)
	c := content{header: []string{styleTitle.Render("Warning events") + styleDim.Render(fmt.Sprintf("  %d in scope, newest first; enter for full message", len(rows))), h}, selectable: true, empty: styleOK.Render("no warning events")}
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

	add(styleTitle.Render("StorageClasses"))
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

	add("", styleTitle.Render("PersistentVolumeClaims")+styleDim.Render("  (namespace filter applies)"))
	rows = nil
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
		rows = append(rows, []string{p.Namespace, p.Name, st, p.Spec.VolumeName, capacity, sc, age(p.CreationTimestamp.Time)})
	}
	if len(rows) == 0 {
		add(styleDim.Render("  none"))
	} else {
		h, lines := renderTable(a.width, []column{{title: "NAMESPACE", max: 24}, {title: "NAME", max: 40}, {title: "STATUS"}, {title: "VOLUME", max: 40}, {title: "CAPACITY"}, {title: "CLASS"}, {title: "AGE"}}, rows)
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
			rows = append(rows, []string{name, m.Mountpoint, m.Type, humanKB(m.SizeKB), humanKB(m.UsedKB), humanKB(m.AvailKB), pctText(float64(m.UsePct), thr.DiskWarnPct, thr.DiskCritPct), pctText(float64(m.InodePct), thr.InodeWarnPct, 95)})
		}
	}
	if len(rows) == 0 {
		add(styleDim.Render("  no SSH data"))
	} else {
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "MOUNT", max: 40}, {title: "TYPE"}, {title: "SIZE", right: true}, {title: "USED", right: true}, {title: "AVAIL", right: true}, {title: "USE%", right: true}, {title: "INODE%", right: true}}, rows)
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
		if _, err := fmt.Sscan(id, &idx); err == nil && idx >= 0 && idx < len(a.findings) {
			f := a.findings[idx]
			lines := []string{sevText(f.Severity) + " " + f.Area + " " + styleBold.Render(f.Object), ""}
			lines = append(lines, wrap(f.Message, a.width-6)...)
			if f.Hint != "" {
				lines = append(lines, "", styleDim.Render("hint: ")+f.Hint)
			}
			return "Finding", lines
		}
	case tabNodes:
		return a.nodeDetail(id)
	case tabWorkloads:
		return a.podDetail(id)
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
		return a.addonsDetail()
	case tabHelm:
		return a.helmDetail(id)
	case tabImages:
		return a.imagesDetail(id)
	case tabSecurity:
		return a.securityDetail(id)
	case tabLogs:
		return a.logsDetail(id)
	}
	return "", nil
}

func (a *App) nodeDetail(name string) (string, []string) {
	s := a.snap
	var n *corev1.Node
	for i := range s.Nodes {
		if s.Nodes[i].Name == name {
			n = &s.Nodes[i]
		}
	}
	if n == nil {
		return "", nil
	}
	w := a.width - 6
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	add(kv("roles", strings.Join(k8s.NodeRoles(n), ",")) + "  " + kv("kubelet", n.Status.NodeInfo.KubeletVersion) + "  " + kv("runtime", n.Status.NodeInfo.ContainerRuntimeVersion))
	add(kv("os", n.Status.NodeInfo.OSImage) + "  " + kv("kernel", n.Status.NodeInfo.KernelVersion) + "  " + kv("arch", n.Status.NodeInfo.Architecture))
	var addrs []string
	for _, ad := range n.Status.Addresses {
		addrs = append(addrs, fmt.Sprintf("%s=%s", ad.Type, ad.Address))
	}
	add(kv("addresses", strings.Join(addrs, " ")))
	add(kv("pod CIDR", strings.Join(n.Spec.PodCIDRs, ",")) + "  " + kv("provider", n.Spec.ProviderID))
	var conds []string
	for _, c := range n.Status.Conditions {
		txt := fmt.Sprintf("%s=%s", c.Type, c.Status)
		bad := (c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue) || (c.Type != corev1.NodeReady && c.Status == corev1.ConditionTrue)
		if bad {
			txt = styleCrit.Render(txt) + styleDim.Render(" ("+c.Reason+")")
		} else {
			txt = styleOK.Render(txt)
		}
		conds = append(conds, txt)
	}
	add(kv("conditions", strings.Join(conds, " ")))
	if len(n.Spec.Taints) > 0 {
		var ts []string
		for _, t := range n.Spec.Taints {
			ts = append(ts, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
		}
		add(kv("taints", strings.Join(ts, " ")))
	}
	var pods []corev1.Pod
	for i := range s.Pods {
		if s.Pods[i].Spec.NodeName == name {
			pods = append(pods, s.Pods[i])
		}
	}
	cpuReq, memReq := k8s.SumRequests(pods)
	cpuAlloc := k8s.QuantityMilli(n.Status.Allocatable, corev1.ResourceCPU)
	memAlloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourceMemory)
	podAlloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourcePods)
	add(kv("allocatable", fmt.Sprintf("cpu %dm, mem %s, pods %d", cpuAlloc, humanBytes(float64(memAlloc)), podAlloc)))
	add(kv("requests", fmt.Sprintf("cpu %dm (%s), mem %s (%s), pods %d", cpuReq, pctOf(cpuReq, cpuAlloc), humanBytes(float64(memReq)), pctOf(memReq, memAlloc), len(pods))))
	if m, ok := s.NodeMetrics[name]; ok {
		add(kv("metrics-server usage", fmt.Sprintf("cpu %dm (%s), mem %s (%s)", m.CPUMilli, pctOf(m.CPUMilli, cpuAlloc), humanBytes(float64(m.MemBytes)), pctOf(m.MemBytes, memAlloc))))
	}
	for _, img := range n.Status.Images {
		_ = img
	}
	add(kv("images cached on node (API)", fmt.Sprint(len(n.Status.Images))))

	ni := a.nodes[name]
	add("", styleTitle.Render("SSH collection"))
	switch {
	case ni == nil && a.pending[name]:
		add(styleDim.Render("  collecting..."))
	case ni == nil:
		add(styleDim.Render("  no data (SSH disabled)"))
	case ni.Err != nil:
		add(styleCrit.Render("  error: " + ni.Err.Error()))
	default:
		add(kv("host", ni.Host) + "  " + kv("hostname", ni.Hostname) + "  " + kv("kernel", ni.Kernel) + "  " + kv("collected", age(ni.Collected)+" ago in "+humanDur(ni.Duration)) + "  " + kv("dist", ni.Dist))
		add(kv("uptime", humanDur(ni.Uptime)) + "  " + kv("load", fmt.Sprintf("%.2f %.2f %.2f on %d cpus", ni.Load1, ni.Load5, ni.Load15, ni.CPUs)) + "  " + kv("cpu busy", pctText(ni.CPUPct, a.cfg.Thresholds.CPUWarnPct, 95)))
		add(kv("memory", fmt.Sprintf("%s total, %s available, %s used", humanBytes(float64(ni.MemTotal)), humanBytes(float64(ni.MemAvail)), pctText(ni.MemPct, a.cfg.Thresholds.MemWarnPct, a.cfg.Thresholds.MemCritPct))) + "  " + kv("swap", fmt.Sprintf("%s total, %s used", humanBytes(float64(ni.SwapTotal)), humanBytes(float64(ni.SwapTotal-ni.SwapFree)))))
		ntp := "unknown"
		if ni.NTPSynced != nil {
			ntp = okText(*ni.NTPSynced, "synchronised", "NOT synchronised")
		}
		add(kv("ntp", ntp) + "  " + kv("clock offset", fmt.Sprint(ni.ClockOffset)) + "  " + kv("selinux", ni.SELinux))
		var svcs []string
		for _, svc := range ni.Services {
			svcs = append(svcs, okText(svc.Active == "active", svc.Name, svc.Name+":"+svc.Active))
		}
		add(kv("services", strings.Join(svcs, " ")))
		for _, u := range ni.Units {
			add(kv("unit "+u.Name, fmt.Sprintf("%s/%s restarts=%d started=%s result=%s", u.Active, u.Sub, u.NRestarts, age(u.Started)+" ago", u.Result)))
		}
		if len(ni.Settings) > 0 {
			var kvs []string
			for _, k := range sortedKeys(ni.Settings) {
				kvs = append(kvs, k+"="+ni.Settings[k])
			}
			add(kv("rke2 config", strings.Join(kvs, " ")))
		}
		if ni.Rancher.SystemAgent != "" || ni.Rancher.Provisioned {
			add(kv("rancher", fmt.Sprintf("system-agent=%s provisioned=%v url=%s plans=%d", strings.TrimSpace(ni.Rancher.SystemAgent), ni.Rancher.Provisioned, ni.Rancher.AgentURL, ni.Rancher.Plans)))
		}
		add("", styleTitle.Render("Filesystems"))
		var rows [][]string
		for _, m := range ni.Mounts {
			rows = append(rows, []string{m.Mountpoint, m.Filesystem, m.Type, humanKB(m.SizeKB), humanKB(m.UsedKB), humanKB(m.AvailKB), pctText(float64(m.UsePct), a.cfg.Thresholds.DiskWarnPct, a.cfg.Thresholds.DiskCritPct), pctText(float64(m.InodePct), a.cfg.Thresholds.InodeWarnPct, 95)})
		}
		h, lines := renderTable(w, []column{{title: "MOUNT", max: 36}, {title: "DEVICE", max: 30}, {title: "TYPE"}, {title: "SIZE", right: true}, {title: "USED", right: true}, {title: "AVAIL", right: true}, {title: "USE%", right: true}, {title: "INODE%", right: true}}, rows)
		add(h)
		add(lines...)
		if len(ni.Certs) > 0 {
			add("", styleTitle.Render("Certificates"))
			rows = nil
			sort.Slice(ni.Certs, func(i, j int) bool { return ni.Certs[i].NotAfter.Before(ni.Certs[j].NotAfter) })
			for _, c := range ni.Certs {
				left := time.Until(c.NotAfter)
				txt := fmt.Sprintf("%dd", int(left.Hours()/24))
				switch {
				case left <= 0:
					txt = styleCrit.Render("EXPIRED")
				case left < a.cfg.Thresholds.CertExpiryWarn:
					txt = styleWarn.Render(txt)
				default:
					txt = styleOK.Render(txt)
				}
				rows = append(rows, []string{c.Path, c.NotAfter.Format("2006-01-02"), txt})
			}
			h, lines = renderTable(w, []column{{title: "FILE"}, {title: "EXPIRES"}, {title: "LEFT", right: true}}, rows)
			add(h)
			add(lines...)
		}
		if len(ni.Sysctl) > 0 {
			var kvs []string
			for _, k := range sortedKeys(ni.Sysctl) {
				kvs = append(kvs, k+"="+ni.Sysctl[k])
			}
			add("", kv("sysctl", strings.Join(kvs, " ")))
		}
		if len(ni.KubeletFlags) > 0 {
			var kvs []string
			for _, k := range sortedKeys(ni.KubeletFlags) {
				kvs = append(kvs, "--"+k+"="+ni.KubeletFlags[k])
			}
			add("", styleTitle.Render("kubelet process args"))
			add(wrap(strings.Join(kvs, " "), w)...)
		}
	}
	return "Node " + name, out
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
