package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/k8s"
)

// nodeDetail renders one node as a dashboard followed by non-overlapping
// tables: facts, capacity/usage, security, services, platform, filesystems,
// certificates, sysctls, kubelet args.
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
	thr := a.cfg.Thresholds
	ni := a.nodes[name]
	hasSSH := ni != nil && ni.Err == nil
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	table := func(cols []column, rows [][]string) {
		h, lines := renderTable(w, cols, rows)
		add(h)
		add(lines...)
	}
	kvTable := func(rows [][]string) {
		table([]column{{title: "FIELD"}, {title: "VALUE"}}, rows)
	}

	// ---- dashboard tiles ----
	add(a.nodeDashboard(n, w)...)

	// ---- node facts ----
	var conds []string
	for _, c := range n.Status.Conditions {
		txt := fmt.Sprintf("%s=%s", c.Type, c.Status)
		bad := (c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue) || (c.Type != corev1.NodeReady && c.Status == corev1.ConditionTrue)
		if bad {
			conds = append(conds, styleCrit.Render(txt)+styleDim.Render(" ("+c.Reason+")"))
		} else {
			conds = append(conds, styleOK.Render(txt))
		}
	}
	var addrs []string
	for _, ad := range n.Status.Addresses {
		addrs = append(addrs, fmt.Sprintf("%s=%s", ad.Type, ad.Address))
	}
	var taints []string
	for _, t := range n.Spec.Taints {
		taints = append(taints, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
	}
	sched := styleOK.Render("schedulable")
	if n.Spec.Unschedulable {
		sched = styleWarn.Render("cordoned")
	}
	osName := n.Status.NodeInfo.OSImage
	kernel := n.Status.NodeInfo.KernelVersion
	if hasSSH {
		if ni.OS.Pretty != "" {
			osName = ni.OS.Pretty
		}
		if ni.Kernel != "" {
			kernel = ni.Kernel
		}
	}
	add(styleTitle.Render("Node"))
	// list renders a field as a yaml-style array, one item per row, so long
	// lists (conditions, addresses) never run off the right edge
	list := func(field string, items []string) [][]string {
		if len(items) == 0 {
			return [][]string{{field, styleDim.Render("-")}}
		}
		rows := [][]string{{field, "- " + items[0]}}
		for _, it := range items[1:] {
			rows = append(rows, []string{"", "- " + it})
		}
		return rows
	}
	facts := [][]string{
		{"roles", strings.Join(k8s.NodeRoles(n), ",") + "  " + sched},
	}
	facts = append(facts, list("conditions", conds)...)
	facts = append(facts,
		[]string{"kubelet / runtime", n.Status.NodeInfo.KubeletVersion + "  " + n.Status.NodeInfo.ContainerRuntimeVersion},
		[]string{"os / kernel / arch", osName + "  " + kernel + "  " + n.Status.NodeInfo.Architecture},
	)
	facts = append(facts, list("addresses", addrs)...)
	facts = append(facts, []string{"pod CIDR", strings.Join(n.Spec.PodCIDRs, ",")})
	facts = append(facts, list("taints", taints)...)
	facts = append(facts, []string{"created", age(n.CreationTimestamp.Time) + " ago"})
	if n.Spec.ProviderID != "" {
		facts = append(facts, []string{"provider", n.Spec.ProviderID})
	}
	if hasSSH {
		ntp := "unknown"
		if ni.NTPSynced != nil {
			ntp = okText(*ni.NTPSynced, "synchronised", "NOT synchronised")
		}
		facts = append(facts,
			[]string{"hostname / dist", ni.Hostname + "  " + ni.Dist + "  " + styleDim.Render("data-dir "+ni.DataDir)},
			[]string{"uptime", humanDur(ni.Uptime)},
			[]string{"clock", "ntp " + ntp + "  offset " + fmt.Sprint(ni.ClockOffset) + " vs this machine"},
			[]string{"ssh", fmt.Sprintf("%s, collected %s ago in %s", ni.Host, age(ni.Collected), humanDur(ni.Duration))},
		)
	} else if ni != nil {
		facts = append(facts, []string{"ssh", styleCrit.Render(ni.Err.Error())})
	} else if a.pending[name] {
		facts = append(facts, []string{"ssh", styleDim.Render("collecting...")})
	}
	kvTable(facts)

	// ---- capacity & usage ----
	add("", styleTitle.Render("Capacity & usage")+styleDim.Render("  requested = sum of pod requests; used = SSH (or metrics-server)"))
	var pods []corev1.Pod
	running := 0
	for i := range s.Pods {
		if s.Pods[i].Spec.NodeName == name {
			pods = append(pods, s.Pods[i])
			if s.Pods[i].Status.Phase == corev1.PodRunning {
				running++
			}
		}
	}
	cpuReq, memReq := k8s.SumRequests(pods)
	cpuAlloc := k8s.QuantityMilli(n.Status.Allocatable, corev1.ResourceCPU)
	memAlloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourceMemory)
	podAlloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourcePods)
	cpuUsed, memUsed := "-", "-"
	switch {
	case hasSSH:
		cpuUsed = gauge(ni.CPUPct, 10, thr.CPUWarnPct, 95) + styleDim.Render(fmt.Sprintf(" of %d cpus, load %.2f/%.2f/%.2f", ni.CPUs, ni.Load1, ni.Load5, ni.Load15))
		memUsed = gauge(ni.MemPct, 10, thr.MemWarnPct, thr.MemCritPct) + styleDim.Render(fmt.Sprintf(" %s used of %s (%s available)", humanBytes(float64(ni.MemTotal-ni.MemAvail)), humanBytes(float64(ni.MemTotal)), humanBytes(float64(ni.MemAvail))))
	default:
		if m, ok := s.NodeMetrics[name]; ok {
			if cpuAlloc > 0 {
				cpuUsed = gauge(float64(m.CPUMilli)*100/float64(cpuAlloc), 10, thr.CPUWarnPct, 95) + styleDim.Render(fmt.Sprintf(" %dm (metrics-server)", m.CPUMilli))
			}
			if memAlloc > 0 {
				memUsed = gauge(float64(m.MemBytes)*100/float64(memAlloc), 10, thr.MemWarnPct, thr.MemCritPct) + styleDim.Render(" "+humanBytes(float64(m.MemBytes))+" (metrics-server)")
			}
		}
	}
	capRows := [][]string{
		{"cpu", fmt.Sprintf("%dm", cpuAlloc), fmt.Sprintf("%dm (%s)", cpuReq, pctOf(cpuReq, cpuAlloc)), cpuUsed},
		{"memory", humanBytes(float64(memAlloc)), fmt.Sprintf("%s (%s)", humanBytes(float64(memReq)), pctOf(memReq, memAlloc)), memUsed},
		{"pods", fmt.Sprint(podAlloc), fmt.Sprintf("%d scheduled, %d running", len(pods), running), gauge(nanIf(podAlloc > 0, float64(running)*100/float64(max(podAlloc, 1))), 10, 80, 90)},
	}
	if hasSSH {
		swap := "none"
		if ni.SwapTotal > 0 {
			swap = fmt.Sprintf("%s used of %s", humanBytes(float64(ni.SwapTotal-ni.SwapFree)), humanBytes(float64(ni.SwapTotal)))
		}
		capRows = append(capRows, []string{"swap", "-", "-", swap})
	}
	capRows = append(capRows, []string{"images (API)", "-", "-", fmt.Sprintf("%d cached on node", len(n.Status.Images))})
	table([]column{{title: "RESOURCE"}, {title: "ALLOCATABLE", right: true}, {title: "REQUESTED"}, {title: "USED"}}, capRows)

	if !hasSSH {
		return "Node " + name, out
	}

	// ---- security (runtime vs boot) ----
	if items := ni.HardeningItems(); len(items) > 0 {
		add("", styleTitle.Render("Security")+styleDim.Render("  runtime state vs boot configuration"))
		var rows [][]string
		for _, it := range items {
			state := styleOK.Render("ok")
			switch {
			case it.Mismatch:
				state = styleWarn.Render("MISMATCH: reboot changes state")
			case !it.OK:
				state = styleWarn.Render("not hardened")
			}
			rows = append(rows, []string{it.Name, it.Runtime, it.Boot, state, it.Detail})
		}
		table([]column{{title: "ITEM"}, {title: "RUNTIME"}, {title: "BOOT CONFIG"}, {title: "ASSESSMENT"}, {title: "DETAIL"}}, rows)
	}

	// ---- services ----
	add("", styleTitle.Render("Services"))
	{
		units := map[string]int{}
		for i, u := range ni.Units {
			units[u.Name] = i
		}
		var rows [][]string
		seen := map[string]bool{}
		for _, svc := range ni.Services {
			seen[svc.Name] = true
			restarts, started, result := "-", "-", ""
			if i, ok := units[svc.Name]; ok {
				u := ni.Units[i]
				restarts = fmt.Sprint(u.NRestarts)
				if u.NRestarts > 0 {
					restarts = styleWarn.Render(restarts)
				}
				if !u.Started.IsZero() {
					started = age(u.Started) + " ago"
				}
				result = u.Result
			}
			critical := svc.Name == "kubelet" || svc.Name == "containerd" || strings.HasPrefix(svc.Name, "rke2-") || strings.HasPrefix(svc.Name, "k3s") || svc.Name == "etcd"
			state := svc.Active + "/" + svc.Sub
			switch {
			case svc.Active == "active":
				state = styleOK.Render(state)
			case critical:
				state = styleCrit.Render(state)
			default:
				state = styleDim.Render(state)
			}
			rows = append(rows, []string{svc.Name, state, ni.ServiceEnabled(svc.Name), restarts, started, result})
		}
		for _, u := range ni.Units {
			if !seen[u.Name] {
				rows = append(rows, []string{u.Name, u.Active + "/" + u.Sub, "", fmt.Sprint(u.NRestarts), age(u.Started) + " ago", u.Result})
			}
		}
		table([]column{{title: "UNIT"}, {title: "STATE"}, {title: "BOOT"}, {title: "RESTARTS", right: true}, {title: "STARTED", right: true}, {title: "RESULT"}}, rows)
	}

	// ---- platform (rke2 / rancher) ----
	var plat [][]string
	if len(ni.Settings) > 0 {
		var kvs []string
		for _, k := range sortedKeys(ni.Settings) {
			kvs = append(kvs, k+"="+ni.Settings[k])
		}
		plat = append(plat, []string{"rke2 config", strings.Join(kvs, "  ")})
	}
	if ni.Rancher.SystemAgent != "" || ni.Rancher.Provisioned {
		plat = append(plat, []string{"rancher", fmt.Sprintf("system-agent=%s provisioned=%v url=%s plans=%d", strings.TrimSpace(ni.Rancher.SystemAgent), ni.Rancher.Provisioned, ni.Rancher.AgentURL, ni.Rancher.Plans)})
	}
	if len(ni.CNI) > 0 {
		var c []string
		for _, x := range ni.CNI {
			c = append(c, fmt.Sprintf("%s [%s]", x.Name, strings.Join(x.Types, ",")))
		}
		plat = append(plat, []string{"cni", strings.Join(c, "; ")})
	}
	if len(ni.RegistryMirrors) > 0 {
		plat = append(plat, []string{"registry mirrors", strings.Join(ni.RegistryMirrors, ", ") + styleDim.Render("  containerd hosts: "+strings.Join(ni.ContainerdHosts, ", "))})
	}
	if len(plat) > 0 {
		add("", styleTitle.Render("Platform")+styleDim.Render("  full config on the RKE2 and Addons tabs"))
		kvTable(plat)
	}

	// ---- filesystems ----
	add("", styleTitle.Render("Filesystems"))
	{
		var rows [][]string
		for _, m := range ni.Mounts {
			rows = append(rows, []string{m.Mountpoint, m.Filesystem, m.Type, humanKB(m.SizeKB), humanKB(m.UsedKB), humanKB(m.AvailKB), gauge(float64(m.UsePct), 14, thr.DiskWarnPct, thr.DiskCritPct), gauge(float64(m.InodePct), 8, thr.InodeWarnPct, 95)})
		}
		table([]column{{title: "MOUNT", max: 36}, {title: "DEVICE", max: 30}, {title: "TYPE"}, {title: "SIZE", right: true}, {title: "USED", right: true}, {title: "AVAIL", right: true}, {title: "USE"}, {title: "INODES"}}, rows)
		if len(ni.PVMounts) > 0 {
			add(styleDim.Render(fmt.Sprintf("  + %d pod volume mounts (PV usage on the Storage tab)", len(ni.PVMounts))))
		}
	}

	// ---- certificates ----
	if len(ni.Certs) > 0 {
		add("", styleTitle.Render("Certificates"))
		certs := append([]struct{}{}, nil...)
		_ = certs
		sorted := make([]int, len(ni.Certs))
		for i := range sorted {
			sorted[i] = i
		}
		sort.Slice(sorted, func(i, j int) bool { return ni.Certs[sorted[i]].NotAfter.Before(ni.Certs[sorted[j]].NotAfter) })
		var rows [][]string
		for _, i := range sorted {
			c := ni.Certs[i]
			left := time.Until(c.NotAfter)
			txt := fmt.Sprintf("%dd", int(left.Hours()/24))
			switch {
			case left <= 0:
				txt = styleCrit.Render("EXPIRED")
			case left < thr.CertExpiryWarn:
				txt = styleWarn.Render(txt)
			default:
				txt = styleOK.Render(txt)
			}
			rows = append(rows, []string{c.Path, c.NotAfter.Format("2006-01-02"), txt})
		}
		table([]column{{title: "FILE"}, {title: "EXPIRES"}, {title: "LEFT", right: true}}, rows)
	}

	// ---- sysctls ----
	if len(ni.Sysctl) > 0 {
		add("", styleTitle.Render("Kernel sysctls"))
		want := map[string]string{"vm.overcommit_memory": "1", "vm.panic_on_oom": "0", "kernel.panic": "10", "kernel.panic_on_oops": "1", "kernel.keys.root_maxbytes": "25000000", "kernel.keys.root_maxkeys": "1000000", "net.ipv4.ip_forward": "1", "net.bridge.bridge-nf-call-iptables": "1"}
		var rows [][]string
		for _, k := range sortedKeys(ni.Sysctl) {
			v := ni.Sysctl[k]
			exp := want[k]
			state := ""
			switch {
			case exp == "":
				state = styleDim.Render("-")
			case v == exp:
				state = styleOK.Render("ok")
			default:
				state = styleWarn.Render("expected " + exp)
			}
			rows = append(rows, []string{k, v, state})
		}
		table([]column{{title: "KEY"}, {title: "VALUE", right: true}, {title: "CIS / KUBELET EXPECTATION"}}, rows)
	}

	// ---- kubelet args ----
	if len(ni.KubeletFlags) > 0 {
		add("", styleTitle.Render("kubelet process args"))
		var rows [][]string
		for _, k := range sortedKeys(ni.KubeletFlags) {
			rows = append(rows, []string{"--" + k, trunc(ni.KubeletFlags[k], w-40)})
		}
		table([]column{{title: "FLAG"}, {title: "VALUE"}}, rows)
	}
	return "Node " + name, out
}

func nanIf(ok bool, v float64) float64 {
	if !ok {
		return nan()
	}
	return v
}
