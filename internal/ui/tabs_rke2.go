package ui

import (
	"fmt"
	"sort"
	"strings"

	"k8s-health-tui/internal/nodeinfo"
)

// settings that should normally agree across nodes of the same role
var driftKeys = []string{"profile", "cni", "selinux", "secrets-encryption", "protect-kernel-defaults", "system-default-registry", "cluster-cidr", "service-cidr", "cluster-domain", "disable", "kube-apiserver-arg", "kubelet-arg", "etcd-snapshot-schedule-cron", "etcd-snapshot-retention", "data-dir", "write-kubeconfig-mode", "tls-san"}

// rke2Content renders the RKE2/k3s configuration tab.
func (a *App) rke2Content() content {
	s := a.snap
	dist := s.Distribution
	hdr := []string{styleTitle.Render("RKE2 / k3s configuration") + "  " + kv("distribution", dist) + "  " + kv("version", s.Version) + styleDim.Render("   enter = full config.yaml, manifests and static pod dumps for the node")}
	if dist != "rke2" && dist != "k3s" {
		return content{header: hdr, empty: "cluster does not look like rke2/k3s (no rke2/k3s node annotations)"}
	}
	if !a.sshEnabled {
		hdr = append(hdr, styleWarn.Render("SSH collection is off - config.yaml and manifest directories need SSH."))
	}

	// drift: value sets per key across server nodes / agent nodes
	type valSet map[string]map[string]bool // key -> value -> seen
	servers, agents := valSet{}, valSet{}
	for _, n := range sortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		vs := agents
		if ni.ControlPlane {
			vs = servers
		}
		for _, k := range driftKeys {
			if vs[k] == nil {
				vs[k] = map[string]bool{}
			}
			vs[k][ni.Settings[k]] = true
		}
	}
	var drift []string
	for _, k := range driftKeys {
		if len(servers[k]) > 1 {
			drift = append(drift, "servers:"+k)
		}
		if len(agents[k]) > 1 {
			drift = append(drift, "agents:"+k)
		}
	}
	if len(drift) > 0 {
		hdr = append(hdr, styleWarn.Render("config drift between nodes: ")+strings.Join(drift, ", "))
	} else if len(a.nodes) > 1 {
		hdr = append(hdr, styleOK.Render("no config drift across nodes for ")+styleDim.Render(strings.Join(driftKeys[:8], ", ")+", ..."))
	}

	// cluster-side bundled charts
	overrides := 0
	failed := 0
	for _, hc := range s.HelmCharts {
		if hc.HasConfig {
			overrides++
		}
		if hc.Failed {
			failed++
		}
	}
	hdr = append(hdr, kv("bundled HelmCharts", fmt.Sprintf("%d (%d with HelmChartConfig overrides, %s)", len(s.HelmCharts), overrides, colorCount(failed, "failed", styleCrit)))+"  "+kv("rke2 settings on nodes", "see table; Addons tab shows registries/CNI"))

	hdr = append(hdr, "", styleTitle.Render("Control-plane isolation")+styleDim.Render("  user pods = non-system namespaces excluding DaemonSets; CP requests = requests set on apiserver/etcd/scheduler/controller static pods"))
	var isoRows [][]string
	for _, iso := range s.ControlPlaneIsolation() {
		taint := styleWarn.Render("none (schedulable)")
		if iso.Protected {
			taint = styleOK.Render(strings.Join(iso.Taints, " "))
		} else if len(iso.Taints) > 0 {
			taint = styleWarn.Render(strings.Join(iso.Taints, " "))
		}
		user := styleOK.Render("0")
		if len(iso.UserPods) > 0 {
			user = styleWarn.Render(fmt.Sprintf("%d: %s", len(iso.UserPods), truncJoin(iso.UserPods, 2)))
		}
		req := styleDim.Render("-")
		if iso.AllocCPU > 0 {
			req = gauge(float64(iso.AllCPUReq)*100/float64(iso.AllocCPU), 6, 60, 85) + styleDim.Render(" cpu ") + gauge(float64(iso.AllMemReq)*100/float64(max(iso.AllocMem, 1)), 6, 60, 85) + styleDim.Render(" mem")
		}
		var comps []string
		for _, c := range []string{"kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"} {
			r, ok := iso.CPComponents[c]
			if !ok {
				continue
			}
			short := strings.TrimPrefix(c, "kube-")
			if r.Set {
				comps = append(comps, styleOK.Render(fmt.Sprintf("%s %dm/%s", short, r.CPUMilli, humanBytes(float64(r.MemBytes)))))
			} else {
				comps = append(comps, styleWarn.Render(short+" none"))
			}
		}
		isoRows = append(isoRows, []string{iso.Node, strings.Join(iso.Roles, ","), taint, user, req, strings.Join(comps, " ")})
	}
	if len(isoRows) > 0 {
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "ROLES"}, {title: "TAINTS", max: 40}, {title: "USER PODS", max: 50}, {title: "REQUESTED OF ALLOCATABLE"}, {title: "CP STATIC POD REQUESTS"}}, isoRows)
		hdr = append(hdr, h)
		hdr = append(hdr, lines...)
	}
	hdr = append(hdr, "", styleTitle.Render("Nodes"))

	var rows [][]string
	var ids []string
	for i := range s.Nodes {
		n := &s.Nodes[i]
		ni := a.nodes[n.Name]
		role := "agent"
		if ni != nil && ni.ControlPlane {
			role = "server"
		}
		if ni == nil || ni.Err != nil {
			state := styleDim.Render("no ssh data")
			if ni != nil {
				state = styleCrit.Render("ssh error")
			}
			rows = append(rows, []string{n.Name, role, state})
			ids = append(ids, n.Name)
			continue
		}
		st := ni.Settings
		profile := st["profile"]
		if profile == "" {
			profile = styleDim.Render("-")
		}
		cni := st["cni"]
		if cni == "" {
			cni = styleDim.Render("canal (default)")
		}
		files := fmt.Sprint(len(ni.ConfigFiles))
		user, bundled := 0, 0
		for _, m := range ni.Manifests {
			if m.Bundled {
				bundled++
			} else {
				user++
			}
		}
		manifests := styleDim.Render("-")
		if ni.ControlPlane {
			manifests = fmt.Sprintf("%d user, %d bundled", user, bundled)
			if user > 0 {
				manifests = styleInfo.Render(fmt.Sprintf("%d user", user)) + fmt.Sprintf(", %d bundled", bundled)
			}
		}
		dd := ni.DataDir
		if dd == "" {
			dd = styleDim.Render("default")
		}
		sec := st["secrets-encryption"]
		if sec == "" {
			sec = styleDim.Render("-")
		}
		dis := st["disable"]
		rows = append(rows, []string{n.Name, role, dd, profile, cni, st["server"], sec, dis, files, manifests, fmt.Sprint(len(ni.StaticPods))})
		ids = append(ids, n.Name)
	}
	h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "ROLE"}, {title: "DATA-DIR", max: 28}, {title: "PROFILE"}, {title: "CNI"}, {title: "SERVER", max: 32}, {title: "SECRETS-ENC"}, {title: "DISABLE", max: 30}, {title: "CFG FILES", right: true}, {title: "MANIFESTS"}, {title: "STATIC PODS", right: true}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no nodes"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

func truncJoin(l []string, n int) string {
	if len(l) <= n {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:n], ", ") + fmt.Sprintf(" +%d", len(l)-n)
}

// rke2Detail dumps a node's rke2 configuration.
func (a *App) rke2Detail(node string) (string, []string) {
	ni := a.nodes[node]
	if ni == nil {
		return "", nil
	}
	if ni.Err != nil {
		return "RKE2 " + node, []string{styleCrit.Render("ssh error: " + ni.Err.Error())}
	}
	w := a.width - 6
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	role := "agent"
	if ni.ControlPlane {
		role = "server"
	}
	add(kv("role", role) + "  " + kv("dist", ni.Dist) + "  " + kv("data-dir", ni.DataDir) + "  " + kv("collected", age(ni.Collected)+" ago"))
	var kvs []string
	for _, k := range sortedKeys(ni.Settings) {
		kvs = append(kvs, k+"="+ni.Settings[k])
	}
	add(wrap("effective top-level settings: "+strings.Join(kvs, "  "), w)...)

	add("", styleTitle.Render("Configuration files (secrets masked)"))
	if len(ni.ConfigFiles) == 0 {
		add(styleDim.Render("  no /etc/rancher/{rke2,k3s}/config.yaml"))
	}
	for _, f := range ni.ConfigFiles {
		add(styleBold.Render("--- " + f.Path))
		for _, l := range strings.Split(f.Content, "\n") {
			add(wrap(l, w)...)
		}
	}
	for _, f := range ni.ExtraFiles {
		add(styleBold.Render("--- " + f.Path))
		for _, l := range strings.Split(f.Content, "\n") {
			add(wrap(l, w)...)
		}
	}

	if len(ni.Manifests) > 0 {
		add("", styleTitle.Render("server/manifests (auto-deploying manifests dir)"))
		sorted := append([]nodeinfo.ManifestFile{}, ni.Manifests...)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Bundled != sorted[j].Bundled && !sorted[i].Bundled || (sorted[i].Bundled == sorted[j].Bundled && sorted[i].Path < sorted[j].Path)
		})
		var rows [][]string
		for _, m := range sorted {
			kind := "user"
			if m.Bundled {
				kind = styleDim.Render("bundled")
			} else {
				kind = styleInfo.Render("user")
			}
			rows = append(rows, []string{shortPath(m.Path), kind, humanBytes(float64(m.Size)), age(m.ModTime), m.Kinds})
		}
		h, lines := renderTable(w, []column{{title: "FILE"}, {title: "ORIGIN"}, {title: "SIZE", right: true}, {title: "MODIFIED", right: true}, {title: "KINDS"}}, rows)
		add(h)
		add(lines...)
		for _, m := range sorted {
			if m.Bundled || m.Content == "" {
				continue
			}
			add("", styleBold.Render("--- "+m.Path))
			for _, l := range strings.Split(m.Content, "\n") {
				add(wrap(l, w)...)
			}
		}
	} else if ni.ControlPlane {
		add("", styleDim.Render("server/manifests: no files found"))
	}

	if len(ni.StaticPods) > 0 {
		add("", styleTitle.Render("Static pod manifests (images and args)"))
		for _, m := range ni.StaticPods {
			add(styleBold.Render("--- "+m.Path) + "  " + styleDim.Render(humanBytes(float64(m.Size))+", modified "+age(m.ModTime)+" ago"))
			for _, l := range strings.Split(m.Content, "\n") {
				if strings.TrimSpace(l) != "" {
					add("  " + trunc(l, w-2))
				}
			}
		}
	}
	if len(ni.KubeletFlags) > 0 {
		var flags []string
		for _, k := range sortedKeys(ni.KubeletFlags) {
			flags = append(flags, "--"+k+"="+ni.KubeletFlags[k])
		}
		add("", styleTitle.Render("kubelet process args"))
		add(wrap(strings.Join(flags, " "), w)...)
	}
	return "RKE2 " + node, out
}
