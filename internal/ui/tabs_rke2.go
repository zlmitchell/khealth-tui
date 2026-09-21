package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/checks"
	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// settings that should normally agree across nodes of the same role
// driftKeysUpstream are the KubeletConfiguration fields (kubeadm / upstream
// nodes: /var/lib/kubelet/config.yaml) compared across nodes.
var driftKeysUpstream = []string{"cgroupDriver", "failSwapOn", "rotateCertificates", "serverTLSBootstrap", "protectKernelDefaults", "readOnlyPort", "staticPodPath", "maxPods", "containerRuntimeEndpoint", "tlsCipherSuites", "eventRecordQPS", "streamingConnectionIdleTimeout", "makeIPTablesUtilChains", "cloudProvider", "resolvConf", "kubeReserved", "systemReserved"}

var driftKeys = []string{"profile", "cni", "selinux", "secrets-encryption", "protect-kernel-defaults", "system-default-registry", "cluster-cidr", "service-cidr", "cluster-domain", "disable", "kube-apiserver-arg", "kubelet-arg", "etcd-snapshot-schedule-cron", "etcd-snapshot-retention", "data-dir", "write-kubeconfig-mode", "tls-san"}

// rke2Content renders the RKE2/k3s configuration tab.
func (a *App) rke2Content() content {
	s := a.snap
	dist := s.Distribution
	rancher := distro.IsRancher(dist)
	voc := distro.For(dist)
	keys := driftKeys
	if !rancher {
		keys = driftKeysUpstream
	}
	hdr := []string{styleTitle.Render(a.tabName(tabRKE2)+" configuration") + "  " + kv("distribution", dist) + "  " + kv("version", s.Version) + styleDim.Render("   enter = full "+voc.ConfigName+", manifests and static pod dumps for the node")}
	if st := a.tierStatus(tierConfig); st != "" {
		hdr = append(hdr, styleDim.Render("  "+st))
	}
	if !rancher {
		// upstream: the kubelet's KubeletConfiguration replaces config.yaml and
		// kubeadm-config carries the cluster-wide settings (certSANs, subnets)
		if kc := s.Kubeadm; kc != nil {
			hdr = append(hdr, kv("kubeadm ClusterConfiguration", fmt.Sprintf("clusterName=%s controlPlaneEndpoint=%s certSANs=[%s] serviceSubnet=%s kubernetesVersion=%s", kc.ClusterName, kc.ControlPlaneEndpoint, strings.Join(kc.CertSANs, ", "), kc.ServiceSubnet, kc.KubernetesVersion)))
			if kc.KubeletRaw != "" {
				hdr = append(hdr, kv("kube-system/kubelet-config", "cluster-wide KubeletConfiguration present (enter on a node shows the node's copy)"))
			}
		} else if dist == "kubeadm" {
			hdr = append(hdr, styleDim.Render("no kube-system/kubeadm-config ConfigMap: no RBAC to read it?"))
		}
	}
	if !a.sshEnabled {
		hdr = append(hdr, styleWarn.Render("SSH collection is off - "+voc.ConfigName+" and manifest directories need SSH."))
	}

	// drift: value sets per key across server nodes / agent nodes
	type valSet map[string]map[string]bool // key -> value -> seen
	servers, agents := valSet{}, valSet{}
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		vs := agents
		if ni.ControlPlane {
			vs = servers
		}
		for _, k := range keys {
			if vs[k] == nil {
				vs[k] = map[string]bool{}
			}
			v := ni.Settings[k]
			if k == "tls-san" { // block lists are empty in Settings; use the parsed list
				v = strings.Join(ni.TLSSAN, ",")
			}
			vs[k][v] = true
		}
	}
	var drift []string
	for _, k := range keys {
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
		hdr = append(hdr, styleOK.Render("no config drift across nodes for ")+styleDim.Render(strings.Join(keys[:8], ", ")+", ..."))
	}

	// API endpoint: what the kubeconfig uses vs what the serving certificate
	// allows vs what tls-san asks for
	hdr = append(hdr, a.endpointLines()...)

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
	if rancher {
		hdr = append(hdr, kv("bundled HelmCharts", fmt.Sprintf("%d (%d with HelmChartConfig overrides, %s)", len(s.HelmCharts), overrides, colorCount(failed, "failed", styleCrit)))+"  "+kv(voc.Name+" settings on nodes", "see table; Addons tab shows registries/CNI"))
	}

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
			user = styleWarn.Render(fmt.Sprintf("%d: %s", len(iso.UserPods), strutil.TruncList(iso.UserPods, 2)))
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
	if !rancher {
		// upstream / kubeadm: the kubelet settings that matter, from
		// /var/lib/kubelet/config.yaml on each node
		for i := range s.Nodes {
			n := &s.Nodes[i]
			ni := a.nodes[n.Name]
			role := "worker"
			if ni != nil && ni.ControlPlane {
				role = "control-plane"
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
			get := func(k, def string) string {
				if v := st[k]; v != "" {
					return v
				}
				return styleDim.Render(def)
			}
			rows = append(rows, []string{n.Name, role, get("cgroupDriver", "cgroupfs"), get("failSwapOn", "true"), get("rotateCertificates", "false"), get("protectKernelDefaults", "false"), get("readOnlyPort", "0"), get("maxPods", "110"), fmt.Sprint(len(ni.ConfigFiles)), fmt.Sprint(len(ni.StaticPods))})
			ids = append(ids, n.Name)
		}
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "ROLE"}, {title: "CGROUP DRIVER"}, {title: "FAIL SWAP ON"}, {title: "ROTATE CERTS"}, {title: "PROTECT KERNEL"}, {title: "READONLY PORT"}, {title: "MAX PODS"}, {title: "CFG FILES", right: true}, {title: "STATIC PODS", right: true}}, rows)
		hdr = append(hdr, h)
		c := content{header: hdr, selectable: true, empty: "no nodes"}
		for i, l := range lines {
			c.rows = append(c.rows, row{id: ids[i], text: l})
		}
		return c
	}
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

// rke2Detail dumps a node's rke2 configuration.
func (a *App) rke2Detail(node string) (string, []string) {
	ni := a.nodes[node]
	if ni == nil {
		return "", nil
	}
	voc := distro.For(ni.Dist)
	if ni.Dist == "" || ni.Dist == "unknown" {
		voc = distro.For(a.snap.Distribution)
	}
	title := voc.Label + " " + node
	if ni.Err != nil {
		return title, []string{styleCrit.Render("ssh error: " + ni.Err.Error())}
	}
	w := a.width - 6
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	role := "agent"
	if ni.ControlPlane {
		role = "server"
	}
	if !distro.IsRancher(voc.Name) {
		role = "worker"
		if ni.ControlPlane {
			role = "control-plane"
		}
	}
	add(kv("role", role) + "  " + kv("dist", ni.Dist) + "  " + kv("data-dir", ni.DataDir) + "  " + kv("collected", age(ni.Collected)+" ago"))
	var kvs []string
	for _, k := range strutil.SortedKeys(ni.Settings) {
		kvs = append(kvs, k+"="+ni.Settings[k])
	}
	add(wrap("effective top-level settings: "+strings.Join(kvs, "  "), w)...)

	add("", styleTitle.Render("Configuration files (secrets masked)"))
	if len(ni.ConfigFiles) == 0 {
		add(styleDim.Render("  no " + voc.ConfigFile + " (config tier not collected yet, or the file is absent)"))
	}
	for _, f := range ni.ConfigFiles {
		add(styleBold.Render("--- " + f.Path))
		add(fileLines(f.Path, f.Content, w)...)
	}
	for _, f := range ni.ExtraFiles {
		add(styleBold.Render("--- " + f.Path))
		add(fileLines(f.Path, f.Content, w)...)
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
			add(fileLines(m.Path, m.Content, w)...)
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
		for _, k := range strutil.SortedKeys(ni.KubeletFlags) {
			flags = append(flags, "--"+k+"="+ni.KubeletFlags[k])
		}
		add("", styleTitle.Render("kubelet process args"))
		add(wrap(strings.Join(flags, " "), w)...)
	}
	if kc := a.snap.Kubeadm; kc != nil && !distro.IsRancher(voc.Name) {
		if kc.Raw != "" {
			add("", styleTitle.Render("kube-system/kubeadm-config ClusterConfiguration")+styleDim.Render("  cluster-wide; the same on every node"))
			add(yamlLines(kc.Raw, w)...)
		}
		if kc.KubeletRaw != "" {
			add("", styleTitle.Render("kube-system/kubelet-config KubeletConfiguration")+styleDim.Render("  cluster default; compare with /var/lib/kubelet/config.yaml above"))
			add(yamlLines(kc.KubeletRaw, w)...)
		}
	}
	return title, out
}

// endpointLines renders the API endpoint section of the RKE2 tab: the
// kubeconfig server, whether it is a VIP or a single node, and per server
// the tls-san config against the serving certificate's SANs.
func (a *App) endpointLines() []string {
	rep := checks.Endpoint(a.apiServer(), a.snap.Nodes, a.nodes, a.snap.Kubeadm)
	dist := a.snap.Distribution
	sanKey := checks.SANKey(dist)
	certName := "serving-kube-apiserver.crt"
	if dist == "kubeadm" {
		certName = "pki/apiserver.crt"
	}
	out := []string{"", styleTitle.Render("API endpoint") + styleDim.Render("  kubeconfig server vs "+sanKey+" vs "+certName+" SANs; an entry missing from the cert needs the certificate reissued: "+checks.ReissueHint(dist))}
	ep := styleDim.Render("unknown")
	if rep.Host != "" {
		ep = styleBold.Render(rep.Host)
		switch {
		case rep.IsNode != "":
			ep += "  " + styleWarn.Render("single server node ("+rep.IsNode+")")
		default:
			ep += "  " + styleOK.Render("VIP / load balancer / external name")
		}
	}
	out = append(out, kv("kubeconfig server", ep))
	if len(rep.Servers) == 0 {
		out = append(out, styleDim.Render("  no server node has reported config.yaml and the serving certificate yet (SSH config tier)"))
		return out
	}
	var rows [][]string
	for _, s := range rep.Servers {
		tls := styleDim.Render("(none: only node IPs / in-cluster names)")
		if len(s.TLSSAN) > 0 {
			tls = strings.Join(s.TLSSAN, ", ")
		}
		cert := styleDim.Render("no cert read")
		if s.HasCert {
			cert = strings.Join(s.CertSANs, ", ")
		}
		missing := styleOK.Render("ok")
		if len(s.Missing) > 0 {
			missing = styleWarn.Render("missing: " + strings.Join(s.Missing, ", ") + " (reissue cert)")
		} else if !s.HasCert {
			missing = styleDim.Render("-")
		}
		host := styleDim.Render("-")
		if rep.Host != "" && s.HasCert {
			host = okText(s.HostOK, "in cert", "NOT in cert")
		}
		rows = append(rows, []string{s.Node, tls, cert, missing, host})
	}
	cfgCol := "TLS-SAN (config.yaml)"
	if dist == "kubeadm" {
		cfgCol = "CERTSANS + CP ENDPOINT (kubeadm-config)"
	}
	h, lines := renderTable(a.width, []column{{title: "SERVER"}, {title: cfgCol, max: 40}, {title: "CERT SANS (external)", max: 50}, {title: "CERT vs CONFIG"}, {title: "KUBECONFIG HOST"}}, rows)
	out = append(out, h)
	out = append(out, lines...)
	return out
}
