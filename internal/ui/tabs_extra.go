package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s-health-tui/internal/helmcheck"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/logs"
	"k8s-health-tui/internal/stig"
)

// ---------- etcd ----------

func (a *App) etcdContent() content {
	s := a.snap
	thr := a.cfg.Thresholds
	var out []string
	add := func(l ...string) { out = append(out, l...) }

	etcdNodes := 0
	for i := range s.Nodes {
		if k8s.IsEtcdNode(s.Nodes, &s.Nodes[i]) {
			etcdNodes++
		}
	}
	add(styleTitle.Render("etcd") + "  " + kv("distribution", s.Distribution) + "  " + kv("etcd nodes", fmt.Sprint(etcdNodes)) + "  " + kv("probes", fmt.Sprintf("%d done, %d pending", len(a.etcd), len(a.etcdPend))) + styleDim.Render("   enter = full config dumps"))
	if !a.sshEnabled {
		add(styleWarn.Render("SSH collection is off - etcd internals need SSH to the control-plane nodes. API-side view only."))
	}
	for _, c := range s.Readyz {
		if strings.HasPrefix(c.Name, "etcd") {
			add(kv("apiserver readyz "+c.Name, okText(c.OK, "ok", "FAILED "+c.Detail)))
		}
	}

	// members (from any probe that has them)
	var memberProbe string
	for _, n := range sortedKeys(a.etcd) {
		if len(a.etcd[n].Members) > 0 {
			memberProbe = n
			break
		}
	}
	add("", styleTitle.Render("Members"))
	if memberProbe == "" {
		add(styleDim.Render("  no member list (etcdctl unavailable on probed nodes - needs crictl access to the etcd container or etcdctl on the host)"))
	} else {
		p := a.etcd[memberProbe]
		var rows [][]string
		for _, m := range p.Members {
			st := p.Status(m.ID)
			ver, db, inuse, leader, term, idx, errs := "-", "-", "-", "", "-", "-", ""
			if st != nil {
				ver = st.Version
				db = humanBytes(float64(st.DBSize))
				if st.DBSizeInUse > 0 {
					inuse = humanBytes(float64(st.DBSizeInUse))
				}
				if st.Leader == st.MemberID {
					leader = styleOK.Render("leader")
				}
				term = fmt.Sprint(st.RaftTerm)
				idx = fmt.Sprint(st.RaftIndex)
				if len(st.Errors) > 0 {
					errs = styleCrit.Render(strings.Join(st.Errors, "; "))
				}
			}
			learner := ""
			if m.IsLearner {
				learner = styleWarn.Render("learner")
			}
			rows = append(rows, []string{m.ID, m.Name, strings.Join(m.PeerURLs, ","), ver, db, inuse, leader, term, idx, learner, errs})
		}
		h, lines := renderTable(a.width, []column{{title: "ID"}, {title: "NAME"}, {title: "PEER URL", max: 40}, {title: "VERSION"}, {title: "DB", right: true}, {title: "IN USE", right: true}, {title: "ROLE"}, {title: "TERM", right: true}, {title: "INDEX", right: true}, {title: ""}, {title: "ERRORS"}}, rows)
		add(h)
		add(lines...)
		add(styleDim.Render(fmt.Sprintf("  via %s on %s", p.EtcdctlVia, memberProbe)))
		alarms := "none"
		if len(p.Alarms) > 0 {
			var al []string
			for _, x := range p.Alarms {
				al = append(al, x.Type+"@"+x.MemberID)
			}
			alarms = styleCrit.Render(strings.Join(al, " "))
		}
		add(kv("alarms", alarms))
	}

	add("", styleTitle.Render("Per-node health")+styleDim.Render("  (curl /health and /metrics with the node's client certs)"))
	var rows [][]string
	for _, n := range sortedKeys(a.etcd) {
		p := a.etcd[n]
		if p.Err != nil {
			rows = append(rows, []string{n, styleCrit.Render("probe error: " + firstLine(p.Err.Error()))})
			continue
		}
		health := styleDim.Render("-")
		if p.Health != nil {
			health = okText(p.Health.Healthy, "healthy", "UNHEALTHY "+firstLine(p.Health.Reason))
		}
		leader, db, frag, fsync, commit, changes, pend, ver, fs := "-", "-", "-", "-", "-", "-", "-", "-", "-"
		if m := p.Metrics; m != nil {
			leader = okText(m.HasLeader, map[bool]string{true: "yes*", false: "yes"}[m.IsLeader], "NO LEADER")
			if m.Quota > 0 {
				pct := m.DBSize / m.Quota * 100
				db = pctStyle(pct, thr.EtcdDBWarnPct, 95).Render(fmt.Sprintf("%s/%s (%.0f%%)", humanBytes(m.DBSize), humanBytes(m.Quota), pct))
			} else {
				db = humanBytes(m.DBSize)
			}
			if m.DBSize > 0 && m.DBSizeInUse > 0 {
				f := (m.DBSize - m.DBSizeInUse) / m.DBSize * 100
				frag = pctStyle(f, thr.EtcdFragWarnPct, 80).Render(fmt.Sprintf("%.0f%%", f))
			}
			fsync = pctStyle(m.WalFsyncAvgMs, int(thr.EtcdFsyncWarnMs), int(thr.EtcdFsyncWarnMs*3)).Render(fmt.Sprintf("%.1fms", m.WalFsyncAvgMs))
			commit = pctStyle(m.BackendCommitAvgMs, 25, 100).Render(fmt.Sprintf("%.1fms", m.BackendCommitAvgMs))
			changes = fmt.Sprintf("%.0f", m.LeaderChanges)
			pend = fmt.Sprintf("%.0f/%.0f", m.ProposalsPending, m.ProposalsFailed)
			ver = m.ServerVersion
		}
		if p.DataDirFS != nil {
			fs = pctText(float64(p.DataDirFS.UsePct), thr.DiskWarnPct, thr.DiskCritPct) + styleDim.Render(" "+p.DataDirFS.Mount)
			if p.DataDirUsedKB > 0 {
				fs += styleDim.Render(" dir=" + humanKB(p.DataDirUsedKB))
			}
		}
		rows = append(rows, []string{n, p.Dist, health, leader, db, frag, fsync, commit, changes, pend, ver, fs})
	}
	for n := range a.etcdPend {
		if _, ok := a.etcd[n]; !ok {
			rows = append(rows, []string{n, styleDim.Render("probing...")})
		}
	}
	if len(rows) == 0 {
		add(styleDim.Render("  no probes yet"))
	} else {
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "DIST"}, {title: "HEALTH"}, {title: "LEADER"}, {title: "DB / QUOTA"}, {title: "FRAG", right: true}, {title: "FSYNC", right: true}, {title: "COMMIT", right: true}, {title: "LDR CHG", right: true}, {title: "PEND/FAIL", right: true}, {title: "VERSION"}, {title: "DATA DIR FS"}}, rows)
		add(h)
		add(lines...)
		add(styleDim.Render("  yes* = this member is the leader; FRAG = allocated but unused db space (defrag reclaims); FSYNC/COMMIT = average disk latency since start"))
	}

	add("", styleTitle.Render("Configuration source"))
	for _, n := range sortedKeys(a.etcd) {
		p := a.etcd[n]
		if p.Err != nil {
			continue
		}
		add(styleBold.Render(n) + "  " + kv("dist", p.Dist) + "  " + kv("endpoint", p.Endpoint) + "  " + kv("data dir", p.DataDir))
		if len(p.Sources) == 0 {
			add(styleDim.Render("  no etcd configuration found on this node"))
		}
		for _, src := range p.Sources {
			add("  " + src)
		}
		add("  " + kv("certs", fmt.Sprintf("ca=%s cert=%s", p.CA, p.Cert)))
		if len(p.RKE2Config) > 0 {
			var kvs []string
			for _, k := range sortedKeys(p.RKE2Config) {
				kvs = append(kvs, k+"="+p.RKE2Config[k])
			}
			add(wrap("  rke2 etcd settings: "+strings.Join(kvs, " "), a.width-2)...)
		} else if p.Dist == "rke2" {
			add(styleDim.Render("  no etcd-* keys in config.yaml: rke2 defaults apply (snapshots every 12h, retention 5, local dir)"))
		}
	}

	add("", styleTitle.Render("Backups / snapshots"))
	if len(s.RKE2Snapshots) > 0 {
		latest := s.RKE2Snapshots[0]
		ok, failed, s3n := 0, 0, 0
		for _, r := range s.RKE2Snapshots {
			switch r.Status {
			case "failed":
				failed++
			default:
				ok++
			}
			if r.S3 {
				s3n++
			}
		}
		ageTxt := age(latest.Created) + " ago"
		if time.Since(latest.Created) > a.cfg.Etcd.MaxBackupAge {
			ageTxt = styleWarn.Render(ageTxt)
		} else {
			ageTxt = styleOK.Render(ageTxt)
		}
		add(kv("cluster records", fmt.Sprintf("%d (%d ok, %s, %d on S3) via %s", len(s.RKE2Snapshots), ok, colorCount(failed, "failed", styleCrit), s3n, latest.Source)))
		add(kv("latest", fmt.Sprintf("%s on %s, %s, %s, %s", latest.Name, latest.Node, ageTxt, humanBytes(float64(latest.Size)), map[bool]string{true: "s3", false: "local"}[latest.S3])))
		var rows [][]string
		for i, r := range s.RKE2Snapshots {
			if i >= 8 {
				add(styleDim.Render(fmt.Sprintf("  ... %d more", len(s.RKE2Snapshots)-8)))
				break
			}
			st := okText(r.Status != "failed", r.Status, r.Status+" "+firstLine(r.Message))
			loc := "local"
			if r.S3 {
				loc = "s3"
			}
			rows = append(rows, []string{r.Name, r.Node, age(r.Created), humanBytes(float64(r.Size)), loc, st})
		}
		h, lines := renderTable(a.width, []column{{title: "SNAPSHOT", max: 60}, {title: "NODE"}, {title: "AGE", right: true}, {title: "SIZE", right: true}, {title: "WHERE"}, {title: "STATUS"}}, rows)
		add(h)
		add(lines...)
	} else if s.Distribution == "rke2" || s.Distribution == "k3s" {
		add(styleWarn.Render("  no ETCDSnapshotFile objects / rke2-etcd-snapshots configmap entries found"))
	}
	if a.s3 != nil {
		if a.s3.Found {
			add(kv("S3 secret "+a.s3.Name, fmt.Sprintf("endpoint=%s bucket=%s folder=%s region=%s credentials=%s", a.s3.Endpoint, a.s3.Bucket, a.s3.Folder, a.s3.Region, okText(a.s3.HasCredentials, "set", "missing"))))
		} else {
			add(kv("S3 secret "+a.s3.Name, styleCrit.Render("not found: "+a.s3.Err)))
		}
	}
	var rows2 [][]string
	for _, n := range sortedKeys(a.etcd) {
		p := a.etcd[n]
		for _, d := range p.SnapshotDirs {
			if len(d.Files) == 0 {
				rows2 = append(rows2, []string{n, d.Path, "0", styleDim.Render("empty"), ""})
				continue
			}
			f := d.Files[0]
			ageTxt := age(f.ModTime) + " ago"
			if time.Since(f.ModTime) > a.cfg.Etcd.MaxBackupAge {
				ageTxt = styleWarn.Render(ageTxt)
			} else {
				ageTxt = styleOK.Render(ageTxt)
			}
			var total int64
			for _, x := range d.Files {
				total += x.Size
			}
			rows2 = append(rows2, []string{n, d.Path, fmt.Sprint(len(d.Files)), ageTxt + " " + f.Name, humanBytes(float64(total))})
		}
	}
	if len(rows2) > 0 {
		add(kv("local snapshot files", ""))
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "DIRECTORY", max: 50}, {title: "N", right: true}, {title: "LATEST", max: 70}, {title: "TOTAL", right: true}}, rows2)
		add(h)
		add(lines...)
	}
	var hints []string
	for _, n := range sortedKeys(a.etcd) {
		for _, hnt := range a.etcd[n].BackupHints {
			hints = append(hints, n+": "+hnt)
		}
	}
	for i := range s.CronJobs {
		if strings.Contains(strings.ToLower(s.CronJobs[i].Name), "etcd") {
			c := &s.CronJobs[i]
			last := "never"
			if c.Status.LastSuccessfulTime != nil {
				last = age(c.Status.LastSuccessfulTime.Time) + " ago"
			}
			hints = append(hints, fmt.Sprintf("CronJob %s/%s schedule=%s last success=%s", c.Namespace, c.Name, c.Spec.Schedule, last))
		}
	}
	if len(hints) > 0 {
		add(kv("other backup mechanisms", ""))
		for _, hnt := range hints {
			add("  " + hnt)
		}
	}
	if len(a.cfg.Etcd.BackupDirs) > 0 {
		add(styleDim.Render("  extra dirs scanned: " + strings.Join(a.cfg.Etcd.BackupDirs, " ")))
	}
	return linesContent(out)
}

func (a *App) etcdDetail() (string, []string) {
	var out []string
	w := a.width - 6
	for _, n := range sortedKeys(a.etcd) {
		p := a.etcd[n]
		out = append(out, styleTitle.Render("== "+n+" ==")+"  "+kv("dist", p.Dist)+"  "+kv("collected", age(p.Collected)+" ago"))
		if p.Err != nil {
			out = append(out, styleCrit.Render(p.Err.Error()))
		}
		for _, src := range p.Sources {
			out = append(out, "  "+src)
		}
		if p.Health != nil {
			out = append(out, kv("health raw", p.Health.Raw))
		}
		for _, cf := range p.ConfigDump {
			out = append(out, "", styleBold.Render("--- "+cf.Path))
			for _, l := range strings.Split(cf.Content, "\n") {
				out = append(out, wrap(l, w)...)
			}
		}
		if p.EtcdctlOut != "" {
			out = append(out, "", styleBold.Render("--- etcdctl"))
			lines := strings.Split(p.EtcdctlOut, "\n")
			if len(lines) > 60 {
				lines = lines[:60]
			}
			for _, l := range lines {
				out = append(out, trunc(l, w))
			}
		}
		out = append(out, "")
	}
	if len(out) == 0 {
		out = append(out, styleDim.Render("no etcd probes"))
	}
	return "etcd configuration dumps", out
}

// ---------- Addons ----------

func (a *App) addonsContent() content {
	s := a.snap
	var out []string
	add := func(l ...string) { out = append(out, l...) }

	// CNI
	cni := detectCNI(s)
	add(styleTitle.Render("CNI") + "  " + kv("detected from daemonsets", cni))
	for _, n := range sortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		var parts []string
		if v := ni.Settings["cni"]; v != "" {
			parts = append(parts, "config cni="+v)
		}
		for _, c := range ni.CNI {
			parts = append(parts, fmt.Sprintf("%s: %s [%s]", shortPath(c.Path), c.Name, strings.Join(c.Types, ",")))
		}
		if len(parts) == 0 {
			parts = append(parts, styleWarn.Render("no CNI config in /etc/cni/net.d"))
		}
		add("  " + styleBold.Render(n) + "  " + strings.Join(parts, "  "))
	}

	// CSI
	add("", styleTitle.Render("CSI"))
	if len(s.CSIDrivers) == 0 {
		add(styleDim.Render("  no CSIDriver objects"))
	}
	nodesPer := map[string]int{}
	for i := range s.CSINodes {
		for _, d := range s.CSINodes[i].Spec.Drivers {
			nodesPer[d.Name]++
		}
	}
	for i := range s.CSIDrivers {
		d := s.CSIDrivers[i].Name
		var scs []string
		for j := range s.StorageClasses {
			if s.StorageClasses[j].Provisioner == d {
				scs = append(scs, s.StorageClasses[j].Name)
			}
		}
		add(fmt.Sprintf("  %s  %s  %s", styleBold.Render(d), kv("nodes", fmt.Sprintf("%d/%d", nodesPer[d], len(s.Nodes))), kv("storageclasses", strings.Join(scs, ","))))
	}

	// system add-ons
	add("", styleTitle.Render("System add-ons"))
	for _, want := range []struct{ label, ns, name, kind string }{
		{"CoreDNS", "kube-system", "rke2-coredns-rke2-coredns", "deploy"}, {"CoreDNS", "kube-system", "coredns", "deploy"},
		{"Ingress", "kube-system", "rke2-ingress-nginx-controller", "ds"}, {"Ingress", "ingress-nginx", "ingress-nginx-controller", "deploy"}, {"Ingress", "kube-system", "traefik", "deploy"},
		{"metrics-server", "kube-system", "rke2-metrics-server", "deploy"}, {"metrics-server", "kube-system", "metrics-server", "deploy"},
		{"Snapshot controller", "kube-system", "rke2-snapshot-controller", "deploy"}, {"Snapshot controller", "kube-system", "snapshot-controller", "deploy"},
		{"Longhorn", "longhorn-system", "longhorn-manager", "ds"}, {"cert-manager", "cert-manager", "cert-manager", "deploy"},
		{"Rancher webhook", "cattle-system", "rancher-webhook", "deploy"}, {"kube-proxy", "kube-system", "kube-proxy", "ds"},
		{"CIS operator", "cis-operator-system", "cis-operator", "deploy"}, {"Prometheus operator", "cattle-monitoring-system", "rancher-monitoring-operator", "deploy"},
		{"NeuVector", "cattle-neuvector-system", "neuvector-controller-pod", "deploy"}, {"Kyverno", "kyverno", "kyverno-admission-controller", "deploy"},
		{"Velero", "velero", "velero", "deploy"}, {"MetalLB", "metallb-system", "metallb-controller", "deploy"},
	} {
		var status string
		found := false
		if want.kind == "deploy" {
			for i := range s.Deployments {
				d := &s.Deployments[i]
				if d.Namespace == want.ns && d.Name == want.name {
					found = true
					status = okText(d.Status.ReadyReplicas == d.Status.Replicas && d.Status.Replicas > 0, fmt.Sprintf("%d/%d", d.Status.ReadyReplicas, d.Status.Replicas), fmt.Sprintf("%d/%d", d.Status.ReadyReplicas, d.Status.Replicas))
					if len(d.Spec.Template.Spec.Containers) > 0 {
						status += styleDim.Render("  " + d.Spec.Template.Spec.Containers[0].Image)
					}
				}
			}
		} else {
			for i := range s.DaemonSets {
				d := &s.DaemonSets[i]
				if d.Namespace == want.ns && d.Name == want.name {
					found = true
					status = okText(d.Status.NumberReady == d.Status.DesiredNumberScheduled, fmt.Sprintf("%d/%d", d.Status.NumberReady, d.Status.DesiredNumberScheduled), fmt.Sprintf("%d/%d", d.Status.NumberReady, d.Status.DesiredNumberScheduled))
					if len(d.Spec.Template.Spec.Containers) > 0 {
						status += styleDim.Render("  " + d.Spec.Template.Spec.Containers[0].Image)
					}
				}
			}
		}
		if found {
			add(fmt.Sprintf("  %-20s %s/%s  %s", want.label, want.ns, want.name, status))
		}
	}

	// Rancher
	add("", styleTitle.Render("Rancher management"))
	if r := s.Rancher; r == nil {
		add(styleDim.Render("  could not query cattle-system"))
	} else if !r.Managed {
		if r.Provisioning != "" {
			add("  " + r.Provisioning)
		} else {
			add(styleDim.Render("  not managed by Rancher (no cattle-cluster-agent)"))
		}
	} else {
		add("  " + kv("management server", styleBold.Render(r.Server)) + "  " + kv("cattle-cluster-agent", okText(r.ClusterAgentOK, r.ClusterAgent, r.ClusterAgent)))
		if r.FleetAgentOK != nil {
			add("  " + kv("fleet-agent", okText(*r.FleetAgentOK, "ready", "not ready")+" in "+r.FleetNamespace))
		}
		if r.SystemUpgradeOK != nil {
			add("  " + kv("system-upgrade-controller", okText(*r.SystemUpgradeOK, "ready", "not ready")))
		}
		var env []string
		for _, k := range sortedKeys(r.Env) {
			if k == "CATTLE_SERVER" {
				continue
			}
			env = append(env, k+"="+r.Env[k])
		}
		add(wrap("  agent env: "+strings.Join(env, " "), a.width-2)...)
		prov := 0
		for _, n := range sortedKeys(a.nodes) {
			ni := a.nodes[n]
			if ni.Err == nil && ni.Rancher.Provisioned {
				prov++
			}
		}
		if len(a.nodes) > 0 {
			kind := "imported/custom (no 50-rancher.yaml on nodes)"
			if prov == len(a.nodes) {
				kind = "Rancher-provisioned (config.yaml.d/50-rancher.yaml on all nodes)"
			} else if prov > 0 {
				kind = fmt.Sprintf("mixed: %d/%d nodes have 50-rancher.yaml", prov, len(a.nodes))
			}
			add("  " + kv("provisioning", kind))
		}
	}
	var rows [][]string
	for _, n := range sortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		agent := strings.TrimSpace(ni.Rancher.SystemAgent)
		if agent == "" || strings.HasPrefix(agent, "not-found") {
			agent = styleDim.Render("-")
		} else {
			agent = okText(strings.Contains(agent, "active running"), agent, agent)
		}
		rows = append(rows, []string{n, ni.Settings["server"], agent, ni.Rancher.AgentURL, fmt.Sprint(ni.Rancher.Provisioned), fmt.Sprint(ni.Rancher.Plans)})
	}
	if len(rows) > 0 {
		add("", styleTitle.Render("Node join topology / agents")+styleDim.Render("  (server = rke2 supervisor the node joined through)"))
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "SERVER (config.yaml)", max: 40}, {title: "RANCHER-SYSTEM-AGENT"}, {title: "AGENT URL", max: 40}, {title: "50-RANCHER"}, {title: "PLANS"}}, rows)
		add(h)
		add(lines...)
	}

	// registries
	add("", styleTitle.Render("Registries")+styleDim.Render("  (registries.yaml vs what containerd applied; enter for full dumps)"))
	regUse := map[string]int{}
	for i := range s.Pods {
		for _, c := range s.Pods[i].Spec.Containers {
			regUse[registryOf(c.Image)]++
		}
	}
	var regs []string
	for _, r := range sortedKeys(regUse) {
		regs = append(regs, fmt.Sprintf("%s (%d)", r, regUse[r]))
	}
	add(wrap("  registries used by running pods: "+strings.Join(regs, ", "), a.width-2)...)
	rows = nil
	for _, n := range sortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		files := make([]string, 0, len(ni.Registries))
		for _, f := range ni.Registries {
			files = append(files, shortPath(f.Path))
		}
		mirrors := strings.Join(ni.RegistryMirrors, ",")
		applied := strings.Join(ni.ContainerdHosts, ",")
		state := styleDim.Render("no registries.yaml")
		switch {
		case len(ni.RegistryMirrors) > 0 && len(ni.ContainerdHosts) == 0:
			state = styleWarn.Render("mirrors NOT applied by containerd")
		case len(ni.RegistryMirrors) > 0:
			state = styleOK.Render("applied")
		}
		sdr := ni.Settings["system-default-registry"]
		rows = append(rows, []string{n, strings.Join(files, ","), mirrors, applied, sdr, state})
	}
	if len(rows) > 0 {
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "FILE"}, {title: "MIRRORS", max: 40}, {title: "CONTAINERD HOSTS", max: 40}, {title: "SYSTEM-DEFAULT-REGISTRY"}, {title: "STATE"}}, rows)
		add(h)
		add(lines...)
	}

	// rke2 HelmCharts
	if len(s.HelmCharts) > 0 {
		add("", styleTitle.Render("rke2/k3s bundled HelmCharts")+styleDim.Render("  (helm.cattle.io; upgraded with the rke2 release; HelmChartConfig = your overrides)"))
		rows = nil
		for _, hc := range s.HelmCharts {
			st := okText(!hc.Failed, "ok", "FAILED")
			cfg := ""
			if hc.HasConfig {
				cfg = styleInfo.Render("overrides")
			}
			rows = append(rows, []string{hc.Name, hc.Chart, hc.Version, hc.TargetNS, cfg, st})
		}
		h, lines := renderTable(a.width, []column{{title: "NAME"}, {title: "CHART", max: 50}, {title: "VERSION"}, {title: "TARGET NS"}, {title: "CONFIG"}, {title: "STATUS"}}, rows)
		add(h)
		add(lines...)
	}
	return linesContent(out)
}

func (a *App) addonsDetail() (string, []string) {
	var out []string
	w := a.width - 6
	for _, n := range sortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		out = append(out, styleTitle.Render("== "+n+" =="))
		for _, f := range ni.ConfigFiles {
			out = append(out, styleBold.Render("--- "+f.Path))
			for _, l := range strings.Split(f.Content, "\n") {
				out = append(out, wrap(l, w)...)
			}
		}
		for _, f := range ni.Registries {
			out = append(out, styleBold.Render("--- "+f.Path))
			for _, l := range strings.Split(f.Content, "\n") {
				out = append(out, wrap(l, w)...)
			}
		}
		for _, f := range ni.ContainerdConfig {
			out = append(out, styleBold.Render("--- "+f.Path))
			for _, l := range strings.Split(f.Content, "\n") {
				out = append(out, wrap(l, w)...)
			}
		}
		out = append(out, "")
	}
	if s := a.snap; s != nil {
		for _, hc := range s.HelmCharts {
			if hc.HasConfig {
				out = append(out, styleBold.Render("--- HelmChartConfig "+hc.Namespace+"/"+hc.Name))
				for _, l := range strings.Split(hc.ConfigValues, "\n") {
					out = append(out, wrap(l, w)...)
				}
			}
		}
	}
	if len(out) == 0 {
		out = append(out, styleDim.Render("no node config collected"))
	}
	return "Node configuration, registries and containerd", out
}

func detectCNI(s *k8s.Snapshot) string {
	var found []string
	for i := range s.DaemonSets {
		n := s.DaemonSets[i].Name
		for _, c := range []string{"canal", "calico", "cilium", "flannel", "multus", "weave", "kube-ovn", "antrea", "kube-router", "aws-node", "azure-cni"} {
			if strings.Contains(n, c) {
				found = append(found, s.DaemonSets[i].Namespace+"/"+n)
			}
		}
	}
	if len(found) == 0 {
		return styleWarn.Render("none detected")
	}
	return strings.Join(found, ", ")
}

func shortPath(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func registryOf(image string) string {
	first := image
	if i := strings.Index(image, "/"); i >= 0 {
		first = image[:i]
	} else {
		return "docker.io"
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return "docker.io"
}

// ---------- Helm ----------

func (a *App) helmContent() content {
	s := a.snap
	var rows [][]string
	var ids []string
	for _, r := range s.HelmReleases {
		if !a.inNamespace(r.Namespace) {
			continue
		}
		st := r.Status
		switch strings.ToLower(st) {
		case "deployed":
			st = styleOK.Render(st)
		case "failed":
			st = styleCrit.Render(st)
		default:
			st = styleWarn.Render(st)
		}
		latest := styleDim.Render("-")
		if l, ok := a.helmLatest[r.Chart]; ok {
			switch {
			case l.Err != "":
				latest = styleDim.Render(firstLine(l.Err))
			case helmcheck.CompareVersions(l.Version, r.Version) > 0:
				latest = styleWarn.Render(l.Version) + styleDim.Render(" "+l.Source)
			default:
				latest = styleOK.Render("up to date")
			}
		} else if a.helm == nil {
			latest = styleDim.Render("(off)")
		}
		vals := ""
		if r.ValuesYAML != "" {
			vals = fmt.Sprintf("%d lines", strings.Count(r.ValuesYAML, "\n")+1)
		}
		rows = append(rows, []string{r.Namespace, r.Name, r.Chart, r.Version, r.AppVersion, fmt.Sprint(r.Revision), st, age(r.Updated), vals, latest})
		ids = append(ids, r.Namespace+"/"+r.Name)
	}
	h, lines := renderTable(a.width, []column{{title: "NAMESPACE", max: 24}, {title: "RELEASE", max: 36}, {title: "CHART", max: 36}, {title: "VERSION"}, {title: "APP"}, {title: "REV", right: true}, {title: "STATUS"}, {title: "UPDATED", right: true}, {title: "VALUES"}, {title: "LATEST"}}, rows)
	hdr := []string{styleTitle.Render("Helm releases") + styleDim.Render(fmt.Sprintf("  %d in scope; enter shows the values applied. Update check: ", len(rows)))}
	if a.helm != nil {
		hdr[0] += styleOK.Render("on")
	} else {
		hdr[0] += styleDim.Render("off (helm.check_updates / --helm-updates)")
	}
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no Helm releases found (helm.sh/release.v1 secrets)"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

func (a *App) helmDetail(id string) (string, []string) {
	for _, r := range a.snap.HelmReleases {
		if r.Namespace+"/"+r.Name != id {
			continue
		}
		out := []string{
			kv("chart", r.Chart+" "+r.Version) + "  " + kv("app version", r.AppVersion) + "  " + kv("revision", fmt.Sprint(r.Revision)) + "  " + kv("status", r.Status),
			kv("updated", r.Updated.Format(time.RFC3339)) + "  " + kv("storage", r.Storage),
			kv("description", r.Description),
		}
		if l, ok := a.helmLatest[r.Chart]; ok && l.Version != "" {
			out = append(out, kv("latest available", l.Version+" ("+l.Source+")"))
		}
		out = append(out, "", styleTitle.Render("User-supplied values (helm get values)"))
		if r.ValuesYAML == "" {
			out = append(out, styleDim.Render("(none - chart defaults)"))
		} else {
			for _, l := range strings.Split(r.ValuesYAML, "\n") {
				out = append(out, wrap(l, a.width-6)...)
			}
		}
		return "Helm release " + id, out
	}
	return "", nil
}

// ---------- Images ----------

func (a *App) imagesContent() content {
	s := a.snap
	var hdr []string
	running := map[string]bool{}
	for i := range s.Pods {
		for _, c := range s.Pods[i].Spec.Containers {
			running[c.Image] = true
		}
	}
	hdr = append(hdr, styleTitle.Render("Images")+"  "+kv("distinct images in pod specs", fmt.Sprint(len(running)))+styleDim.Render("  per-node inventory needs full SSH collection (R); enter for details"))
	var rows [][]string
	var ids []string
	for _, n := range sortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			rows = append(rows, []string{n, styleCrit.Render("ssh error")})
			ids = append(ids, n)
			continue
		}
		if !ni.Heavy && len(ni.Images) == 0 {
			rows = append(rows, []string{n, styleDim.Render("pending full collection")})
			ids = append(ids, n)
			continue
		}
		var total int64
		for _, im := range ni.Images {
			total += im.Size
		}
		unused, ub := ni.UnusedImages()
		tarImgs := map[string]bool{}
		for _, t := range ni.Tarballs {
			for _, im := range t.Images {
				tarImgs[im] = true
			}
		}
		runningHere := map[string]bool{}
		for _, c := range ni.Containers {
			runningHere[c.Image] = true
		}
		for i := range s.Pods {
			if s.Pods[i].Spec.NodeName == n {
				for _, c := range s.Pods[i].Spec.Containers {
					runningHere[c.Image] = true
				}
			}
		}
		notInTar := 0
		if len(tarImgs) > 0 {
			for im := range runningHere {
				if !tarImgs[normImage(im)] && !tarImgs[im] {
					notInTar++
				}
			}
		}
		tarTxt := styleDim.Render("-")
		if len(ni.Tarballs) > 0 {
			var tsize int64
			for _, t := range ni.Tarballs {
				tsize += t.Size
			}
			tarTxt = fmt.Sprintf("%d files %s, %d images", len(ni.Tarballs), humanBytes(float64(tsize)), len(tarImgs))
		}
		unusedTxt := fmt.Sprintf("%d (%s)", len(unused), humanBytes(float64(ub)))
		if float64(ub)/1e9 >= a.cfg.Thresholds.UnusedImagesGB {
			unusedTxt = styleWarn.Render(unusedTxt)
		}
		rows = append(rows, []string{n, fmt.Sprint(len(ni.Images)), humanBytes(float64(total)), fmt.Sprint(len(ni.Containers)), unusedTxt, tarTxt, fmt.Sprint(notInTar)})
		ids = append(ids, n)
	}
	h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "IMAGES", right: true}, {title: "SIZE", right: true}, {title: "CONTAINERS", right: true}, {title: "UNUSED"}, {title: "AIRGAP TARBALLS"}, {title: "RUNNING NOT IN TARBALLS", right: true}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no SSH data"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

func normImage(im string) string {
	// docker.io/library/nginx:1.2 vs nginx:1.2
	im = strings.TrimPrefix(im, "docker.io/library/")
	im = strings.TrimPrefix(im, "docker.io/")
	return im
}

func (a *App) imagesDetail(node string) (string, []string) {
	ni := a.nodes[node]
	if ni == nil {
		return "", nil
	}
	w := a.width - 6
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	add(kv("crictl", ni.CrictlInfo))
	unused, ub := ni.UnusedImages()
	add(kv("images", fmt.Sprint(len(ni.Images))) + "  " + kv("running containers", fmt.Sprint(len(ni.Containers))) + "  " + kv("unused", fmt.Sprintf("%d (%s)", len(unused), humanBytes(float64(ub)))))

	if len(ni.Tarballs) > 0 {
		add("", styleTitle.Render("Airgap image tarballs"))
		running := map[string]bool{}
		for _, c := range ni.Containers {
			running[normImage(c.Image)] = true
			running[normImage(c.ImageRef)] = true
		}
		if s := a.snap; s != nil {
			for i := range s.Pods {
				if s.Pods[i].Spec.NodeName == node {
					for _, c := range s.Pods[i].Spec.Containers {
						running[normImage(c.Image)] = true
					}
				}
			}
		}
		for _, t := range ni.Tarballs {
			add(styleBold.Render(shortPath(t.Path)) + "  " + kv("size", humanBytes(float64(t.Size))) + "  " + kv("modified", t.ModTime.Format("2006-01-02")) + "  " + kv("images", fmt.Sprint(len(t.Images))))
			if !t.Parsed {
				add(styleDim.Render("  manifest not readable (zstd missing, or unsupported format)"))
			}
			sort.Strings(t.Images)
			for _, im := range t.Images {
				mark := styleDim.Render("  idle    ")
				if running[normImage(im)] {
					mark = styleOK.Render("  running ")
				}
				add(mark + im)
			}
		}
	}
	sort.Slice(unused, func(i, j int) bool { return unused[i].Size > unused[j].Size })
	add("", styleTitle.Render("Unused images (largest first)"))
	if len(unused) == 0 {
		add(styleDim.Render("  none"))
	}
	for _, im := range unused {
		tag := strings.Join(im.Tags, ",")
		if tag == "" {
			tag = styleDim.Render("<none> " + trunc(im.ID, 20))
		}
		add(fmt.Sprintf("  %8s  %s", humanBytes(float64(im.Size)), trunc(tag, w-12)))
	}
	add("", styleTitle.Render("Running containers"))
	sort.Slice(ni.Containers, func(i, j int) bool { return ni.Containers[i].Pod < ni.Containers[j].Pod })
	for _, c := range ni.Containers {
		add(trunc(fmt.Sprintf("  %-50s %-20s %s", c.Pod, c.Name, c.ImageRef), w))
	}
	return "Images on " + node, out
}

// ---------- Security ----------

func (a *App) securityContent() content {
	counts := stig.Counts(a.stigRes)
	hdr := []string{
		styleTitle.Render("STIG / CIS checks") + "  " + styleCrit.Render(fmt.Sprintf("%d fail", counts[stig.Fail])) + "  " + styleWarn.Render(fmt.Sprintf("%d manual", counts[stig.Manual])) + "  " + styleOK.Render(fmt.Sprintf("%d pass", counts[stig.Pass])) + "  " + styleDim.Render(fmt.Sprintf("%d n/a  %d unknown", counts[stig.NA], counts[stig.Unknown])),
		styleDim.Render("IDs reference the DISA Kubernetes STIG (V-...) and CIS benchmarks; confirm the mapping against your STIG release. 'a' hides passing rules; enter shows detail + fix."),
	}
	var rows [][]string
	var ids []string
	for i, r := range a.stigRes {
		if a.problemOnly && (r.Status == stig.Pass || r.Status == stig.NA) {
			continue
		}
		rows = append(rows, []string{stigStyle(r.Status).Render(fmt.Sprintf("%-7s", r.Status.String())), r.Cat, r.ID, r.Group, r.Title, r.Detail})
		ids = append(ids, fmt.Sprint(i))
	}
	h, lines := renderTable(a.width, []column{{title: "STATUS"}, {title: "CAT"}, {title: "ID"}, {title: "GROUP"}, {title: "RULE", max: 60}, {title: "DETAIL"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no results"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

func (a *App) securityDetail(id string) (string, []string) {
	var idx int
	if _, err := fmt.Sscan(id, &idx); err != nil || idx < 0 || idx >= len(a.stigRes) {
		return "", nil
	}
	r := a.stigRes[idx]
	w := a.width - 6
	out := []string{stigStyle(r.Status).Render(r.Status.String()) + "  " + kv("category", r.Cat) + "  " + kv("group", r.Group), "", styleBold.Render(r.Title), ""}
	out = append(out, wrap("detail: "+r.Detail, w)...)
	out = append(out, "")
	out = append(out, wrap("fix: "+r.Fix, w)...)
	return r.ID, out
}

// ---------- Logs ----------

func (a *App) logsContent() content {
	hdr := []string{styleTitle.Render("Node logs") + styleDim.Render("  journal of rke2-server/agent, kubelet, containerd, rancher-system-agent classified with the pattern knowledge base. R refreshes; enter shows lines + explanations.")}
	var rows [][]string
	var ids []string
	for _, n := range sortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			rows = append(rows, []string{n, styleCrit.Render("ssh error")})
			ids = append(ids, n)
			continue
		}
		unit := "-"
		for _, u := range ni.Units {
			if u.Name == "rke2-server" || u.Name == "rke2-agent" || u.Name == "k3s" || u.Name == "k3s-agent" || u.Name == "kubelet" {
				txt := fmt.Sprintf("%s %s/%s", u.Name, u.Active, u.Sub)
				if u.NRestarts > 0 {
					txt += styleWarn.Render(fmt.Sprintf(" restarts=%d", u.NRestarts))
				}
				unit = okText(u.Active == "active", txt, txt)
				break
			}
		}
		ls := a.logSum[n]
		if ls == nil {
			rows = append(rows, []string{n, unit, styleDim.Render("pending full collection")})
			ids = append(ids, n)
			continue
		}
		up := styleDim.Render("not seen in window")
		if !ls.Startup.IsZero() {
			up = "up and running " + age(ls.Startup) + " ago"
		}
		errs := colorCount(ls.Counts[logs.ClassError], "err", styleCrit)
		warns := colorCount(ls.Counts[logs.ClassWarn], "warn", styleWarn)
		startup := fmt.Sprintf("%d startup", ls.Counts[logs.ClassStartup])
		top := strings.Join(append(ls.TopPatterns(logs.ClassError, 2), ls.TopPatterns(logs.ClassWarn, 2)...), ", ")
		rows = append(rows, []string{n, unit, fmt.Sprint(ls.Total), errs, warns, startup, up, top})
		ids = append(ids, n)
	}
	h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "UNIT"}, {title: "LINES", right: true}, {title: "ERRORS"}, {title: "WARNINGS"}, {title: "STARTUP"}, {title: "STARTUP MARKER"}, {title: "TOP PATTERNS"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no SSH data"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

func (a *App) logsDetail(node string) (string, []string) {
	ls := a.logSum[node]
	ni := a.nodes[node]
	if ls == nil || ni == nil {
		return "", nil
	}
	w := a.width - 6
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	for _, u := range ni.Units {
		add(kv(u.Name, fmt.Sprintf("%s/%s restarts=%d started=%s ago result=%s", u.Active, u.Sub, u.NRestarts, age(u.Started), u.Result)))
	}
	add("", styleTitle.Render("Pattern summary"))
	for _, cls := range []logs.Class{logs.ClassError, logs.ClassWarn, logs.ClassStartup} {
		for _, name := range ls.TopPatterns(cls, 20) {
			p := logs.Find(name)
			if p == nil {
				continue
			}
			label := classStyle(cls).Render(fmt.Sprintf("%-8s", cls.String()))
			add(fmt.Sprintf("%s %4dx %s", label, ls.ByName[name], styleBold.Render(name)))
			add(wrap("           "+p.Explain, w)...)
		}
	}
	add("", styleTitle.Render("Lines (errors, warnings and persistent startup noise; info lines omitted)"))
	shown := 0
	for _, m := range ls.Matches {
		if m.Class == logs.ClassInfo || (m.Class == logs.ClassStartup && m.Pattern != nil && m.Pattern.Persist == 0) {
			continue
		}
		name := ""
		if m.Pattern != nil {
			name = m.Pattern.Name
		}
		add(classStyle(m.Class).Render(fmt.Sprintf("%-7s", m.Class.String())) + " " + styleDim.Render(fmt.Sprintf("%-18s", name)) + " " + trunc(m.Line, w-27))
		shown++
		if shown >= 400 {
			add(styleDim.Render("... truncated"))
			break
		}
	}
	if shown == 0 {
		add(styleOK.Render("  nothing noteworthy in the collected window"))
	}
	if len(ni.LogFiles) > 0 {
		add("", styleTitle.Render("Log files (filtered tail)"))
		for _, f := range ni.LogFiles {
			add(styleBold.Render("--- " + f.Path))
			for _, l := range strings.Split(f.Content, "\n") {
				if strings.TrimSpace(l) != "" {
					add(trunc(l, w))
				}
			}
		}
	}
	return "Logs on " + node, out
}

func classStyle(c logs.Class) interface{ Render(...string) string } {
	switch c {
	case logs.ClassError:
		return styleCrit
	case logs.ClassWarn:
		return styleWarn
	case logs.ClassStartup:
		return styleInfo
	}
	return styleDim
}
