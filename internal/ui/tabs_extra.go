package ui

import (
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/checks"
	"github.com/zlmitchell/khealth-tui/internal/distro"
	etcdpkg "github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/helmcheck"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/stig"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

var _ = math.NaN

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
	add(styleTitle.Render("etcd") + "  " + kv("distribution", s.Distribution) + "  " + kv("etcd nodes", fmt.Sprint(etcdNodes)) + "  " + kv("probes", fmt.Sprintf("%d done, %d pending", len(a.etcd), len(a.etcdPend))) + styleDim.Render("   enter = full config dumps   X = rescue (restore a snapshot)   D = defrag all members, one at a time"))
	add(a.etcdTiles()...)
	if !a.sshEnabled {
		add(styleWarn.Render("SSH collection is off - etcd internals need SSH to the control-plane nodes. API-side view only."))
	}
	for _, c := range s.Readyz {
		if strings.HasPrefix(c.Name, "etcd") {
			add(kv("apiserver readyz "+c.Name, okText(c.OK, "ok", "FAILED "+c.Detail)))
		}
	}

	// members: kubectl-exec probe first (cluster-wide), else any SSH probe
	var memberProbe string
	probes := map[string]*etcdpkg.Probe{}
	for n, p := range a.etcd {
		probes[n] = p
	}
	if x := a.etcdExec; x != nil && x.Err == nil && len(x.Members) > 0 {
		memberProbe = "kubectl-exec"
		probes[memberProbe] = x
	} else {
		for _, n := range strutil.SortedKeys(a.etcd) {
			if len(a.etcd[n].Members) > 0 {
				memberProbe = n
				break
			}
		}
	}
	if x := a.etcdExec; x != nil && x.Err != nil {
		add(styleDim.Render("kubectl exec probe: ") + styleWarn.Render(strutil.FirstLine(x.Err.Error())) + styleDim.Render("  (needs pods/exec on kube-system; SSH probes still apply)"))
	}
	// statuses can come from one etcdctl --cluster call or one gateway call per node
	statusByID := map[string]*etcdpkg.EndpointStatus{}
	healthByEP := map[string]etcdpkg.EndpointHealth{}
	for _, n := range strutil.SortedKeys(probes) {
		for i := range probes[n].Statuses {
			st := &probes[n].Statuses[i]
			if st.MemberID != "" {
				statusByID[st.MemberID] = st
			}
		}
		for _, h := range probes[n].EndpointHealth {
			healthByEP[h.Endpoint] = h
		}
	}
	// correlated triage: one block per problem member with the steps to fix it
	var triage []checks.Finding
	for _, f := range a.findings {
		if f.Area == "etcd" && len(f.Steps) > 0 {
			triage = append(triage, f)
		}
	}
	if len(triage) > 0 {
		add("", styleTitle.Render("Triage")+styleDim.Render("  what is wrong, in order of severity, and what to do about it"))
		for _, f := range triage {
			add(sevText(f.Severity) + " " + styleBold.Render(f.Object) + "  " + f.Message)
			add(stepLines(f.Steps, a.width-4)...)
			add("")
		}
	}

	add("", styleTitle.Render("Members"))
	if memberProbe == "" {
		add(styleDim.Render("  no member list. Per node:"))
		for _, n := range strutil.SortedKeys(a.etcd) {
			p := a.etcd[n]
			if p.Err != nil {
				add("  " + styleBold.Render(n) + "  " + styleCrit.Render("probe error: "+strutil.FirstLine(p.Err.Error())))
				continue
			}
			line := "  " + styleBold.Render(n) + "  " + kv("via", p.EtcdctlVia)
			if p.EtcdctlDiag != "" {
				line += "  " + styleWarn.Render(p.EtcdctlDiag)
			}
			if len(p.Missing) > 0 {
				line += "  " + styleCrit.Render("missing: "+strings.Join(p.Missing, ", "))
			}
			if p.EtcdctlDiag == "" && len(p.Missing) == 0 && p.EtcdctlOut != "" {
				line += "  " + styleDim.Render(trunc(lastNonEmpty(p.EtcdctlOut), 100))
			}
			add(line)
		}
		add(styleDim.Render("  enter shows the raw probe output; set etcd.ca_cert/client_cert/client_key/endpoint in the config for non-standard layouts"))
	} else {
		p := probes[memberProbe]
		var rows [][]string
		for _, m := range p.Members {
			st := statusByID[m.ID]
			ver, db, inuse, leader, term, idx, errs := "-", "-", "-", "", "-", "-", ""
			health := styleDim.Render("-")
			for _, u := range m.ClientURLs {
				if h, ok := healthByEP[u]; ok {
					health = okText(h.Healthy, "healthy "+h.Took, "UNHEALTHY "+strutil.FirstLine(h.Error))
				}
			}
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
			rows = append(rows, []string{m.ID, m.Name, strings.Join(m.PeerURLs, ","), health, ver, db, inuse, leader, term, idx, learner, errs})
		}
		h, lines := renderTable(a.width, []column{{title: "ID"}, {title: "NAME"}, {title: "PEER URL", max: 40}, {title: "HEALTH"}, {title: "VERSION"}, {title: "DB", right: true}, {title: "IN USE", right: true}, {title: "ROLE"}, {title: "TERM", right: true}, {title: "INDEX", right: true}, {title: ""}, {title: "ERRORS"}}, rows)
		add(h)
		add(lines...)
		add(styleDim.Render(fmt.Sprintf("  via %s (member list first, then endpoint health/status against every client URL)", p.EtcdctlVia)))
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
	for _, n := range strutil.SortedKeys(a.etcd) {
		p := a.etcd[n]
		if p.Err != nil {
			rows = append(rows, []string{n, styleCrit.Render("probe error: " + strutil.FirstLine(p.Err.Error()))})
			continue
		}
		health := styleDim.Render("-")
		if p.Health != nil {
			health = okText(p.Health.Healthy, "healthy", "UNHEALTHY "+strutil.FirstLine(p.Health.Reason))
		}
		leader, db, frag, fsync, commit, changes, pend, ver, fs := "-", "-", "-", "-", "-", "-", "-", "-", "-"
		if m := p.Metrics; m != nil {
			leader = okText(m.HasLeader, map[bool]string{true: "yes*", false: "yes"}[m.IsLeader], "NO LEADER")
			if m.Quota > 0 {
				pct := m.DBSize / m.Quota * 100
				db = gauge(pct, 8, thr.EtcdDBWarnPct, 95) + styleDim.Render(" "+humanBytes(m.DBSize)+"/"+humanBytes(m.Quota))
			} else {
				db = humanBytes(m.DBSize)
			}
			if m.DBSize > 0 && m.DBSizeInUse > 0 {
				f := (m.DBSize - m.DBSizeInUse) / m.DBSize * 100
				frag = gauge(f, 6, thr.EtcdFragWarnPct, 80)
			}
			fsync = pctStyle(m.WalFsyncAvgMs, int(thr.EtcdFsyncWarnMs), int(thr.EtcdFsyncWarnMs*3)).Render(fmt.Sprintf("%.1fms", m.WalFsyncAvgMs)) + " " + sparkStyled(a.values("etcd.fsync:"+n), 8, 0, int(thr.EtcdFsyncWarnMs), int(thr.EtcdFsyncWarnMs*3))
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
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "DIST"}, {title: "HEALTH"}, {title: "LEADER"}, {title: "DB / QUOTA"}, {title: "FRAG"}, {title: "FSYNC + TREND"}, {title: "COMMIT", right: true}, {title: "LDR CHG", right: true}, {title: "PEND/FAIL", right: true}, {title: "VERSION"}, {title: "DATA DIR FS"}}, rows)
		add(h)
		add(lines...)
		add(styleDim.Render("  yes* = this member is the leader; FRAG = allocated but unused db space (defrag reclaims); FSYNC/COMMIT = average disk latency since start"))
	}

	add("", styleTitle.Render("Configuration source"))
	for _, n := range strutil.SortedKeys(a.etcd) {
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
		if raft := raftLine(p); raft != "" {
			add("  " + raft)
		}
		if len(p.RKE2Config) > 0 {
			var kvs []string
			for _, k := range strutil.SortedKeys(p.RKE2Config) {
				kvs = append(kvs, k+"="+p.RKE2Config[k])
			}
			add(wrap("  rke2 etcd settings: "+strings.Join(kvs, " "), a.width-2)...)
		} else if p.Dist == "rke2" {
			add(styleDim.Render("  no etcd-* keys in config.yaml: rke2 defaults apply (snapshots every 12h, retention 5, local dir)"))
		}
	}

	add("", styleTitle.Render("Backups / snapshots"))
	if len(s.RKE2Snapshots) > 0 {
		latest := s.RKE2Snapshots[0] // newest first; the newest usable one is what "latest" means
		ok, failed, s3n := 0, 0, 0
		for i, r := range s.RKE2Snapshots {
			switch r.Status {
			case "failed":
				failed++
			default:
				ok++
			}
			if r.S3 {
				s3n++
			}
			if r.Status != "failed" && (latest.Status == "failed" || i == 0) {
				latest = r
			}
		}
		ageTxt := age(latest.Created) + " ago"
		if time.Since(latest.Created) > a.cfg.Etcd.MaxBackupAge {
			ageTxt = styleWarn.Render(ageTxt)
		} else {
			ageTxt = styleOK.Render(ageTxt)
		}
		add(kv("cluster records", fmt.Sprintf("%d (%d ok, %s, %d on S3) via %s", len(s.RKE2Snapshots), ok, colorCount(failed, "failed", styleCrit), s3n, latest.Source)))
		if cm := s.SnapshotCM; cm != nil {
			// the ConfigMap has a 1 MiB ceiling; full = the records stop
			use := fmt.Sprintf("%d KiB of 1 MiB (%d%%), %d entries", cm.Bytes/1024, cm.Pct(), cm.Entries)
			switch {
			case cm.Pct() >= 90:
				use = styleCrit.Render(use + " - nearly full: the next rewrite is refused and the records stop")
			case cm.Pct() >= 70:
				use = styleWarn.Render(use + " - lower etcd-snapshot-retention before it fills")
			default:
				use = styleOK.Render(use)
			}
			add(kv("records configmap", "kube-system/"+cm.Name+"  "+use))
		}
		add(kv("latest", fmt.Sprintf("%s on %s, %s, %s, %s", latest.Name, latest.Node, ageTxt, humanBytes(float64(latest.Size)), map[bool]string{true: "s3", false: "local"}[latest.S3])))
		var rows [][]string
		for i, r := range s.RKE2Snapshots {
			if i >= 8 {
				add(styleDim.Render(fmt.Sprintf("  ... %d more", len(s.RKE2Snapshots)-8)))
				break
			}
			st := okText(r.Status != "failed", r.Status, r.Status+" "+strutil.FirstLine(r.Message))
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
			ca := "system CAs"
			switch {
			case a.s3.SkipSSLVerify:
				ca = styleWarn.Render("skip-ssl-verify")
			case a.s3.EndpointCA != "":
				ca = "custom CA in secret"
			}
			add(kv("S3 secret "+a.s3.Name, fmt.Sprintf("endpoint=%s bucket=%s folder=%s region=%s credentials=%s tls=%s", a.s3.Endpoint, a.s3.Bucket, a.s3.Folder, a.s3.Region, okText(a.s3.HasCredentials, "set", "missing"), ca)))
		} else {
			add(kv("S3 secret "+a.s3.Name, styleCrit.Render("not found: "+a.s3.Err)))
		}
	}
	if s3rows := checks.S3Rows(checks.Input{Etcd: a.etcd, S3: a.s3, S3Reach: a.s3Reach}); len(s3rows) > 0 {
		for _, r := range s3rows {
			switch {
			case r[1] == "off":
				r[1] = styleDim.Render("off")
			case strings.HasPrefix(r[6], "FAIL"):
				r[6] = styleCrit.Render(r[6])
			case strings.HasPrefix(r[6], "ok"):
				r[6] = styleOK.Render(r[6])
			}
			if r[5] == "missing" {
				r[5] = styleWarn.Render(r[5])
			}
		}
		add(kv("S3 per server", styleDim.Render("(every server uploads its own snapshots; reachability = curl from the node with its CA settings)")))
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "S3"}, {title: "SOURCE"}, {title: "ENDPOINT", max: 40}, {title: "BUCKET/FOLDER", max: 40}, {title: "CREDS"}, {title: "REACHABLE"}}, s3rows)
		add(h)
		add(lines...)
	}
	var rows2 [][]string
	for _, n := range strutil.SortedKeys(a.etcd) {
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
	for _, n := range strutil.SortedKeys(a.etcd) {
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

// etcdSummary is the cluster-wide etcd picture used by the tiles on the etcd
// and Overview tabs.
type etcdSummary struct {
	probed, healthy int
	noProbeReason   string // why probed == 0
	dbPct, dbSize   float64
	frag, fsync     float64
	dbNode          string
	memberInfo      string
	leader          string
	source          string // where members/health came from: "ssh" or "exec" (kubectl exec)
}

// etcdSummarize merges the SSH probes with the kubectl-exec probe: SSH probes
// give per-node /health + /metrics (quota, fsync), the exec probe gives the
// member list, endpoint health and db sizes for the whole cluster. Either
// alone is enough to fill the tiles.
func (a *App) etcdSummarize() etcdSummary {
	sum := etcdSummary{dbPct: nan(), dbSize: nan(), frag: nan(), fsync: nan()}
	errs := 0
	for _, n := range strutil.SortedKeys(a.etcd) {
		p := a.etcd[n]
		if p.Err != nil {
			errs++
			continue
		}
		if p.Health != nil {
			sum.probed++
			if p.Health.Healthy {
				sum.healthy++
			}
		}
		if m := p.Metrics; m != nil {
			if m.Quota > 0 && (math.IsNaN(sum.dbPct) || m.DBSize/m.Quota*100 > sum.dbPct) {
				sum.dbPct, sum.dbSize, sum.dbNode = m.DBSize/m.Quota*100, m.DBSize, n
				if m.DBSize > 0 {
					sum.frag = (m.DBSize - m.DBSizeInUse) / m.DBSize * 100
				}
			}
			if math.IsNaN(sum.fsync) || m.WalFsyncAvgMs > sum.fsync {
				sum.fsync = m.WalFsyncAvgMs
			}
		}
		if sum.memberInfo == "" && len(p.Members) > 0 {
			sum.memberInfo, sum.leader = memberSummary(p)
			sum.source = "ssh"
		}
	}
	// kubectl-exec probe fills whatever SSH could not
	if x := a.etcdExec; x != nil && x.Err == nil {
		if sum.memberInfo == "" && len(x.Members) > 0 {
			sum.memberInfo, sum.leader = memberSummary(x)
			sum.source = "exec"
		}
		if sum.probed == 0 && len(x.EndpointHealth) > 0 {
			for _, h := range x.EndpointHealth {
				sum.probed++
				if h.Healthy {
					sum.healthy++
				}
			}
			sum.source = "exec"
		}
		if math.IsNaN(sum.dbSize) {
			// endpoint status has the sizes but not the quota: absolute size only
			for _, st := range x.Statuses {
				if st.DBSize <= 0 || (!math.IsNaN(sum.dbSize) && float64(st.DBSize) <= sum.dbSize) {
					continue
				}
				sum.dbSize = float64(st.DBSize)
				sum.dbNode = st.Endpoint
				if m := x.MemberByEndpoint(st.Endpoint); m != nil {
					sum.dbNode = m.Name
				}
				if st.DBSizeInUse > 0 {
					sum.frag = float64(st.DBSize-st.DBSizeInUse) / float64(st.DBSize) * 100
				}
			}
		}
	}
	if sum.probed == 0 {
		switch {
		case !a.sshEnabled && a.etcdExec == nil:
			sum.noProbeReason = "ssh off, exec probe not run"
		case !a.sshEnabled:
			sum.noProbeReason = "ssh off"
		case len(a.etcdPend) > 0:
			sum.noProbeReason = fmt.Sprintf("probing %d", len(a.etcdPend))
		case errs > 0:
			sum.noProbeReason = fmt.Sprintf("%d probe error", errs)
			if errs > 1 {
				sum.noProbeReason += "s"
			}
		case len(a.etcd) == 0:
			sum.noProbeReason = "no etcd nodes probed"
		default:
			sum.noProbeReason = "no /health reply"
		}
		if x := a.etcdExec; x != nil && x.Err != nil {
			sum.noProbeReason += ", exec failed"
		}
	}
	return sum
}

// memberSummary renders "N members[, N learner]" and the leader's name.
func memberSummary(p *etcdpkg.Probe) (info, leader string) {
	learners := 0
	for _, m := range p.Members {
		if m.IsLearner {
			learners++
		}
	}
	info = fmt.Sprintf("%d members", len(p.Members))
	if learners > 0 {
		info += fmt.Sprintf(", %d learner", learners)
	}
	for _, st := range p.Statuses {
		if st.Leader == "" || st.Leader != st.MemberID {
			continue
		}
		for _, m := range p.Members {
			if m.ID == st.MemberID {
				leader = m.Name
			}
		}
	}
	return info, leader
}

// etcdTiles renders the summary tiles at the top of the etcd tab.
func (a *App) etcdTiles() []string {
	thr := a.cfg.Thresholds
	sum := a.etcdSummarize()
	dbPct, dbSize, frag, fsync, dbNode := sum.dbPct, sum.dbSize, sum.frag, sum.fsync, sum.dbNode
	memberInfo, leaderName, healthy, probed := sum.memberInfo, sum.leader, sum.healthy, sum.probed
	var latest time.Time
	for _, r := range a.snap.RKE2Snapshots {
		if r.Status != "failed" && r.Created.After(latest) {
			latest = r.Created
		}
	}
	for _, p := range a.etcd {
		if f, _, ok := p.LatestSnapshot(); ok && f.ModTime.After(latest) {
			latest = f.ModTime
		}
	}
	backup := styleDim.Render("none found")
	if !latest.IsZero() {
		backup = okText(time.Since(latest) <= a.cfg.Etcd.MaxBackupAge, age(latest)+" ago", age(latest)+" ago")
	}
	tw, n := tileWidths(a.width, 5)
	gw := tw - 9
	sw := tw - 4
	if memberInfo == "" {
		memberInfo = styleDim.Render("no member list")
	}
	if leaderName == "" {
		leaderName = "-"
	}
	leaderLine := kv("leader", leaderName)
	if sum.source != "" {
		leaderLine += styleDim.Render(" via " + sum.source)
	}
	healthTxt := okText(healthy == probed && probed > 0, fmt.Sprintf("%d/%d", healthy, probed), fmt.Sprintf("%d/%d", healthy, probed))
	if probed == 0 {
		healthTxt = styleWarn.Render(sum.noProbeReason)
	}
	dbLabel := styleDim.Render("no db size: needs ssh/exec")
	switch {
	case !math.IsNaN(dbPct):
		dbLabel = styleDim.Render(humanBytes(dbSize) + " on " + dbNode)
	case !math.IsNaN(dbSize):
		dbLabel = styleDim.Render(humanBytes(dbSize) + " on " + dbNode + " (no quota)")
	}
	tiles := []string{
		tile(tw, "Cluster", memberInfo, leaderLine, kv("healthy", healthTxt)),
		tile(tw, "DB size / quota", gauge(dbPct, gw, thr.EtcdDBWarnPct, 95), sparkStyled(a.values("etcd.db:"+dbNode), sw, 100, thr.EtcdDBWarnPct, 95), dbLabel),
		tile(tw, "Fragmentation", gauge(frag, gw, thr.EtcdFragWarnPct, 80), sparkStyled(a.values("etcd.frag:"+dbNode), sw, 100, thr.EtcdFragWarnPct, 80), styleDim.Render("defrag reclaims")),
		tile(tw, "WAL fsync (worst)", pctStyle(fsync, int(thr.EtcdFsyncWarnMs), int(thr.EtcdFsyncWarnMs*3)).Render(fmtMs(fsync)), sparkStyled(a.values("etcd.fsync:"+dbNode), sw, 0, int(thr.EtcdFsyncWarnMs), int(thr.EtcdFsyncWarnMs*3)), styleDim.Render(fmt.Sprintf("warn > %.0fms", thr.EtcdFsyncWarnMs))),
		tile(tw, "Latest backup", backup, styleDim.Render(fmt.Sprintf("%d cluster records", len(a.snap.RKE2Snapshots))), styleDim.Render("max age "+strutil.HumanDur(a.cfg.Etcd.MaxBackupAge))),
	}
	return tileRow(tiles[:n])
}

func lastNonEmpty(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" && !strings.HasPrefix(t, "---") {
			return t
		}
	}
	return ""
}

func fmtMs(v float64) string {
	if math.IsNaN(v) {
		return "-"
	}
	return fmt.Sprintf("%.1f ms", v)
}

func (a *App) etcdDetail() (string, []string) {
	var out []string
	w := a.width - 6
	if x := a.etcdExec; x != nil {
		out = append(out, styleTitle.Render("== kubectl exec probe ==")+"  "+kv("via", x.EtcdctlVia)+"  "+kv("collected", age(x.Collected)+" ago"))
		if x.Err != nil {
			out = append(out, styleCrit.Render(x.Err.Error()))
		}
		if x.Stderr != "" {
			out = append(out, styleWarn.Render("stderr: "+strutil.FirstLine(x.Stderr)))
		}
		for _, l := range strings.Split(strings.TrimSpace(x.EtcdctlOut), "\n") {
			out = append(out, trunc(l, w))
		}
		out = append(out, "")
	}
	for _, n := range strutil.SortedKeys(a.etcd) {
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
		if p.EtcdctlVia != "" {
			out = append(out, kv("etcdctl via", p.EtcdctlVia)+"  "+kv("diag", p.EtcdctlDiag))
		}
		if len(p.Missing) > 0 {
			out = append(out, styleCrit.Render("missing: "+strings.Join(p.Missing, ", ")))
		}
		if p.Stderr != "" {
			out = append(out, styleWarn.Render("stderr: "+strutil.FirstLine(p.Stderr)))
		}
		for _, cf := range p.ConfigDump {
			out = append(out, "", styleBold.Render("--- "+cf.Path))
			out = append(out, fileLines(cf.Path, cf.Content, w)...)
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
	// headings and free text get no id (the cursor skips them); table rows
	// carry an id that addonsDetail dispatches on
	var out, ids []string
	add := func(l ...string) {
		for _, x := range l {
			out = append(out, x)
			ids = append(ids, "")
		}
	}
	addRow := func(id, l string) {
		out = append(out, l)
		ids = append(ids, id)
	}

	// CNI
	cni := detectCNI(s)
	add(styleTitle.Render("CNI") + "  " + kv("detected from daemonsets", cni))
	for _, n := range strutil.SortedKeys(a.nodes) {
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
		if l := netSummary(ni); l != "" {
			add("      " + l)
		}
	}

	// cloud provider integration and CSI
	add("", styleTitle.Render("Cloud provider (CPI)")+"  "+styleDim.Render("cloud-controller-manager, node initialization, CSI drivers and their backends"))
	add(a.cloudLines(s)...)

	// system add-ons, found by workload name in whatever namespace the chart
	// put them (ns is the conventional one, shown dim when it differs)
	add("", styleTitle.Render("System add-ons"))
	for _, want := range []struct{ label, ns, name, kind string }{
		{"CoreDNS", "kube-system", "rke2-coredns-rke2-coredns", "deploy"}, {"CoreDNS", "kube-system", "coredns", "deploy"},
		{"Ingress", "kube-system", "rke2-ingress-nginx-controller", "ds"}, {"Ingress", "ingress-nginx", "ingress-nginx-controller", "deploy"}, {"Ingress", "ingress-nginx", "ingress-nginx-controller", "ds"}, {"Ingress", "kube-system", "traefik", "deploy"},
		{"metrics-server", "kube-system", "rke2-metrics-server", "deploy"}, {"metrics-server", "kube-system", "metrics-server", "deploy"},
		{"Snapshot controller", "kube-system", "rke2-snapshot-controller", "deploy"}, {"Snapshot controller", "kube-system", "snapshot-controller", "deploy"},
		{"Longhorn", "longhorn-system", "longhorn-manager", "ds"}, {"cert-manager", "cert-manager", "cert-manager", "deploy"},
		{"Rancher webhook", "cattle-system", "rancher-webhook", "deploy"}, {"kube-proxy", "kube-system", "kube-proxy", "ds"},
		{"CIS operator", "cis-operator-system", "cis-operator", "deploy"}, {"Prometheus operator", "cattle-monitoring-system", "rancher-monitoring-operator", "deploy"}, {"Prometheus operator", "monitoring", "prometheus-operator", "deploy"},
		{"NeuVector", "cattle-neuvector-system", "neuvector-controller-pod", "deploy"}, {"Kyverno", "kyverno", "kyverno-admission-controller", "deploy"},
		{"Velero", "velero", "velero", "deploy"}, {"MetalLB", "metallb-system", "metallb-controller", "deploy"},
		{"Trident", "trident", "trident-controller", "deploy"}, {"Trident", "trident", "trident-csi", "deploy"},
	} {
		type hit struct{ ns, status string }
		var hits []hit
		if want.kind == "deploy" {
			for i := range s.Deployments {
				d := &s.Deployments[i]
				if d.Name != want.name {
					continue
				}
				st := okText(d.Status.ReadyReplicas == d.Status.Replicas && d.Status.Replicas > 0, fmt.Sprintf("%d/%d", d.Status.ReadyReplicas, d.Status.Replicas), fmt.Sprintf("%d/%d", d.Status.ReadyReplicas, d.Status.Replicas))
				if len(d.Spec.Template.Spec.Containers) > 0 {
					st += styleDim.Render("  " + d.Spec.Template.Spec.Containers[0].Image)
				}
				hits = append(hits, hit{d.Namespace, st})
			}
		} else {
			for i := range s.DaemonSets {
				d := &s.DaemonSets[i]
				if d.Name != want.name {
					continue
				}
				st := okText(d.Status.NumberReady == d.Status.DesiredNumberScheduled, fmt.Sprintf("%d/%d", d.Status.NumberReady, d.Status.DesiredNumberScheduled), fmt.Sprintf("%d/%d", d.Status.NumberReady, d.Status.DesiredNumberScheduled))
				if len(d.Spec.Template.Spec.Containers) > 0 {
					st += styleDim.Render("  " + d.Spec.Template.Spec.Containers[0].Image)
				}
				hits = append(hits, hit{d.Namespace, st})
			}
		}
		for _, h := range hits {
			ns := h.ns
			if ns != want.ns {
				ns = h.ns + styleDim.Render(" (not "+want.ns+")")
			}
			add(fmt.Sprintf("  %-20s %s/%s  %s", want.label, ns, want.name, h.status))
		}
	}

	// Rancher: always relevant on rke2/k3s; on other distributions only when
	// the cluster is actually registered in Rancher (cattle-cluster-agent)
	voc := distro.For(s.Distribution)
	rancherDist := distro.IsRancher(voc.Name)
	r := s.Rancher
	showRancher := rancherDist || (r != nil && (r.Managed || r.Provisioning != ""))
	if showRancher {
		add("", styleTitle.Render("Rancher management"))
	}
	if !showRancher {
		// a kubeadm/upstream cluster that is not registered in Rancher: nothing to say
	} else if r == nil {
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
		// the Authorized Cluster Endpoint: direct kubectl that survives a
		// Rancher outage (webhook on every apiserver + kube-api-auth)
		if ace := s.ACE(); len(ace.Servers)+len(ace.Without) > 0 {
			txt := ""
			switch {
			case len(ace.Servers) == 0:
				txt = styleWarn.Render("not enabled") + styleDim.Render("  every kubectl goes through Rancher; enable it in Cluster Management > Edit Config > Networking")
			case len(ace.Without) > 0:
				txt = styleWarn.Render("webhook on " + strutil.TruncList(ace.Servers, 3) + ", missing on " + strutil.TruncList(ace.Without, 3))
			case !ace.AuthFound:
				txt = styleCrit.Render("enabled, kube-api-auth DaemonSet missing (direct requests get 401)")
			default:
				txt = styleOK.Render("enabled") + "  " + kv("kube-api-auth", okText(ace.AuthReady == ace.AuthDesired, fmt.Sprintf("%d/%d", ace.AuthReady, ace.AuthDesired), fmt.Sprintf("%d/%d", ace.AuthReady, ace.AuthDesired))) + styleDim.Render("  webhook "+ace.Webhook)
			}
			add("  " + kv("authorized cluster endpoint", txt))
		}
		var env []string
		for _, k := range strutil.SortedKeys(r.Env) {
			if k == "CATTLE_SERVER" {
				continue
			}
			env = append(env, k+"="+r.Env[k])
		}
		add(wrap("  agent env: "+strings.Join(env, " "), a.width-2)...)
		prov := 0
		for _, n := range strutil.SortedKeys(a.nodes) {
			ni := a.nodes[n]
			if ni.Err == nil && ni.Rancher.Provisioned {
				prov++
			}
		}
		if len(a.nodes) > 0 {
			kind := "imported (" + voc.Label + " cluster registered in Rancher; node configuration is not Rancher-managed)"
			if rancherDist {
				kind = "imported/custom (no 50-rancher.yaml on nodes)"
				if prov == len(a.nodes) {
					kind = "Rancher-provisioned (config.yaml.d/50-rancher.yaml on all nodes)"
				} else if prov > 0 {
					kind = fmt.Sprintf("mixed: %d/%d nodes have 50-rancher.yaml", prov, len(a.nodes))
				}
			}
			add("  " + kv("provisioning", kind))
		}
	}
	// upgrade plans / provisioned clusters
	a.upgradeSection(s, add, addRow)

	// join topology: config.yaml server + rancher-system-agent are rke2/k3s
	// concepts; the kubeadm tab shows the API endpoint the kubelets use
	var rows [][]string
	var rowIDs []string
	for _, n := range strutil.SortedKeys(a.nodes) {
		if !rancherDist {
			break
		}
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
		rowIDs = append(rowIDs, "node:"+n)
	}
	if len(rows) > 0 {
		add("", styleTitle.Render("Node join topology / agents")+styleDim.Render("  (server = rke2 supervisor the node joined through; enter = the node's config.yaml)"))
		h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "SERVER (config.yaml)", max: 40}, {title: "RANCHER-SYSTEM-AGENT"}, {title: "AGENT URL", max: 40}, {title: "50-RANCHER"}, {title: "PLANS"}}, rows)
		add(h)
		for i, l := range lines {
			addRow(rowIDs[i], l)
		}
	}

	// registries: rke2/k3s write registries.yaml and generate containerd's
	// config from it; everywhere else containerd's own certs.d/hosts.toml is
	// the mirror configuration and config.toml's config_path must point at it
	if rancherDist {
		add("", styleTitle.Render("Registries")+styleDim.Render("  (registries.yaml vs what containerd applied; enter on a node = its registries.yaml + containerd dump)"))
	} else {
		add("", styleTitle.Render("Registries")+styleDim.Render("  (containerd certs.d/<registry>/hosts.toml mirrors vs config.toml config_path; enter on a node = its containerd dump)"))
	}
	regUse := map[string]int{}
	for i := range s.Pods {
		for _, c := range s.Pods[i].Spec.Containers {
			regUse[registryOf(c.Image)]++
		}
	}
	var regs []string
	for _, r := range strutil.SortedKeys(regUse) {
		regs = append(regs, fmt.Sprintf("%s (%d)", r, regUse[r]))
	}
	add(wrap("  registries used by running pods: "+strings.Join(regs, ", "), a.width-2)...)
	rows, rowIDs = nil, nil
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		applied := strings.Join(ni.ContainerdHosts, ",")
		if !rancherDist {
			var cfg string
			for _, f := range ni.ContainerdConfig {
				if strings.HasSuffix(f.Path, "config.toml") {
					cfg = shortPath(f.Path)
				}
			}
			configPath := ni.ContainerdSetting("config_path")
			state := styleDim.Render("no mirrors (pulls go to the registry itself)")
			switch {
			case cfg == "" && len(ni.ContainerdHosts) == 0:
				state = styleDim.Render("no containerd config found")
			case len(ni.ContainerdHosts) > 0 && configPath == "":
				state = styleWarn.Render("hosts.toml NOT applied: config_path unset in config.toml")
			case len(ni.ContainerdHosts) > 0:
				state = styleOK.Render("applied")
			case configPath != "":
				state = styleDim.Render("config_path set, no hosts.toml")
			}
			rows = append(rows, []string{n, cfg, applied, configPath, ni.ContainerdSetting("sandbox_image"), state})
			rowIDs = append(rowIDs, "registries:"+n)
			continue
		}
		files := make([]string, 0, len(ni.Registries))
		for _, f := range ni.Registries {
			files = append(files, shortPath(f.Path))
		}
		mirrors := strings.Join(ni.RegistryMirrors, ",")
		state := styleDim.Render("no registries.yaml")
		switch {
		case len(ni.RegistryMirrors) > 0 && len(ni.ContainerdHosts) == 0:
			state = styleWarn.Render("mirrors NOT applied by containerd")
		case len(ni.RegistryMirrors) > 0:
			state = styleOK.Render("applied")
		}
		sdr := ni.Settings["system-default-registry"]
		rows = append(rows, []string{n, strings.Join(files, ","), mirrors, applied, sdr, state})
		rowIDs = append(rowIDs, "registries:"+n)
	}
	if len(rows) > 0 {
		cols := []column{{title: "NODE"}, {title: "FILE"}, {title: "MIRRORS", max: 40}, {title: "CONTAINERD HOSTS", max: 40}, {title: "SYSTEM-DEFAULT-REGISTRY"}, {title: "STATE"}}
		if !rancherDist {
			cols = []column{{title: "NODE"}, {title: "CONFIG"}, {title: "CERTS.D HOSTS", max: 40}, {title: "CONFIG_PATH", max: 30}, {title: "SANDBOX IMAGE", max: 36}, {title: "STATE"}}
		}
		h, lines := renderTable(a.width, cols, rows)
		add(h)
		for i, l := range lines {
			addRow(rowIDs[i], l)
		}
	}

	// rke2 HelmCharts
	if len(s.HelmCharts) > 0 {
		add("", styleTitle.Render("rke2/k3s bundled HelmCharts")+styleDim.Render("  (helm.cattle.io; upgraded with the rke2 release; HelmChartConfig = your overrides; enter = values)"))
		rows, rowIDs = nil, nil
		for _, hc := range s.HelmCharts {
			st := okText(!hc.Failed, "ok", "FAILED")
			cfg := ""
			if hc.HasConfig {
				cfg = styleInfo.Render("overrides")
			}
			rows = append(rows, []string{hc.Name, hc.Chart, hc.Version, hc.TargetNS, cfg, st})
			rowIDs = append(rowIDs, "helmchart:"+hc.Namespace+"/"+hc.Name)
		}
		h, lines := renderTable(a.width, []column{{title: "NAME"}, {title: "CHART", max: 50}, {title: "VERSION"}, {title: "TARGET NS"}, {title: "CONFIG"}, {title: "STATUS"}}, rows)
		add(h)
		for i, l := range lines {
			addRow(rowIDs[i], l)
		}
	}
	c := content{selectable: true}
	for i, l := range out {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// addonsDetail dispatches on the selected row: a node's registries/containerd
// files, a node's config.yaml, or a bundled HelmChart's values. With nothing
// selected it dumps everything.
func (a *App) addonsDetail(id string) (string, []string) {
	kind, name, _ := strings.Cut(id, ":")
	w := a.width - 6
	var out []string
	dump := func(files []nodeinfo.ConfigFile) {
		for _, f := range files {
			out = append(out, styleBold.Render("--- "+f.Path))
			out = append(out, fileLines(f.Path, f.Content, w)...)
		}
	}
	switch kind {
	case "registries":
		ni := a.nodes[name]
		if ni == nil || ni.Err != nil {
			return "", nil
		}
		voc := distro.For(ni.Dist)
		if ni.Dist == "" || ni.Dist == "unknown" {
			voc = distro.For(a.snap.Distribution)
		}
		if distro.IsRancher(voc.Name) {
			out = append(out, kv("mirrors in registries.yaml", strings.Join(ni.RegistryMirrors, ", "))+"  "+kv("containerd certs.d hosts", strings.Join(ni.ContainerdHosts, ", "))+"  "+kv("system-default-registry", ni.Settings["system-default-registry"]))
			if len(ni.Registries) == 0 {
				out = append(out, styleDim.Render("no "+voc.Registries))
			}
			dump(ni.Registries)
		} else {
			out = append(out, kv("containerd certs.d hosts", strings.Join(ni.ContainerdHosts, ", "))+"  "+kv("config_path", ni.ContainerdSetting("config_path"))+"  "+kv("sandbox_image", ni.ContainerdSetting("sandbox_image")))
		}
		if len(ni.ContainerdConfig) > 0 {
			title := "containerd configuration (config.toml registry lines, certs.d/*/hosts.toml)"
			if distro.IsRancher(voc.Name) {
				title = "containerd (generated by " + voc.Name + " from registries.yaml)"
			}
			out = append(out, "", styleTitle.Render(title))
			dump(ni.ContainerdConfig)
		} else if !distro.IsRancher(voc.Name) {
			out = append(out, styleDim.Render("no "+voc.Registries))
		}
		return "Registries on " + name, out
	case "node":
		ni := a.nodes[name]
		if ni == nil || ni.Err != nil {
			return "", nil
		}
		out = append(out, kv("rancher-system-agent", ni.Rancher.SystemAgent)+"  "+kv("agent url", ni.Rancher.AgentURL)+"  "+kv("50-rancher.yaml", fmt.Sprint(ni.Rancher.Provisioned))+"  "+kv("plans", fmt.Sprint(ni.Rancher.Plans)))
		if len(ni.ConfigFiles) == 0 {
			out = append(out, styleDim.Render("no "+distro.For(ni.Dist).ConfigFile))
		}
		dump(ni.ConfigFiles)
		return "Node configuration on " + name, out
	case "plan":
		if l := a.planDetail(a.snap, name); l != nil {
			return "Upgrade plan " + name, l
		}
		return "", nil
	case "provcluster":
		if l := a.provClusterDetail(a.snap, name); l != nil {
			return "Provisioned cluster " + name, l
		}
		return "", nil
	case "helmchart":
		for _, hc := range a.snap.HelmCharts {
			if hc.Namespace+"/"+hc.Name != name {
				continue
			}
			out = append(out, kv("chart", hc.Chart)+"  "+kv("version", hc.Version)+"  "+kv("repo", hc.Repo)+"  "+kv("target namespace", hc.TargetNS)+"  "+kv("status", okText(!hc.Failed, "ok", "FAILED")))
			if hc.JobName != "" {
				out = append(out, kv("install job", hc.JobName))
			}
			if hc.ValuesContent != "" {
				out = append(out, "", styleTitle.Render("HelmChart valuesContent"))
				out = append(out, yamlLines(hc.ValuesContent, w)...)
			}
			if hc.HasConfig {
				out = append(out, "", styleTitle.Render("HelmChartConfig overrides"))
				out = append(out, yamlLines(hc.ConfigValues, w)...)
			} else {
				out = append(out, "", styleDim.Render("no HelmChartConfig override"))
			}
			return "HelmChart " + name, out
		}
		return "", nil
	}
	return a.addonsDump()
}

// addonsDump is the everything-from-every-node fallback.
func (a *App) addonsDump() (string, []string) {
	var out []string
	w := a.width - 6
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		out = append(out, styleTitle.Render("== "+n+" =="))
		for _, f := range ni.ConfigFiles {
			out = append(out, styleBold.Render("--- "+f.Path))
			out = append(out, fileLines(f.Path, f.Content, w)...)
		}
		for _, f := range ni.Registries {
			out = append(out, styleBold.Render("--- "+f.Path))
			out = append(out, fileLines(f.Path, f.Content, w)...)
		}
		for _, f := range ni.ContainerdConfig {
			out = append(out, styleBold.Render("--- "+f.Path))
			out = append(out, fileLines(f.Path, f.Content, w)...)
		}
		out = append(out, "")
	}
	if s := a.snap; s != nil {
		for _, hc := range s.HelmCharts {
			if hc.HasConfig {
				out = append(out, styleBold.Render("--- HelmChartConfig "+hc.Namespace+"/"+hc.Name))
				out = append(out, yamlLines(hc.ConfigValues, w)...)
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
		if l, ok := a.helmLatest[helmKey(r)]; ok {
			switch {
			case l.Err != "":
				latest = styleDim.Render(strutil.FirstLine(l.Err))
			case helmcheck.CompareVersions(l.Version, r.Version) > 0:
				latest = styleWarn.Render(l.Version) + styleDim.Render(" "+l.Source)
			default:
				latest = styleOK.Render("up to date")
			}
		} else if a.helm == nil {
			latest = styleDim.Render("off (helm.check_updates)")
		}
		name := r.Name
		if r.CRShipped {
			name += styleDim.Render(" (rke2)")
		} else if r.Bundled {
			name += styleDim.Render(" (HelmChart)")
		}
		rows = append(rows, []string{r.Namespace, name, r.Chart, r.Version, r.AppVersion, fmt.Sprintf("%d/%d", r.Revision, len(r.History)), st, age(r.Updated), latest})
		ids = append(ids, r.Namespace+"/"+r.Name)
	}
	h, lines := renderTable(a.width, []column{{title: "NAMESPACE", max: 24}, {title: "RELEASE", max: 30}, {title: "CHART", max: 30}, {title: "VERSION"}, {title: "APP"}, {title: "REV/HIST", right: true}, {title: "STATUS"}, {title: "UPDATED", right: true}, {title: "LATEST"}}, rows)
	hsegs := []seg{{0, styleOK, "deployed"}, {0, styleCrit, "failed"}, {0, styleWarn, "other"}, {0, styleInfo, "outdated"}}
	for _, r := range s.HelmReleases {
		switch strings.ToLower(r.Status) {
		case "deployed":
			hsegs[0].n++
		case "failed":
			hsegs[1].n++
		default:
			hsegs[2].n++
		}
		if l, ok := a.helmLatest[helmKey(r)]; ok && l.Version != "" && helmcheck.CompareVersions(l.Version, r.Version) > 0 {
			hsegs[3].n++
		}
	}
	hdr := []string{styleTitle.Render("Helm releases") + "  " + stacked(30, hsegs[:3]) + "  " + legend(hsegs) + styleDim.Render(fmt.Sprintf("   %d in scope; enter = values, ", len(rows))) + styleKey.Render("u") + styleDim.Render(" upgrade to latest, ") + styleKey.Render("b") + styleDim.Render(" rollback, ") + styleKey.Render("B") + styleDim.Render(" roll a failed release back to the last good revision. Update check: ")}
	if a.helm != nil {
		hdr[0] += styleOK.Render("on")
		status := map[string]helmcheck.RepoStatus{}
		for _, st := range a.helm.Status() {
			status[st.Name] = st
		}
		var names []string
		for _, r := range a.helm.Repos() {
			n := r.Name
			switch status[r.Name].State {
			case "index":
				n = styleOK.Render(n)
			case "cache":
				n = styleWarn.Render(n) + styleDim.Render(" (offline, helm cache)")
			case "offline":
				n = styleCrit.Render(n) + styleDim.Render(" (offline)")
			default:
				n = styleDim.Render(n + " (checking)")
			}
			names = append(names, n)
		}
		src := "repos: " + strings.Join(names, ", ")
		if len(names) == 0 {
			src = "no repos (helm repo add, or helm.repos in the config)"
		}
		hdr[0] += styleDim.Render("  " + src)
		if e := a.helm.LoadErr(); e != "" {
			hdr = append(hdr, styleWarn.Render("helm repositories.yaml: "+e))
		}
	} else {
		hdr[0] += styleWarn.Render("off") + styleDim.Render(" - helm.check_updates is false (or --helm-updates=false); it uses your helm repos (helm repo add) and helm.repos in the config")
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
		if l, ok := a.helmLatest[helmKey(r)]; ok {
			if l.Version != "" {
				out = append(out, kv("latest available", l.Version+" ("+l.Source+")"))
			} else if l.Err != "" {
				out = append(out, kv("latest available", styleDim.Render(l.Err)))
			}
		}
		out = append(out, "", styleTitle.Render("Origin")+styleDim.Render("  helm does not record the repository a chart was pulled from; this is the evidence in the release's Chart.yaml"))
		if r.ChartRepo != "" {
			if r.CRShipped {
				out = append(out, kv("rke2 HelmChart", r.ChartRepo)+"  "+styleDim.Render("shipped with rke2 (spec.chartContent); upgraded with the rke2 release, values via HelmChartConfig"))
			} else {
				out = append(out, kv("HelmChart CR", r.CRNamespace+"/"+r.Name)+"  "+kv("source", r.ChartRepo)+"  "+styleDim.Render("your own HelmChart manifest; u patches its spec.version"))
			}
		}
		if r.Home != "" {
			out = append(out, kv("home", r.Home))
		}
		for _, src := range r.Sources {
			out = append(out, kv("source", src))
		}
		for _, d := range r.DepRepos {
			out = append(out, kv("dependency repo", d))
		}
		for _, k := range strutil.SortedKeys(r.Annotations) {
			if strings.HasPrefix(k, "catalog.cattle.io/") || strings.HasPrefix(k, "artifacthub.io/") || strings.HasPrefix(k, "meta.helm.sh/") {
				out = append(out, kv(k, trunc(strings.ReplaceAll(r.Annotations[k], "\n", " "), a.width-30)))
			}
		}
		if len(r.History) > 0 {
			out = append(out, "", styleTitle.Render("History")+styleDim.Render("  (on the Helm tab: b picks a revision to roll back to, B goes straight to the last one that deployed)"))
			var rows [][]string
			for _, h := range r.History {
				rows = append(rows, []string{fmt.Sprint(h.Revision), h.Status, h.Chart + " " + h.Version, h.AppVersion, age(h.Updated) + " ago", strutil.FirstLine(h.Description)})
			}
			h, lines := renderTable(a.width-6, []column{{title: "REV", right: true}, {title: "STATUS"}, {title: "CHART"}, {title: "APP"}, {title: "UPDATED", right: true}, {title: "DESCRIPTION"}}, rows)
			out = append(out, h)
			out = append(out, lines...)
		}
		if r.ValuesYAML == "" {
			out = append(out, "", styleTitle.Render("User-supplied values (helm get values)"), styleDim.Render("(none - chart defaults)"))
		} else {
			out = append(out, "", styleTitle.Render("User-supplied values (helm get values)")+styleDim.Render(fmt.Sprintf("  %d lines", strings.Count(r.ValuesYAML, "\n")+1)))
			out = append(out, yamlLines(r.ValuesYAML, a.width-6)...)
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
	hdr = append(hdr, styleTitle.Render("Images")+"  "+kv("distinct images in pod specs", fmt.Sprint(len(running)))+styleDim.Render("  per-node inventory over SSH, collected while this tab is open; enter for details"))
	if st := a.tierStatus(tierImages); st != "" {
		hdr = append(hdr, styleDim.Render("  "+st))
	}
	var rows [][]string
	var ids []string
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			rows = append(rows, []string{n, styleCrit.Render("ssh error")})
			ids = append(ids, n)
			continue
		}
		if ni.ImagesAt.IsZero() && len(ni.Images) == 0 {
			rows = append(rows, []string{n, styleDim.Render("collecting the inventory (opens on this tab)")})
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
		if total > 0 {
			unusedTxt = bar(float64(ub)/float64(total), 8, styleWarn) + " " + unusedTxt
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
	if !a.secScanned {
		// opt-in: nothing is evaluated or shown until the operator asks
		c := content{empty: "Security scan not run yet", centered: true, sub: []string{
			styleKey.Render("Shift+S") + " runs it: STIG/CIS rules from the API data, node hardening and the DISA OS STIG facts over SSH",
			styleDim.Render("(sysctl -a, packages, audit rules, file sweep, config dumps; a few seconds per node; nothing runs on the nodes until you do)"),
		}}
		if l := a.sshOffLine("the node side of the scan"); l != "" {
			c.sub = append(c.sub, "", l)
		}
		return c
	}
	if a.scan.running() && !a.scan.peek {
		return a.scanProgressContent()
	}
	c := a.securitySubContent()
	if a.scan.running() {
		// peeking: the tables are there, but say what is still missing
		c.header = append([]string{a.spinner.View() + " " + styleWarn.Render(fmt.Sprintf("security scan still running: %d%%, %d/%d nodes answered - node hardening and OS STIG rows are partial (esc/enter showed them early)", a.scan.percent(), a.scan.done(), len(a.scan.nodes)))}, c.header...)
	}
	return c
}

// securitySubContent is the selected Security sub-tab after a scan.
func (a *App) securitySubContent() content {
	switch a.subName() {
	case "Node hardening":
		return a.hardeningContent()
	case "OS STIG":
		return a.osStigContent()
	}
	var clusterRes []stig.Result
	for _, r := range a.stigRes {
		if r.Group != "os" {
			clusterRes = append(clusterRes, r)
		}
	}
	counts := stig.Counts(clusterRes)
	ssegs := []seg{{float64(counts[stig.Pass]), styleOK, "pass"}, {float64(counts[stig.Fail]), styleCrit, "fail"}, {float64(counts[stig.Manual]), styleWarn, "manual"}, {float64(counts[stig.NA] + counts[stig.Unknown]), styleDim, "n/a"}}
	score := nan()
	if d := counts[stig.Pass] + counts[stig.Fail]; d > 0 {
		score = float64(counts[stig.Pass]) * 100 / float64(d)
	}
	hdr := []string{
		styleTitle.Render("STIG / CIS checks") + "  " + stacked(40, ssegs) + "  " + legend(ssegs) + "  " + kv("automated pass rate", gauge(score, 10, 200, 200)),
		a.benchmarkLine(),
	}
	if l := a.sshOffLine("the node-level rules (sysctls, file modes, rke2 profile, etcd user)"); l != "" {
		hdr = append(hdr, l)
	}
	for _, sc := range stig.Scores(clusterRes, false) {
		hdr = append(hdr, scoreLine(sc, 0))
	}
	hdr = append(hdr, styleDim.Render("score = Not a Finding / (Not a Finding + Open), the XCCDF default model SCC and OpenSCAP report (N/A and Not Reviewed excluded). IDs are a best-effort mapping; confirm against the release you are audited on. 'a' hides passing, 'm' hides manual; enter shows detail + fix."))
	var rows [][]string
	var ids []string
	for i, r := range a.stigRes {
		if r.Group == "os" || (a.problemOnly && (r.Status == stig.Pass || r.Status == stig.NA)) || (a.hideManual && r.Status == stig.Manual) {
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

// scanProgressContent replaces every Security sub-tab while a scan is in
// flight: a checklist of what the scan does, with each node's progress
// through the collection stages. Showing the API-side rules alone would
// read as a finished scan before the nodes have answered.
func (a *App) scanProgressContent() content {
	sc := a.scan
	c := content{empty: fmt.Sprintf("Security scan running: %d%%  -  %d/%d nodes answered", sc.percent(), sc.done(), len(sc.nodes)), centered: true, spin: true}
	tick := styleOK.Render("✓")
	wait := a.spinner.View()
	c.sub = append(c.sub,
		styleDim.Render("started "+age(sc.started)+" ago - the tab switches to the results when the last node answers; esc shows them early"),
		"",
		tick+" STIG/CIS rules from the API data "+styleDim.Render(fmt.Sprintf("(%d rules: component flags, kubelet config, PSA, RBAC)", len(a.stigRes))),
	)
	names := sc.nodes
	more := 0
	if len(names) > 10 {
		more = len(names) - 10
		names = names[:10]
	}
	total := len(sc.stages)
	for _, n := range names {
		done := sc.stage[n]
		pct := 0
		if total > 0 {
			pct = 100 * done / total
		}
		prog := bar(float64(done)/float64(max(total, 1)), 12, styleInfo) + fmt.Sprintf(" %3d%%  %d/%d stages", pct, done, total)
		switch {
		case sc.failed[n] != "":
			c.sub = append(c.sub, styleCrit.Render("✗")+" "+styleBold.Render(n)+"  "+prog+"  "+styleCrit.Render("failed at "+sc.failed[n]))
		case sc.want[n]:
			cur := ""
			if done < total {
				st := sc.stages[done]
				cur = styleDim.Render(st.Name + ": " + st.Label)
				if t := sc.at[n]; !t.IsZero() {
					cur += styleDim.Render(fmt.Sprintf(" (%s)", time.Since(t).Round(time.Second)))
				}
			}
			c.sub = append(c.sub, wait+" "+styleBold.Render(n)+"  "+prog+"  "+cur)
		default:
			c.sub = append(c.sub, tick+" "+styleBold.Render(n)+"  "+prog+"  "+styleDim.Render("done in "+sc.took[n].Round(100*time.Millisecond).String()))
		}
	}
	if more > 0 {
		c.sub = append(c.sub, styleDim.Render(fmt.Sprintf("  ... %d more nodes", more)))
	}
	var stages []string
	for _, st := range sc.stages {
		stages = append(stages, st.Name)
	}
	c.sub = append(c.sub,
		styleDim.Render("stages per node: "+strings.Join(stages, " → ")+" - each its own SSH run, so a slow filesystem sweep does not hold the other facts back"),
		styleDim.Render("○")+" evaluate the OS STIG rules per node "+styleDim.Render("(after the last node answers)"))
	return c
}

// sshOffLine says why the node-side facts are missing and how to get them:
// SSH never configured (no user / key), failed to set up, or toggled off.
func (a *App) sshOffLine(what string) string {
	switch {
	case a.runner == nil && a.sshErr != "":
		return styleWarn.Render("SSH disabled: "+a.sshErr) + styleDim.Render("  -  "+what+" needs SSH to the nodes: start khealth as  khealth root@<node>  or with --ssh-user/--ssh-key")
	case !a.sshEnabled:
		return styleWarn.Render("SSH collection is off (s toggles it)") + styleDim.Render("  -  "+what+" needs SSH to the nodes")
	}
	return ""
}

// hardeningContent shows per-node OS security facts (runtime vs boot config).
func (a *App) hardeningContent() content {
	hdr := []string{styleTitle.Render("Node OS hardening") + styleDim.Render("  each cell = runtime state / boot configuration; ") + styleWarn.Render("≠") + styleDim.Render(" marks a mismatch (a reboot changes the effective state). enter = node dashboard; the OS STIG sub-tab lists the rules.")}
	if st := a.tierStatus(tierConfig); st != "" {
		hdr = append(hdr, styleDim.Render("  "+st))
	}
	if l := a.sshOffLine("this view"); l != "" {
		hdr = append(hdr, l)
	}
	hdr = append(hdr, a.osBenchmarkLine())
	cols := []string{"MAC", "FIPS", "fapolicyd", "auditd", "firewall", "Secure Boot", "Kernel lockdown", "Reboot required", "OS STIG"}
	var rows [][]string
	var ids []string
	for i := range a.snap.Nodes {
		n := a.snap.Nodes[i].Name
		ni := a.nodes[n]
		if ni == nil || ni.Err != nil {
			rows = append(rows, []string{n, styleDim.Render("no ssh data")})
			ids = append(ids, n)
			continue
		}
		osName := ni.OS.Pretty
		if osName == "" {
			osName = a.snap.Nodes[i].Status.NodeInfo.OSImage
		}
		counts, _ := stig.OSSummary(a.stigRes, n)
		osCell := styleDim.Render("no STIG table")
		if !ni.STIGProbed {
			osCell = styleDim.Render("not collected (Shift+S)")
		} else if len(counts) > 0 {
			sc := stig.Score{Open: counts[stig.Fail], NotAFinding: counts[stig.Pass]}
			txt := stig.OSSummaryText(counts)
			if p := sc.Percent(); !math.IsNaN(p) {
				txt = fmt.Sprintf("score %.1f%%  %s", p, txt)
			}
			switch {
			case counts[stig.Fail] > 0:
				osCell = styleCrit.Render(txt)
			case counts[stig.Manual] > 0:
				osCell = styleWarn.Render(txt)
			default:
				osCell = styleOK.Render(txt)
			}
			if stig.OSBenchmarkFor(ni.OS) == nil {
				osCell += styleDim.Render(" (generic)")
			}
		}
		items := map[string]nodeinfo.HardeningItem{}
		for _, it := range ni.HardeningItems() {
			key := it.Name
			switch it.Name {
			case "SELinux", "AppArmor":
				key = "MAC"
			case "firewalld", "ufw":
				key = "firewall"
			}
			items[key] = it
		}
		row := []string{n, osName}
		for _, c := range cols {
			if c == "OS STIG" {
				row = append(row, osCell)
				continue
			}
			it, ok := items[c]
			if !ok {
				row = append(row, styleDim.Render("-"))
				continue
			}
			row = append(row, hardeningCell(it))
		}
		rows = append(rows, row)
		ids = append(ids, n)
	}
	columns := []column{{title: "NODE"}, {title: "OS", max: 30}}
	for _, c := range cols {
		columns = append(columns, column{title: strings.ToUpper(c)})
	}
	h, lines := renderTable(a.width, columns, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no nodes"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}

	return c
}

// osStigContent lists every rule of each node's DISA OS STIG (RHEL / Ubuntu):
// automated where ComplianceAsCode has a template or a hand-written check
// exists, MANUAL otherwise (the STIG check text is in the row's detail).
func (a *App) osStigContent() content {
	var osRes []stig.Result
	for _, r := range a.stigRes {
		if r.Group == "os" {
			osRes = append(osRes, r)
		}
	}
	counts := stig.Counts(osRes)
	ssegs := []seg{{float64(counts[stig.Pass]), styleOK, "pass"}, {float64(counts[stig.Fail]), styleCrit, "fail"}, {float64(counts[stig.Manual]), styleWarn, "manual"}, {float64(counts[stig.NA] + counts[stig.Unknown]), styleDim, "n/a"}}
	score := nan()
	if d := counts[stig.Pass] + counts[stig.Fail]; d > 0 {
		score = float64(counts[stig.Pass]) * 100 / float64(d)
	}
	if len(osRes) == 0 {
		// nothing collected yet: no gauge or scorecard, just how to start
		hdr := []string{styleTitle.Render("DISA OS STIG rules") + "  " + styleDim.Render("opt-in: nothing runs on the nodes until you ask"), a.osBenchmarkLine()}
		c := content{header: hdr, empty: "no OS STIG results yet - Shift+S collects the facts from the nodes"}
		switch {
		case a.sshOffLine("") != "":
			hdr = append(hdr, a.sshOffLine("the OS STIG scan"))
			c.empty = "the OS STIG scan cannot run without SSH"
		case a.scan.running():
			c.empty = "collecting the OS STIG facts from the nodes (a few seconds per node)..."
		default:
			hdr = append(hdr, styleBold.Render("Shift+S runs the full OS STIG scan on all hosts")+styleDim.Render(" (sysctl -a, packages, audit rules, file sweep, config dumps; a few seconds per node; results stay until the next Shift+S)"))
		}
		c.header = hdr
		return c
	}
	hdr := []string{
		styleTitle.Render("DISA OS STIG rules") + "  " + stacked(40, ssegs) + "  " + legend(ssegs) + "  " + kv("automated pass rate", gauge(score, 10, 200, 200)),
		a.osBenchmarkLine(),
	}
	scores := stig.Scores(osRes, true)
	shown := 0
	for _, sc := range scores {
		if sc.Node == "" {
			hdr = append(hdr, scoreLine(sc, 0))
			continue
		}
		if shown < 8 {
			hdr = append(hdr, scoreLine(sc, 4))
		}
		shown++
	}
	if shown > 8 {
		hdr = append(hdr, styleDim.Render(fmt.Sprintf("    ... %d more nodes: per-node scores are in the Node hardening OS STIG column", shown-8)))
	}
	hdr = append(hdr, styleDim.Render("score = Not a Finding / (Not a Finding + Open) as SCC / OpenSCAP report it (N/A and Not Reviewed excluded). MANUAL = Not Reviewed: needs a decision, evidence and the STIG check text in the detail (enter). 'a' hides passing, 'm' hides manual, '/' filters."))
	if l := a.sshOffLine("this view"); l != "" {
		hdr = append(hdr, l)
	}
	var rows [][]string
	var ids []string
	for i, r := range a.stigRes {
		if r.Group != "os" || (a.problemOnly && (r.Status == stig.Pass || r.Status == stig.NA)) || (a.hideManual && r.Status == stig.Manual) {
			continue
		}
		ref := r.Ref
		if ref == "" {
			ref = "generic"
		}
		if i := strings.Index(ref, " STIG"); i > 0 {
			ref = ref[:i]
		}
		rows = append(rows, []string{stigStyle(r.Status).Render(fmt.Sprintf("%-7s", r.Status.String())), r.Cat, r.ID, strutil.FirstNonEmpty(r.RuleID, "-"), ref, r.Title, r.Detail})
		ids = append(ids, fmt.Sprint(i))
	}
	h, lines := renderTable(a.width, []column{{title: "STATUS"}, {title: "CAT"}, {title: "ID"}, {title: "STIG ID"}, {title: "STIG", max: 22}, {title: "RULE", max: 56}, {title: "DETAIL"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no OS STIG results yet - Shift+S collects the facts from the nodes"}
	if a.scan.running() {
		c.empty = "collecting the OS STIG facts from the nodes (a few seconds per node)..."
	}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// osBenchmarkLine names the OS STIG release each reachable node is matched to.
func (a *App) osBenchmarkLine() string {
	seen := map[string]bool{}
	var parts []string
	generic := 0
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni == nil || ni.Err != nil {
			continue
		}
		if b := stig.OSBenchmarkFor(ni.OS); b != nil {
			if !seen[b.Name] {
				seen[b.Name] = true
				total, auto := b.Coverage()
				parts = append(parts, styleBold.Render(b.Name)+" "+b.Version+styleDim.Render(fmt.Sprintf(" (%d/%d rules evaluated)", auto, total)))
			}
		} else {
			generic++
		}
	}
	if generic > 0 {
		parts = append(parts, styleDim.Render(fmt.Sprintf("%d node(s) on an OS without a DISA STIG table (generic OS-* checks)", generic)))
	}
	if len(parts) == 0 {
		return kv("OS STIGs", styleDim.Render("no node facts yet"))
	}
	var oldest time.Time
	unprobed := 0
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni == nil || ni.Err != nil {
			continue
		}
		switch {
		case !ni.STIGProbed:
			unprobed++
		case oldest.IsZero() || ni.STIGCollected.Before(oldest):
			oldest = ni.STIGCollected
		}
	}
	when := styleWarn.Render("facts not collected yet - Shift+S runs the scan (a few seconds per node)")
	if !oldest.IsZero() {
		when = styleDim.Render("facts collected " + age(oldest) + " ago (Shift+S re-collects)")
		if unprobed > 0 {
			when += styleWarn.Render(fmt.Sprintf(", %d node(s) not collected", unprobed))
		}
	}
	if a.scan.running() {
		when = styleInfo.Render(fmt.Sprintf("collecting OS STIG facts: %d%%, %d/%d nodes answered %s", a.scan.percent(), a.scan.done(), len(a.scan.nodes), a.spinner.View()))
	}
	return kv("OS STIGs", strings.Join(parts, "  ·  ")) + "  " + when
}

// hardeningCell renders "runtime/boot" colored by desirability and mismatch.
func hardeningCell(it nodeinfo.HardeningItem) string {
	rt := it.Runtime
	if it.Name == "SELinux" || it.Name == "AppArmor" {
		rt = it.Name + " " + rt
	}
	var txt string
	if it.OK {
		txt = styleOK.Render(rt)
	} else {
		txt = styleWarn.Render(rt)
	}
	if it.Boot != "" && it.Boot != "-" && it.Boot != it.Runtime {
		sep := styleDim.Render("/")
		if it.Mismatch {
			sep = styleWarn.Render("≠")
		}
		txt += sep + styleDim.Render(it.Boot)
	}
	return txt
}

// scoreLine renders one SCC-style scorecard line: benchmark (or node),
// score gauge, Open / Not a Finding / N/A / Not Reviewed and the open count
// per severity.
func scoreLine(sc stig.Score, indent int) string {
	label := styleBold.Render(stig.ShortBenchmark(sc.Benchmark))
	if sc.Node != "" {
		label = styleBold.Render(sc.Node) + styleDim.Render(" ("+stig.ShortBenchmark(sc.Benchmark)+")")
	}
	pct := sc.Percent()
	scoreTxt := styleDim.Render("no scored rules")
	if !math.IsNaN(pct) {
		st := styleOK
		switch {
		case pct < 70:
			st = styleCrit
		case pct < 90:
			st = styleWarn
		}
		scoreTxt = st.Render(fmt.Sprintf("score %5.1f%%", pct)) + " " + gauge(pct, 12, 90, 70)
	}
	cats := fmt.Sprintf("CAT I %d/%d  CAT II %d/%d  CAT III %d/%d open", sc.CatOpen[0], sc.CatTotal[0], sc.CatOpen[1], sc.CatTotal[1], sc.CatOpen[2], sc.CatTotal[2])
	if sc.CatOpen[0] > 0 {
		cats = styleCrit.Render(fmt.Sprintf("CAT I %d/%d", sc.CatOpen[0], sc.CatTotal[0])) + fmt.Sprintf("  CAT II %d/%d  CAT III %d/%d open", sc.CatOpen[1], sc.CatTotal[1], sc.CatOpen[2], sc.CatTotal[2])
	}
	return strings.Repeat(" ", indent) + label + "  " + scoreTxt + "  " +
		styleCrit.Render(fmt.Sprintf("open %d", sc.Open)) + "  " + styleOK.Render(fmt.Sprintf("not a finding %d", sc.NotAFinding)) + "  " +
		styleDim.Render(fmt.Sprintf("n/a %d", sc.NotApplicable)) + "  " + styleWarn.Render(fmt.Sprintf("not reviewed %d", sc.NotReviewed)) + "  " + styleDim.Render(cats)
}

// benchmarkLine names the references that produced at least one rule: the
// Rancher MCM STIG only on the cluster that runs Rancher, the RKE2 STIG only
// on rke2, and so on.
func (a *App) benchmarkLine() string {
	var parts []string
	for _, b := range stig.Benchmarks {
		used := false
		for _, r := range a.stigRes {
			if b.Matches(r.ID) {
				used = true
				break
			}
		}
		if !used {
			continue
		}
		parts = append(parts, styleBold.Render(b.Name)+" "+b.Version+styleDim.Render(" ["+strings.Join(b.Prefixes, "*,")+"*]"))
	}
	if len(parts) == 0 {
		return kv("references", styleDim.Render("none evaluated yet"))
	}
	return kv("references", strings.Join(parts, "  ·  "))
}

func (a *App) securityDetail(id string) (string, []string) {
	if a.subName() == "Node hardening" {
		return a.nodeDetail(id)
	}
	var idx int
	if _, err := fmt.Sscan(id, &idx); err != nil || idx < 0 || idx >= len(a.stigRes) {
		return "", nil
	}
	r := a.stigRes[idx]
	w := a.width - 6
	ref := r.Ref
	if ref == "" {
		ref = "custom"
		for _, b := range stig.Benchmarks {
			if b.Matches(r.ID) {
				ref = b.Name + " " + b.Version
			}
		}
	}
	head := stigStyle(r.Status).Render(r.Status.String()) + "  " + kv("category", r.Cat) + "  " + kv("group", r.Group) + "  " + kv("reference", ref)
	if r.RuleID != "" {
		head += "  " + kv("rule", r.RuleID)
	}
	out := []string{head, "", styleBold.Render(r.Title), ""}
	out = append(out, wrap("detail: "+r.Detail, w)...)
	out = append(out, "")
	out = append(out, wrap("fix: "+r.Fix, w)...)
	if r.Check != "" {
		out = append(out, "", styleBold.Render("STIG check procedure"), "")
		out = append(out, wrap(r.Check, w)...)
	}
	return r.ID, out
}

// ---------- Logs ----------

func (a *App) logsContent() content {
	if a.logsNode != "" {
		return a.logLinesContent(a.logsNode)
	}
	hdr := []string{styleTitle.Render("Node logs") + styleDim.Render("  journal of the rke2/k3s supervisor or kubelet, containerd, rancher-system-agent plus rke2's kubelet.log and containerd.log, classified with the pattern knowledge base. Collected while this tab is open (and hourly for the findings); R refreshes; enter opens a node's lines.")}
	if st := a.tierStatus(tierJournal); st != "" {
		hdr = append(hdr, styleDim.Render("  "+st))
	}
	var rows [][]string
	var ids []string
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			rows = append(rows, []string{n, styleCrit.Render("ssh error")})
			ids = append(ids, n)
			continue
		}
		unit := "-"
		unitText := func(u nodeinfo.Unit) string {
			txt := fmt.Sprintf("%s %s/%s", u.Name, u.Active, u.Sub)
			if u.NRestarts > 0 {
				txt += styleWarn.Render(fmt.Sprintf(" restarts=%d", u.NRestarts))
			}
			return okText(u.Active == "active", txt, txt)
		}
		if u := ni.Unit(ni.SupervisorUnit()); u != nil {
			unit = unitText(*u)
		}
		// Rancher-managed nodes: the agent that rewrites the config
		rancher := ""
		for _, u := range ni.Units {
			if u.Name == "rancher-system-agent" {
				rancher = unitText(u)
			}
		}
		ls := a.logSum[n]
		if ls == nil {
			rows = append(rows, []string{n, unit, rancher, styleDim.Render("pending full collection")})
			ids = append(ids, n)
			continue
		}
		// last plan event: Rancher rewriting the node's config is what makes
		// it differ from what was set locally
		if m := ls.Last("rancher-plan-failed"); !m.Time.IsZero() {
			rancher += " " + styleCrit.Render("plan FAILED "+age(m.Time)+" ago")
		} else if m := ls.Last("rancher-plan-applied"); !m.Time.IsZero() {
			rancher += " " + styleWarn.Render("plan applied "+age(m.Time)+" ago")
		}
		rancher = strings.TrimSpace(rancher)
		up := styleDim.Render("not seen in window")
		if !ls.Startup.IsZero() {
			up = "up and running " + age(ls.Startup) + " ago"
		}
		errs := colorCount(ls.Counts[logs.ClassError], "err", styleCrit)
		warns := colorCount(ls.Counts[logs.ClassWarn], "warn", styleWarn)
		mix := stacked(12, []seg{{float64(ls.Counts[logs.ClassError]), styleCrit, ""}, {float64(ls.Counts[logs.ClassWarn]), styleWarn, ""}, {float64(ls.Counts[logs.ClassStartup]), styleInfo, ""}, {float64(ls.Counts[logs.ClassInfo]), styleDim, ""}})
		hist := styleCrit.Render(sparkline(errorsPerHour(ls, 24), 24, 0))
		top := strings.Join(append(ls.TopPatterns(logs.ClassError, 2), ls.TopPatterns(logs.ClassWarn, 2)...), ", ")
		rows = append(rows, []string{n, unit, rancher, fmt.Sprint(ls.Total), mix, errs, warns, hist, up, top})
		ids = append(ids, n)
	}
	h, lines := renderTable(a.width, []column{{title: "NODE"}, {title: "UNIT"}, {title: "RANCHER-SYSTEM-AGENT"}, {title: "LINES", right: true}, {title: "MIX"}, {title: "ERRORS"}, {title: "WARNINGS"}, {title: "ERR/HOUR (24h)"}, {title: "STARTUP MARKER"}, {title: "TOP PATTERNS"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no SSH data"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// errorsPerHour buckets error-class matches into the last n hours.
func errorsPerHour(ls *logs.Summary, n int) []float64 {
	out := make([]float64, n)
	now := time.Now()
	for _, m := range ls.Matches {
		if m.Class != logs.ClassError || m.Time.IsZero() {
			continue
		}
		h := int(now.Sub(m.Time).Hours())
		if h < 0 || h >= n {
			continue
		}
		out[n-1-h]++
	}
	return out
}

// logLinesContent lists one node's classified log lines (Enter = full line).
func (a *App) logLinesContent(node string) content {
	ls := a.logSum[node]
	ni := a.nodes[node]
	hdr := []string{styleTitle.Render("Logs: "+node) + styleDim.Render("  esc back to nodes · enter full line + explanation (w wraps) · a toggles info lines · / filters")}
	if ls == nil || ni == nil {
		return content{header: hdr, empty: "no log data for this node yet (R for a full collection)"}
	}
	var units []string
	for _, u := range ni.Units {
		units = append(units, fmt.Sprintf("%s %s/%s restarts=%d", u.Name, u.Active, u.Sub, u.NRestarts))
	}
	hdr = append(hdr, styleDim.Render(strings.Join(units, "  ")))
	mix := []seg{{float64(ls.Counts[logs.ClassError]), styleCrit, "error"}, {float64(ls.Counts[logs.ClassWarn]), styleWarn, "warn"}, {float64(ls.Counts[logs.ClassStartup]), styleInfo, "startup"}, {float64(ls.Counts[logs.ClassInfo]), styleDim, "info"}}
	hdr = append(hdr, stacked(40, mix)+"  "+legend(mix)+"  "+styleDim.Render("err/hour ")+styleCrit.Render(sparkline(errorsPerHour(ls, 24), 24, 0)))
	var rows [][]string
	var ids []string
	for i, m := range ls.Matches {
		if !a.logsAll && (m.Class == logs.ClassInfo || (m.Class == logs.ClassStartup && m.Pattern != nil && m.Pattern.Persist == 0)) {
			continue
		}
		name := ""
		if m.Pattern != nil {
			name = m.Pattern.Name
		}
		ts := ""
		if !m.Time.IsZero() {
			ts = m.Time.Local().Format("01-02 15:04:05")
		}
		rows = append(rows, []string{classStyle(m.Class).Render(fmt.Sprintf("%-7s", m.Class.String())), ts, m.Unit, styleDim.Render(name), highlightLog(logMessage(m.Line))})
		ids = append(ids, fmt.Sprint(i))
	}
	h, lines := renderTable(a.width, []column{{title: "CLASS"}, {title: "TIME"}, {title: "UNIT", max: 22}, {title: "PATTERN", max: 20}, {title: "MESSAGE"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: styleOK.Render("nothing noteworthy in the collected window (a shows all lines)")}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// renderLogLine colors a journal / log-file line the way every log view
// shows one: the journal timestamp/host/unit prefix dim, the message
// highlighted by its format (JSON, logfmt, klog, plain). The lines table
// puts the prefix in its own columns and calls highlightLog(logMessage(l))
// directly; the detail views, which show whole lines, use this.
func renderLogLine(line string) string {
	// only the journal prefix: a klog header or logfmt time= is colored by
	// the highlighter itself
	if g := journalPrefix.FindString(line); g != "" {
		return styleDim.Render(g) + highlightLog(line[len(g):])
	}
	return highlightLog(line)
}

// logMessage strips the journal timestamp/host/unit prefix for the table.
func logMessage(line string) string {
	for _, re := range []*regexp.Regexp{journalPrefix, klogPrefix, logfmtPrefix} {
		if g := re.FindStringSubmatch(line); g != nil {
			return line[len(g[0]):]
		}
	}
	return line
}

func (a *App) logsDetail(node string) (string, []string) {
	if a.logsNode != "" {
		return a.logLineDetail(a.logsNode, node)
	}
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
		add(classStyle(m.Class).Render(fmt.Sprintf("%-7s", m.Class.String())) + " " + styleDim.Render(fmt.Sprintf("%-18s", name)) + " " + renderLogLine(m.Line)) // full: the overlay cuts or wraps (w)
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
		add("", styleTitle.Render("Log files (tailed and classified above)"))
		for _, f := range ni.LogFiles {
			n := 0
			for _, l := range strings.Split(f.Content, "\n") {
				if strings.TrimSpace(l) != "" {
					n++
				}
			}
			add(kv(logFileUnit(f.Path), fmt.Sprintf("%d lines from %s", n, f.Path)))
		}
	}
	return "Logs on " + node, out
}

var journalPrefix = regexp.MustCompile(`^\S+\s+\S+\s+[^:\s]+(\[\d+\])?:\s*`)

// klogPrefix: "I0918 10:22:00.123456    1234 " (the TIME column already shows the stamp)
var klogPrefix = regexp.MustCompile(`^[IWEF]\d{4} \d{2}:\d{2}:\d{2}(\.\d+)?\s+\d+\s+`)

// logfmtPrefix: containerd's leading time="..." field
var logfmtPrefix = regexp.MustCompile(`^time="[^"]*"\s*`)

// logFileUnit names the unit a tailed log file belongs to (kubelet.log -> kubelet).
func logFileUnit(p string) string { return strings.TrimSuffix(path.Base(p), ".log") }

// logLineDetail shows one full log line with the matching pattern's explanation.
func (a *App) logLineDetail(node, id string) (string, []string) {
	ls := a.logSum[node]
	ni := a.nodes[node]
	if ls == nil || ni == nil {
		return "", nil
	}
	w := a.width - 6
	var idx int
	if _, err := fmt.Sscan(id, &idx); err != nil || idx < 0 || idx >= len(ls.Matches) {
		return "", nil
	}
	m := ls.Matches[idx]
	out := []string{classStyle(m.Class).Render(m.Class.String()) + "  " + kv("unit", m.Unit) + "  " + kv("time", m.Time.Format(time.RFC3339)), ""}
	out = append(out, wrapStyled(renderLogLine(m.Line), w)...) // the subject: always wrapped
	if m.Pattern != nil {
		out = append(out, "", styleTitle.Render("Pattern: "+m.Pattern.Name)+"  "+styleDim.Render("(seen "+fmt.Sprint(ls.ByName[m.Pattern.Name])+"x in this window)"))
		out = append(out, wrap(m.Pattern.Explain, w)...)
		if m.Pattern.Persist > 0 {
			out = append(out, styleDim.Render(fmt.Sprintf("Expected during startup; escalated to a warning when still seen more than %s after the unit came up.", strutil.HumanDur(m.Pattern.Persist))))
		}
	} else {
		out = append(out, "", styleDim.Render("No knowledge-base pattern matched this line."))
	}
	if v := logVerdict(ls, m); len(v) > 0 {
		out = append(out, "", styleTitle.Render("Verdict"))
		for _, l := range v {
			out = append(out, wrap(l, w)...)
		}
	}
	// context: the neighboring lines from the same window
	out = append(out, "", styleTitle.Render("Context"))
	for i := idx - 3; i <= idx+3; i++ {
		if i < 0 || i >= len(ls.Matches) {
			continue
		}
		prefix := "  "
		if i == idx {
			prefix = styleBold.Render("> ")
		}
		out = append(out, prefix+renderLogLine(ls.Matches[i].Line)) // full: the overlay cuts or wraps (w)
	}
	return "Log line on " + node, out
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

// logVerdict answers the question a generic (unmatched) error raises: is
// this something to fix? It looks at when the line was logged relative to
// the node's startup windows and whether the same message shape keeps
// coming back.
func logVerdict(ls *logs.Summary, m logs.Match) []string {
	if m.Pattern == nil || (m.Pattern.Name != "generic-error" && m.Pattern.Name != "generic-warn" && m.Pattern.Name != "startup-unmatched") {
		return nil
	}
	r := ls.Recur(m)
	clock := func(t time.Time) string { return t.Local().Format("15:04:05") }
	var out []string
	seen := fmt.Sprintf("This message shape was logged %dx in the collected window", r.Count)
	if !r.First.IsZero() {
		if r.Count > 1 {
			seen += fmt.Sprintf(" (first %s, last %s, %s ago)", clock(r.First), clock(r.Last), age(r.Last))
		} else {
			seen += fmt.Sprintf(" (%s ago)", age(r.Last))
		}
	}
	out = append(out, seen+".")
	windows := ls.StartupWindows()
	inStart := ls.InStartup(m.Time)
	switch {
	case m.Pattern.Name == "startup-unmatched":
		w := windows[0]
		for _, x := range windows {
			if !m.Time.Before(x[0]) && !m.Time.After(x[1]) {
				w = x
			}
		}
		out = append(out, styleOK.Render("Startup race, not a fault: ")+fmt.Sprintf("logged %s after the node's start marker (starting %s, settled by %s) and never again after startup. Nothing to fix.", strutil.HumanDur(m.Time.Sub(w[0])), clock(w[0]), clock(w[1])))
	case inStart && r.Ongoing:
		out = append(out, styleWarn.Render("Started as a startup race but is still recurring: ")+"the same message keeps appearing well after the node came up, so whatever it could not reach did not come back. Read the message for the target (an address, a lease, a container, a pod) and check that component; the other nodes' Logs tab shows whether it is node-specific.")
	case inStart:
		out = append(out, styleWarn.Render("Logged during startup but seen again later: ")+fmt.Sprintf("the last occurrence was %s ago, outside the startup window. If it stopped by itself it was a transient (a dependency restarting); if the timestamps cluster around one event, look at what happened on the node then (Nodes tab uptime, unit restarts above).", age(r.Last)))
	case r.Ongoing:
		out = append(out, styleCrit.Render("Ongoing: ")+"still being logged and not during a startup - actionable. The message names what failed; the same line on the other nodes means a cluster-wide dependency (apiserver, etcd, DNS, a registry), on this node only a local one (kubelet, containerd, the CNI, disk).")
	case len(windows) == 0 && m.Pattern.Name == "generic-error":
		out = append(out, styleDim.Render("No start marker in the collected window, so a startup race cannot be ruled out; press R after a node restart to collect the boot lines."))
		fallthrough
	default:
		out = append(out, styleOK.Render("Past incident: ")+fmt.Sprintf("not seen for %s. Nothing to do unless it comes back; if it does, the recurrence above shows how often.", age(r.Last)))
	}
	return out
}

// stepLines renders numbered remediation steps, wrapped to width; lines that
// already carry a sub-number (ranked lists) are indented instead.
func stepLines(steps []string, width int) []string {
	var out []string
	n := 0
	for _, st := range steps {
		if strings.HasPrefix(st, "   ") {
			for _, l := range wrap(strings.TrimSpace(st), width-8) {
				out = append(out, "        "+styleDim.Render(l))
			}
			continue
		}
		n++
		prefix := fmt.Sprintf("  %2d. ", n)
		for i, l := range wrap(st, width-len(prefix)) {
			if i > 0 {
				prefix = strings.Repeat(" ", len(prefix))
			}
			out = append(out, prefix+l)
		}
	}
	return out
}

// raftLine summarizes what the node's disk and etcd log say about raft state
// (readable even when etcd is down).
func raftLine(p *etcdpkg.Probe) string {
	var parts []string
	if p.LocalMemberID != "" {
		parts = append(parts, kv("member id", p.LocalMemberID))
	}
	if ev, ok := p.LastLeader(); ok {
		who := ev.Leader
		if who == p.LocalMemberID {
			who = "this node"
		}
		when := ""
		if !ev.Time.IsZero() {
			when = " at " + ev.Time.UTC().Format("2006-01-02 15:04 UTC")
		}
		parts = append(parts, kv("last election in log", fmt.Sprintf("term %d -> %s%s", ev.Term, who, when)))
	}
	if r := p.Raft; r != nil {
		if r.SnapTerm > 0 || r.SnapIndex > 0 {
			parts = append(parts, kv("raft snapshot", fmt.Sprintf("term %d index %d", r.SnapTerm, r.SnapIndex)))
		}
		if !r.WALLastWrite.IsZero() {
			parts = append(parts, kv("last WAL write", age(r.WALLastWrite)+" ago"))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "  ")
}

// cloudLines renders the cloud provider / CSI picture for the Addons tab:
// the controller workloads, what they did to the nodes, and each CSI driver
// with its controller, node plugin, backends and recent failures.
func (a *App) cloudLines(s *k8s.Snapshot) []string {
	ci := s.Cloud()
	var out []string
	comp := func(c *k8s.Component) string {
		if c == nil {
			return styleDim.Render("not installed")
		}
		st := fmt.Sprintf("%d/%d", c.Ready, c.Desired)
		if c.OK() {
			st = styleOK.Render(st)
		} else {
			st = styleCrit.Render(st)
			if c.Problem != "" {
				st += " " + styleCrit.Render(trunc(c.Problem, 60))
			}
		}
		r := ""
		if c.Restarts > 0 {
			r = "  " + styleWarn.Render(fmt.Sprintf("%d restarts", c.Restarts))
		}
		return fmt.Sprintf("%s %s/%s %s%s", c.Kind, c.Namespace, c.Name, st, r)
	}
	out = append(out, "  "+kv("provider", styleBold.Render(ci.Provider))+"  "+styleDim.Render(ci.Source))
	for i := range ci.CCMs {
		c := &ci.CCMs[i]
		out = append(out, fmt.Sprintf("  %-28s %s  %s", c.Label, comp(c), styleDim.Render(c.Image)))
	}
	// nodes
	var uninit, noID, zones []string
	byScheme := map[string]int{}
	for _, n := range ci.Nodes {
		if n.Uninitialized {
			uninit = append(uninit, n.Name)
		}
		if n.ProviderID == "" {
			noID = append(noID, n.Name)
		} else {
			sch, _, _ := strings.Cut(n.ProviderID, "://")
			byScheme[sch]++
		}
		if n.Zone != "" {
			zones = append(zones, n.Zone)
		}
	}
	var ids []string
	for _, k := range strutil.SortedKeys(byScheme) {
		ids = append(ids, fmt.Sprintf("%s:// x%d", k, byScheme[k]))
	}
	line := "  " + kv("node providerIDs", strings.Join(ids, ", "))
	if len(noID) > 0 {
		line += "  " + styleWarn.Render("none on "+strings.Join(noID, ","))
	}
	if len(uninit) > 0 {
		line += "  " + styleCrit.Render("UNINITIALIZED taint on "+strings.Join(uninit, ","))
	}
	if len(zones) > 0 {
		line += "  " + kv("zones", strings.Join(strutil.Uniq(zones), ","))
	}
	out = append(out, line)
	// node-side facts from the preflight probe
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni.Err != nil {
			continue
		}
		p := &ni.Preflight
		var parts []string
		if v := ni.KubeletFlags["cloud-provider"]; v != "" {
			parts = append(parts, "kubelet cloud-provider="+v)
		}
		if p.Virt.AWS() && p.Virt.IMDS != "" {
			parts = append(parts, "imds "+okText(p.Virt.IMDS == "200", "ok", "HTTP "+p.Virt.IMDS))
		}
		if p.Virt.VMware() && p.Probed {
			parts = append(parts, "disk.EnableUUID "+okText(p.Virt.WWNDisks > 0, "ok", "NOT SET"))
		}
		for _, vc := range p.VCenters {
			parts = append(parts, "vcenter "+vc.Host+" "+okText(vc.Code > 0, "reachable", "unreachable"))
		}
		if len(parts) > 0 {
			out = append(out, "  "+styleBold.Render(n)+"  "+strings.Join(parts, "  "))
		}
	}

	out = append(out, "", styleTitle.Render("CSI"))
	if len(ci.CSI) == 0 {
		out = append(out, styleDim.Render("  no CSIDriver objects"))
	}
	for _, d := range ci.CSI {
		nodes := fmt.Sprintf("%d/%d", d.Registered, len(s.Nodes))
		if len(d.Missing) > 0 {
			nodes = styleWarn.Render(nodes) + styleDim.Render(" missing "+strings.Join(d.Missing, ","))
		} else {
			nodes = styleOK.Render(nodes)
		}
		out = append(out, fmt.Sprintf("  %s  %s  %s  %s", styleBold.Render(d.Driver), kv("nodes", nodes), kv("pvs", fmt.Sprint(d.PVs)), kv("storageclasses", strings.Join(d.StorageCls, ","))))
		out = append(out, fmt.Sprintf("      controller: %s", comp(d.Controller)))
		out = append(out, fmt.Sprintf("      node plugin: %s", comp(d.NodePlugin)))
		for _, b := range d.Trident {
			st := okText(b.Online && (b.State == "" || b.State == "online"), b.State, strings.ToUpper(b.State))
			if b.StateReason != "" && !b.Online {
				st += " " + styleDim.Render(trunc(b.StateReason, 60))
			}
			if strings.EqualFold(b.UserState, "suspended") {
				st += " " + styleWarn.Render("suspended")
			}
			out = append(out, fmt.Sprintf("      backend %s  %s  %s  %s", styleBold.Render(b.BackendName), b.Driver, st, styleDim.Render(b.Version)))
		}
		out = append(out, a.tridentLines(s, d.TridentX, d.Trident)...)
		if d.Provider == "trident" {
			out = append(out, protectLines(s.Protect)...)
		}
		if d.Longhorn != nil {
			out = append(out, a.longhornLines(s, d.Longhorn)...)
		}
		if d.Ceph != nil {
			out = append(out, cephLines(d.Ceph)...)
		}
		if v := d.VSphere; v != nil {
			sec := "secret " + v.SecretRef
			if v.SecretRef != "" {
				sec = okText(v.SecretFound, sec, sec+" MISSING")
			}
			out = append(out, fmt.Sprintf("      vsphere.conf: %s  %s  insecure=%v  %s", kv("vcenters", strings.Join(v.VCenters, ",")), kv("datacenters", strings.Join(v.Datacenters, ",")), v.Insecure, sec))
		}
		if len(d.Failures) > 0 {
			f := d.Failures[0]
			out = append(out, "      "+styleWarn.Render(fmt.Sprintf("%d failure events in the last hour", len(d.Failures)))+"  "+styleDim.Render(f.Reason+" "+f.Object+": "+trunc(f.Message, 100)))
		}
	}
	return out
}

// netSummary is one line of a node's network facts for the Addons CNI
// section and the node detail: the overlay and underlay MTUs, and the
// outcome of the active probes when the config tier ran them.
func netSummary(ni *nodeinfo.Info) string {
	var parts []string
	if ni.DefaultDev != "" {
		if l := ni.Link(ni.DefaultDev); l != nil {
			parts = append(parts, kv("underlay", fmt.Sprintf("%s mtu %d", l.Name, l.MTU)))
		}
	}
	for _, name := range []string{"flannel.1", "flannel-wg", "vxlan.calico", "tunl0", "wireguard.cali", "cilium_vxlan", "cilium_wg0", "cni0", "cilium_host"} {
		if l := ni.Link(name); l != nil {
			txt := fmt.Sprintf("%s mtu %d", l.Name, l.MTU)
			if l.State == "DOWN" {
				txt = styleCrit.Render(txt + " DOWN")
			}
			parts = append(parts, txt)
		}
	}
	if ni.NetProbed {
		ok, fail, skip := 0, 0, 0
		var failed []string
		for _, p := range ni.NetProbes {
			switch {
			case p.Skip:
				skip++
			case p.OK:
				ok++
			default:
				fail++
				t := p.Kind
				if p.Node != "" {
					t += "→" + p.Node
				} else {
					t += " " + p.Target
				}
				failed = append(failed, t)
			}
		}
		txt := fmt.Sprintf("probes %d ok", ok)
		if fail > 0 {
			txt = styleCrit.Render(fmt.Sprintf("probes %d failed (%s), %d ok", fail, strings.Join(failed, ", "), ok))
		} else if ok > 0 {
			txt = styleOK.Render(txt)
		}
		if skip > 0 {
			txt += styleDim.Render(fmt.Sprintf(", %d skipped", skip))
		}
		parts = append(parts, txt)
	} else if len(ni.Links) > 0 {
		parts = append(parts, styleDim.Render("probes: with the next config collection (R)"))
	}
	return strings.Join(parts, "  ")
}
