package ui

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/helmcheck"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// action is a mutating CLI command that needs explicit confirmation.
type action struct {
	title string
	// short names the action in the header while it runs ("etcd defrag"),
	// where the title is too long. Not every action is a helm action.
	short  string
	argv   []string                                  // CLI form
	run    func(ctx context.Context) (string, error) // in-process form (API patch)
	desc   []string
	onFail string // what to do next when the command fails (shown under FAILED)
}

// label is what the header shows while the action runs.
func (a *action) label() string {
	if a == nil || a.short == "" {
		return "action"
	}
	return a.short
}

func (a *action) command() string {
	if a.run != nil {
		return "(API call)"
	}
	return strings.Join(a.argv, " ")
}

type actionDoneMsg struct {
	act *action
	out string
	err error
	dur time.Duration
}

// helmBase returns the helm binary plus kubeconfig/context flags.
func (a *App) helmBase() []string {
	argv := []string{a.cfg.Actions.HelmBinary}
	if a.cfg.Kubeconfig != "" {
		argv = append(argv, "--kubeconfig", a.cfg.Kubeconfig)
	}
	if a.client != nil && a.client.Context != "" {
		argv = append(argv, "--kube-context", a.client.Context)
	}
	return argv
}

// actionsAllowed checks the opt-out flag and that the helm binary exists.
func (a *App) actionsAllowed() bool {
	if !a.cfg.Actions.Enabled {
		a.setStatus("mutating actions are disabled (--read-only / actions.enabled: false)")
		return false
	}
	if _, err := exec.LookPath(a.cfg.Actions.HelmBinary); err != nil {
		a.setStatus("helm CLI not found: " + err.Error() + " (set actions.helm_binary)")
		return false
	}
	return true
}

func (a *App) selectedRelease() *k8s.HelmRelease {
	id := a.selectedID()
	for i := range a.snap.HelmReleases {
		r := &a.snap.HelmReleases[i]
		if r.Namespace+"/"+r.Name == id {
			return r
		}
	}
	return nil
}

// helmChartManifest finds the server/manifests file a user HelmChart CR
// came from, best effort: a non-bundled manifest on any server whose
// content declares that HelmChart.
func (a *App) helmChartManifest(name string) string {
	for _, n := range strutil.SortedKeys(a.nodes) {
		ni := a.nodes[n]
		if ni == nil {
			continue
		}
		for _, m := range ni.Manifests {
			if m.Bundled || !strings.Contains(m.Kinds, "HelmChart") || !strings.Contains(m.Content, "kind: HelmChart\n") {
				continue
			}
			if strings.Contains(m.Content, "name: "+name+"\n") || strings.Contains(m.Content, "name: "+name+" ") {
				return n + ":" + m.Path
			}
		}
	}
	return ""
}

// startHelmUpgrade prepares the upgrade to the newest known chart version:
// "helm upgrade" for a release helm installed, a spec.version patch on the
// HelmChart CR for one the rke2/k3s helm controller owns.
func (a *App) startHelmUpgrade() {
	rel := a.selectedRelease()
	if rel == nil {
		return
	}
	if rel.Bundled && rel.CRShipped {
		a.setStatus(rel.Name + " is a chart shipped inside rke2/k3s (HelmChart spec.chartContent): its version moves with the rke2 release; a HelmChartConfig changes only its values")
		return
	}
	if rel.Bundled {
		a.startHelmChartUpgrade(rel)
		return
	}
	if !a.actionsAllowed() {
		return
	}
	l, ok := a.helmLatest[helmKey(*rel)]
	if !ok || l.Version == "" {
		a.setStatus("no newer version known for " + rel.Chart + " (helm repo add its repository, or add it under helm.repos)")
		return
	}
	if helmcheck.CompareVersions(l.Version, rel.Version) <= 0 {
		a.setStatus(rel.Name + " is already at the latest known version " + rel.Version)
		return
	}
	if l.RepoURL == "" && l.Alias == "" {
		a.setStatus("no chart repository known for " + rel.Chart + " (helm repo add it, or add it under helm.repos)")
		return
	}
	// a repo the user added with `helm repo add` is referenced by alias so
	// helm applies its stored credentials; otherwise pass the URL
	var argv []string
	source := l.RepoURL + " (" + l.Source + ")"
	if l.Alias != "" {
		argv = append(a.helmBase(), "upgrade", rel.Name, l.Alias+"/"+rel.Chart, "--version", l.Version, "--namespace", rel.Namespace, "--reuse-values")
		source = l.Alias + "/" + rel.Chart + " from your helm repos (" + l.RepoURL + ")"
	} else {
		argv = append(a.helmBase(), "upgrade", rel.Name, rel.Chart, "--repo", l.RepoURL, "--version", l.Version, "--namespace", rel.Namespace, "--reuse-values")
	}
	a.pendingAct = &action{
		title:  fmt.Sprintf("Upgrade %s/%s: %s %s -> %s", rel.Namespace, rel.Name, rel.Chart, rel.Version, l.Version),
		short:  "helm upgrade",
		argv:   argv,
		onFail: fmt.Sprintf("the failed revision is now in the release history; B on the Helm tab rolls %s back to revision %d, b picks a revision", rel.Name, rel.Revision),
		desc: []string{
			"Source: " + source,
			"--reuse-values keeps the values currently applied (helm get values); new chart defaults are not merged.",
			"If the upgrade fails, B on the Helm tab rolls straight back to revision " + fmt.Sprint(rel.Revision) + " (b picks a revision).",
		},
	}
	a.overlay = ovConfirm
}

// helmStateHint explains what a non-deployed status means for a rollback.
func helmStateHint(rel *k8s.HelmRelease) string {
	switch st := strings.ToLower(rel.Status); {
	case st == "failed":
		return "Release is failed: revision " + fmt.Sprint(rel.Revision) + " did not go through (" + strutil.FirstLine(rel.Description) + ")."
	case strings.HasPrefix(st, "pending-"):
		return "Release is " + st + ": a helm " + strings.TrimPrefix(st, "pending-") + " never finished (killed, timed out, lost its connection). Make sure no helm/CI job is still working on it; a rollback is how a stuck release is unlocked."
	case st == "uninstalling":
		return "Release is uninstalling: an uninstall was interrupted; rolling back reinstates the selected revision."
	}
	return ""
}

// lastGoodOrExplain returns the revision to fall back to, or sets a status
// line saying why there is none.
func (a *App) lastGoodOrExplain(rel *k8s.HelmRelease) (k8s.HelmRevision, bool) {
	if g, ok := rel.LastGood(); ok {
		return g, true
	}
	if len(rel.History) < 2 {
		if rel.Healthy() {
			a.setStatus("no previous revision to roll back to (helm keeps history in release secrets; check --history-max)")
		} else {
			a.setStatus(fmt.Sprintf("%s/%s: the first install is %s and nothing was deployed before it, so there is nothing to roll back to; helm uninstall %s -n %s and reinstall (helm history %s -n %s shows the error)", rel.Namespace, rel.Name, rel.Status, rel.Name, rel.Namespace, rel.Name, rel.Namespace))
		}
		return k8s.HelmRevision{}, false
	}
	a.setStatus(fmt.Sprintf("%s/%s: no earlier revision ever deployed (all %d are failed/pending); b lets you pick one anyway, or helm uninstall and reinstall", rel.Namespace, rel.Name, len(rel.History)))
	return k8s.HelmRevision{}, false
}

// startHelmChartUpgrade upgrades a release the rke2/k3s helm controller
// owns by patching spec.version on its HelmChart CR (no helm binary
// needed): the controller re-runs its helm job with the new version.
func (a *App) startHelmChartUpgrade(rel *k8s.HelmRelease) {
	if !a.cfg.Actions.Enabled {
		a.setStatus("mutating actions are disabled (--read-only / actions.enabled: false)")
		return
	}
	l, ok := a.helmLatest[helmKey(*rel)]
	if !ok || l.Version == "" {
		a.setStatus("no newer version known for " + rel.Chart + " (the HelmChart's spec.repo index could not be read; see the LATEST column)")
		return
	}
	if helmcheck.CompareVersions(l.Version, rel.Version) <= 0 {
		a.setStatus(rel.Name + " is already at the latest known version " + rel.Version)
		return
	}
	crNS, name, version := rel.CRNamespace, rel.Name, l.Version
	if crNS == "" {
		crNS = rel.Namespace
	}
	client := a.client
	desc := []string{
		"Source: " + rel.ChartRepo + " (" + l.Source + ")",
		fmt.Sprintf("Patches spec.version of HelmChart %s/%s; the rke2/k3s helm controller then runs a helm-install-%s job that upgrades the release with the CR's valuesContent plus any HelmChartConfig, the same way it installed it.", crNS, name, name),
	}
	if f := a.helmChartManifest(name); f != "" {
		desc = append(desc, styleWarn.Render("The CR comes from "+f+": set version: "+version+" there too, or the next edit of that file puts "+rel.Version+" back."))
	} else {
		desc = append(desc, "If this HelmChart is applied from a file under server/manifests (or a GitOps repo), update spec.version there too or the next apply reverts it.")
	}
	desc = append(desc, "Progress: the Addons tab (rke2 HelmCharts) shows the job; "+fmt.Sprintf("B on the Helm tab rolls back to revision %d if it fails.", rel.Revision))
	a.pendingAct = &action{
		title:  fmt.Sprintf("Upgrade HelmChart %s/%s: %s %s -> %s", crNS, name, rel.Chart, rel.Version, version),
		short:  "HelmChart upgrade",
		desc:   desc,
		onFail: "the CR was not changed; kubectl -n " + crNS + " get helmchart " + name + " -o yaml shows its state",
		run: func(ctx context.Context) (string, error) {
			if err := client.SetHelmChartVersion(ctx, crNS, name, version); err != nil {
				return "", err
			}
			return fmt.Sprintf("helmchart.helm.cattle.io/%s patched: spec.version=%s\nthe helm controller's job helm-install-%s runs the upgrade now; refresh (r) to follow the release revision", name, version, name), nil
		},
	}
	a.overlay = ovConfirm
}

// startHelmRollback opens the revision picker for the selected release,
// preselecting the last revision that actually deployed.
func (a *App) startHelmRollback() {
	if !a.actionsAllowed() {
		return
	}
	rel := a.selectedRelease()
	if rel == nil {
		return
	}
	if len(rel.History) < 2 {
		a.lastGoodOrExplain(rel)
		return
	}
	a.revRelease = rel
	a.revCursor = 0
	target := -1
	if g, ok := rel.LastGood(); ok {
		target = g.Revision
	}
	for i, h := range rel.History {
		if (target >= 0 && h.Revision == target) || (target < 0 && h.Revision != rel.Revision) {
			a.revCursor = i
			break
		}
	}
	a.overlay = ovRevisions
}

// startHelmRollbackLastGood skips the picker: roll a failed or stuck release
// straight back to the last revision that deployed (B).
func (a *App) startHelmRollbackLastGood() {
	if !a.actionsAllowed() {
		return
	}
	rel := a.selectedRelease()
	if rel == nil {
		return
	}
	g, ok := a.lastGoodOrExplain(rel)
	if !ok {
		return
	}
	a.revRelease = rel
	a.confirmRollback(g)
}

func (a *App) confirmRollback(rev k8s.HelmRevision) {
	rel := a.revRelease
	if rel == nil {
		return
	}
	if rev.Revision == rel.Revision {
		a.setStatus("that is the current revision")
		return
	}
	argv := append(a.helmBase(), "rollback", rel.Name, fmt.Sprint(rev.Revision), "--namespace", rel.Namespace)
	desc := []string{fmt.Sprintf("Current: revision %d, %s %s, %s", rel.Revision, rel.Chart, rel.Version, rel.Status)}
	if h := helmStateHint(rel); h != "" {
		desc = append(desc, h)
	}
	if g, ok := rel.LastGood(); ok && g.Revision == rev.Revision {
		desc = append(desc, fmt.Sprintf("Revision %d is the last one that deployed (%s).", g.Revision, g.Status))
	} else if st := strings.ToLower(rev.Status); st == "failed" || strings.HasPrefix(st, "pending-") {
		desc = append(desc, styleWarn.Render(fmt.Sprintf("Revision %d is %s itself: it never ran successfully.", rev.Revision, rev.Status)))
	}
	desc = append(desc, "helm creates a new revision that reproduces the selected one (values and chart).")
	if rel.Bundled {
		desc = append(desc, styleWarn.Render("This release is owned by the rke2/k3s helm controller: it re-runs its helm job (back to the HelmChart's version and values) whenever the HelmChart CR or its HelmChartConfig changes, so the rollback holds only until then."))
	}
	a.pendingAct = &action{
		title: fmt.Sprintf("Rollback %s/%s to revision %d (%s %s, %s)", rel.Namespace, rel.Name, rev.Revision, rev.Chart, rev.Version, rev.Status),
		short: "helm rollback",
		argv:  argv,
		desc:  desc,
	}
	a.overlay = ovConfirm
}

// runAction executes the pending action in the background.
func (a *App) runAction(act *action) tea.Cmd {
	a.actionRunning, a.actionLabel = true, act.label()
	a.setStatus("running: " + act.command())
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		start := time.Now()
		if act.run != nil {
			out, err := act.run(ctx)
			return actionDoneMsg{act: act, out: out, err: err, dur: time.Since(start)}
		}
		cmd := exec.CommandContext(ctx, act.argv[0], act.argv[1:]...)
		out, err := cmd.CombinedOutput()
		return actionDoneMsg{act: act, out: string(out), err: err, dur: time.Since(start)}
	}
}

func (a *App) handleActionDone(m actionDoneMsg) tea.Cmd {
	a.actionRunning, a.actionLabel = false, ""
	lines := []string{styleDim.Render("$ " + m.act.command()), ""}
	for _, l := range strings.Split(strings.TrimRight(m.out, "\n"), "\n") {
		lines = append(lines, wrap(l, a.width-6)...)
	}
	lines = append(lines, "")
	if m.err != nil {
		lines = append(lines, styleCrit.Render("FAILED: "+m.err.Error())+styleDim.Render(fmt.Sprintf(" (%s; refreshing)", strutil.HumanDur(m.dur))))
		if m.act.onFail != "" {
			lines = append(lines, wrap(m.act.onFail, a.width-6)...)
		}
	} else {
		lines = append(lines, styleOK.Render("succeeded")+styleDim.Render(fmt.Sprintf(" in %s; refreshing", strutil.HumanDur(m.dur))))
	}
	a.setDetail(m.act.title, lines)
	// refresh after a failure too: a failed helm upgrade still leaves a new
	// (failed) revision behind, and that is what the rollback keys act on
	if !a.refreshing {
		return a.refreshCmd()
	}
	return nil
}

// handleActionOverlayKey handles keys for the confirm and revision overlays.
func (a *App) handleActionOverlayKey(key string) (tea.Model, tea.Cmd) {
	switch a.overlay {
	case ovConfirm:
		switch key {
		case "y", "Y":
			act := a.pendingAct
			a.pendingAct = nil
			a.overlay = ovNone
			return a, a.runAction(act)
		default:
			a.pendingAct = nil
			a.overlay = ovNone
			a.setStatus("canceled")
		}
	case ovRevisions:
		switch key {
		case "esc", "q":
			a.overlay = ovNone
		case "j", "down":
			if a.revRelease != nil && a.revCursor < len(a.revRelease.History)-1 {
				a.revCursor++
			}
		case "k", "up":
			if a.revCursor > 0 {
				a.revCursor--
			}
		case "enter":
			if a.revRelease != nil && a.revCursor < len(a.revRelease.History) {
				a.confirmRollback(a.revRelease.History[a.revCursor])
			}
		}
	}
	return a, nil
}

// renderActionOverlay returns title and lines for confirm/revision overlays.
func (a *App) renderActionOverlay() (string, []string) {
	switch a.overlay {
	case ovConfirm:
		if a.pendingAct == nil {
			return "", nil
		}
		lines := []string{styleBold.Render(a.pendingAct.title), ""}
		lines = append(lines, wrap("$ "+a.pendingAct.command(), a.width-6)...)
		lines = append(lines, "")
		for _, d := range a.pendingAct.desc {
			lines = append(lines, wrap(d, a.width-6)...)
		}
		lines = append(lines, "", styleWarn.Render("This changes the cluster. ")+styleKey.Render("y")+" runs it, any other key cancels.")
		return "Confirm action", lines
	case ovRevisions:
		rel := a.revRelease
		if rel == nil {
			return "", nil
		}
		lines := []string{styleDim.Render("j/k select, enter to roll back to that revision, esc cancels")}
		if h := helmStateHint(rel); h != "" {
			lines = append(lines, wrap(styleWarn.Render(h), a.width-6)...)
		}
		if g, ok := rel.LastGood(); ok {
			lines = append(lines, styleDim.Render(fmt.Sprintf("revision %d is the last one that deployed (preselected; B on the Helm tab goes there without this picker)", g.Revision)))
		}
		lines = append(lines, "")
		var rows [][]string
		for _, h := range rel.History {
			cur := ""
			if h.Revision == rel.Revision {
				cur = styleInfo.Render("current")
			} else if g, ok := rel.LastGood(); ok && g.Revision == h.Revision {
				cur = styleOK.Render("last good")
			}
			st := h.Status
			switch s := strings.ToLower(st); {
			case s == "deployed":
				st = styleOK.Render(st)
			case s == "failed", strings.HasPrefix(s, "pending-"):
				st = styleCrit.Render(st)
			default:
				st = styleDim.Render(st)
			}
			rows = append(rows, []string{fmt.Sprint(h.Revision), st, h.Chart + " " + h.Version, h.AppVersion, age(h.Updated) + " ago", strutil.FirstLine(h.Description), cur})
		}
		h, tl := renderTable(a.width-8, []column{{title: "REV", right: true}, {title: "STATUS"}, {title: "CHART"}, {title: "APP"}, {title: "UPDATED", right: true}, {title: "DESCRIPTION", max: 50}, {title: ""}}, rows)
		lines = append(lines, "  "+h)
		for i, l := range tl {
			if i == a.revCursor {
				lines = append(lines, selectRow("> "+l, a.width-6))
			} else {
				lines = append(lines, "  "+l)
			}
		}
		return "Rollback " + rel.Namespace + "/" + rel.Name, lines
	}
	return "", nil
}

// startEtcdDefrag prepares a cluster-wide etcd defragmentation: every
// member in turn through the etcd static pod (kubectl exec), followers
// first, the leader last, a health check after each. Forced: it runs
// whatever the fragmentation is; the confirmation shows what it will
// reclaim.
func (a *App) startEtcdDefrag() {
	if !a.cfg.Actions.Enabled {
		a.setStatus("mutating actions are disabled (--read-only / actions.enabled: false)")
		return
	}
	x := a.etcdExec
	if x == nil || x.Err != nil || len(x.Members) == 0 {
		a.setStatus("defrag needs the kubectl exec probe (etcdctl inside the etcd static pod; pods/exec on kube-system): it has not answered yet, or was refused")
		return
	}
	pod := strings.TrimPrefix(x.EtcdctlVia, "kubectl exec ")
	if a.snap == nil || pod == "" {
		return
	}
	if p, ok := a.snap.EtcdPods()[x.Node]; ok {
		pod = p.Name
	}
	leader := x.Leader()
	var rows []string
	frag := false
	for _, m := range x.Members {
		line := m.Name
		if m.ID == leader {
			line += " (leader, last)"
		}
		if m.IsLearner {
			line += " (learner, skipped)"
		}
		if st := x.Status(m.ID); st != nil && st.DBSize > 0 {
			f := 0.0
			if st.DBSizeInUse > 0 {
				f = float64(st.DBSize-st.DBSizeInUse) / float64(st.DBSize) * 100
			}
			if f >= float64(a.cfg.Thresholds.EtcdFragWarnPct) {
				frag = true
			}
			line += fmt.Sprintf(": db %s, %s in use, %.0f%% reclaimable", humanBytes(float64(st.DBSize)), humanBytes(float64(st.DBSizeInUse)), f)
		}
		rows = append(rows, "  "+line)
	}
	desc := []string{
		"Runs `etcdctl defrag` against one member at a time inside " + pod + " (kubectl exec), followers first and the leader last, and checks `endpoint health` after each; a member that does not come back healthy stops the run so at most one member is ever affected.",
		"Each member is blocked for the duration of its own defrag (seconds per GB of db, longer on slow disks): reads and writes to that member stall, and while the leader defragments the whole cluster's writes stall. Run it in a quiet moment.",
		"Defrag only rewrites the db file: it reclaims what compaction already freed (etcd's auto-compaction, or `etcdctl compact <rev>`). A NOSPACE alarm still needs `etcdctl alarm disarm` afterwards.",
		"Members now:",
	}
	desc = append(desc, rows...)
	if !frag {
		desc = append(desc, styleWarn.Render(fmt.Sprintf("No member is above the %d%% fragmentation threshold: this is a forced defrag, it will reclaim little.", a.cfg.Thresholds.EtcdFragWarnPct)))
	}
	if len(x.Alarms) > 0 {
		var al []string
		for _, al2 := range x.Alarms {
			al = append(al, al2.Type+"@"+al2.MemberID)
		}
		desc = append(desc, styleCrit.Render("Active alarms: "+strings.Join(al, " ")+" - disarm them after the defrag (etcdctl alarm disarm)."))
	}
	client := a.client
	members, dist := x.Members, x.Dist
	a.pendingAct = &action{
		title:  fmt.Sprintf("Defragment etcd: %d members, one at a time", len(members)),
		short:  "etcd defrag",
		desc:   desc,
		onFail: "check `etcdctl endpoint health` on every member before anything else; the etcd tab (r) shows which member is unhealthy",
		run: func(ctx context.Context) (string, error) {
			rep := etcd.Defrag(ctx, client, pod, dist, members, leader)
			if rep.Aborted != "" {
				return rep.String(), fmt.Errorf("%s", rep.Aborted)
			}
			return rep.String(), nil
		},
	}
	a.overlay = ovConfirm
}
