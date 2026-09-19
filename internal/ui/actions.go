package ui

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"k8s-health-tui/internal/helmcheck"
	"k8s-health-tui/internal/k8s"
)

// action is a mutating CLI command that needs explicit confirmation.
type action struct {
	title string
	argv  []string
	desc  []string
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

// startHelmUpgrade prepares "helm upgrade" to the newest known chart version.
func (a *App) startHelmUpgrade() {
	if !a.actionsAllowed() {
		return
	}
	rel := a.selectedRelease()
	if rel == nil {
		return
	}
	if rel.Bundled {
		a.setStatus("release is managed by the rke2/k3s HelmChart controller: change its HelmChartConfig or upgrade rke2 instead")
		return
	}
	l, ok := a.helmLatest[rel.Chart]
	if !ok || l.Version == "" {
		a.setStatus("no newer version known for " + rel.Chart + " (enable helm.check_updates with helm.repos / artifacthub)")
		return
	}
	if helmcheck.CompareVersions(l.Version, rel.Version) <= 0 {
		a.setStatus(rel.Name + " is already at the latest known version " + rel.Version)
		return
	}
	if l.RepoURL == "" {
		a.setStatus("no chart repository URL known for " + rel.Chart + " (add it under helm.repos)")
		return
	}
	argv := append(a.helmBase(), "upgrade", rel.Name, rel.Chart, "--repo", l.RepoURL, "--version", l.Version, "--namespace", rel.Namespace, "--reuse-values")
	a.pendingAct = &action{
		title: fmt.Sprintf("Upgrade %s/%s: %s %s -> %s", rel.Namespace, rel.Name, rel.Chart, rel.Version, l.Version),
		argv:  argv,
		desc: []string{
			"Source: " + l.RepoURL + " (" + l.Source + ")",
			"--reuse-values keeps the values currently applied (helm get values); new chart defaults are not merged.",
			"A failed upgrade can be undone with rollback (b) to revision " + fmt.Sprint(rel.Revision) + ".",
		},
	}
	a.overlay = ovConfirm
}

// startHelmRollback opens the revision picker for the selected release.
func (a *App) startHelmRollback() {
	if !a.actionsAllowed() {
		return
	}
	rel := a.selectedRelease()
	if rel == nil {
		return
	}
	if len(rel.History) < 2 {
		a.setStatus("no previous revision to roll back to (helm keeps history in release secrets; check --history-max)")
		return
	}
	a.revRelease = rel
	a.revCursor = 0
	for i, h := range rel.History {
		if h.Revision != rel.Revision {
			a.revCursor = i
			break
		}
	}
	a.overlay = ovRevisions
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
	a.pendingAct = &action{
		title: fmt.Sprintf("Rollback %s/%s to revision %d (%s %s, %s)", rel.Namespace, rel.Name, rev.Revision, rev.Chart, rev.Version, rev.Status),
		argv:  argv,
		desc: []string{
			fmt.Sprintf("Current: revision %d, %s %s, %s", rel.Revision, rel.Chart, rel.Version, rel.Status),
			"helm creates a new revision that reproduces the selected one (values and chart).",
		},
	}
	a.overlay = ovConfirm
}

// runAction executes the pending action in the background.
func (a *App) runAction(act *action) tea.Cmd {
	a.actionRunning = true
	a.setStatus("running: " + strings.Join(act.argv, " "))
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		start := time.Now()
		cmd := exec.CommandContext(ctx, act.argv[0], act.argv[1:]...)
		out, err := cmd.CombinedOutput()
		return actionDoneMsg{act: act, out: string(out), err: err, dur: time.Since(start)}
	}
}

func (a *App) handleActionDone(m actionDoneMsg) tea.Cmd {
	a.actionRunning = false
	lines := []string{styleDim.Render("$ " + strings.Join(m.act.argv, " ")), ""}
	for _, l := range strings.Split(strings.TrimRight(m.out, "\n"), "\n") {
		lines = append(lines, wrap(l, a.width-6)...)
	}
	lines = append(lines, "")
	if m.err != nil {
		lines = append(lines, styleCrit.Render("FAILED: "+m.err.Error())+styleDim.Render(fmt.Sprintf(" (%s)", humanDur(m.dur))))
	} else {
		lines = append(lines, styleOK.Render("succeeded")+styleDim.Render(fmt.Sprintf(" in %s; refreshing", humanDur(m.dur))))
	}
	a.detailTitle = m.act.title
	a.detailLines = lines
	a.detailScroll = 0
	a.overlay = ovDetail
	if m.err == nil && !a.refreshing {
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
			a.setStatus("cancelled")
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
		lines = append(lines, wrap("$ "+strings.Join(a.pendingAct.argv, " "), a.width-6)...)
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
		lines := []string{styleDim.Render("j/k select, enter to roll back to that revision, esc cancels"), ""}
		var rows [][]string
		for _, h := range rel.History {
			cur := ""
			if h.Revision == rel.Revision {
				cur = styleInfo.Render("current")
			}
			st := h.Status
			switch strings.ToLower(st) {
			case "deployed":
				st = styleOK.Render(st)
			case "failed":
				st = styleCrit.Render(st)
			default:
				st = styleDim.Render(st)
			}
			rows = append(rows, []string{fmt.Sprint(h.Revision), st, h.Chart + " " + h.Version, h.AppVersion, age(h.Updated) + " ago", firstLine(h.Description), cur})
		}
		h, tl := renderTable(a.width-8, []column{{title: "REV", right: true}, {title: "STATUS"}, {title: "CHART"}, {title: "APP"}, {title: "UPDATED", right: true}, {title: "DESCRIPTION", max: 50}, {title: ""}}, rows)
		lines = append(lines, "  "+h)
		for i, l := range tl {
			if i == a.revCursor {
				lines = append(lines, styleSel.Render("> "+l))
			} else {
				lines = append(lines, "  "+l)
			}
		}
		return "Rollback " + rel.Namespace + "/" + rel.Name, lines
	}
	return "", nil
}
