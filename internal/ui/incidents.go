package ui

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/rca"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// incidentPanes are the Incidents tab's views: the list, then one
// incident seen from each angle.
var incidentPanes = []string{"List", "Cause", "Workload", "Node", "Traffic", "Timeline", "Logs", "Cluster"}

// incState is the Incidents tab: the incidents built from the snapshot and
// the node journals (live) or from a log bundle (offline), and the context
// of the ones opened.
type incState struct {
	list    []rca.Incident
	tl      *rca.Timeline
	hyps    []rca.Hypothesis
	src     rca.Source
	builtOf string // what the list was built from (live: snapshot time + journal lines)
	kind    int    // type filter: 0 = all, i = rca.Kinds[i-1]
	open    string // the incident shown in the panes ("" = the list)
	listCur int    // list cursor to come back to
	ctx     map[string]*rca.Context
	loading string
	err     string
}

type incCtxMsg struct {
	id  string
	ctx *rca.Context
}

// incRefresh rebuilds the live incident list when the snapshot or the
// journals changed; an open incident keeps the list it came from.
func (a *App) incRefresh() {
	if a.offline != nil || a.snap == nil || a.inc.open != "" {
		return
	}
	lines := 0
	for _, s := range a.logSum {
		if s != nil {
			lines += s.Total
		}
	}
	var reach rca.Reach
	if a.sshEnabled {
		reach.SSH = a.sshDown
	}
	if a.apiDown != nil {
		f := *a.apiDown
		if a.sshEnabled {
			for _, name := range strutil.SortedKeys(a.nodes) {
				if a.nodes[name].Err == nil {
					f.SSHUp = append(f.SSHUp, name)
				}
			}
		}
		reach.API = &f
	}
	key := fmt.Sprintf("%d/%d/%d/%v", a.snap.Taken.UnixNano(), lines, len(reach.SSH), reach.API != nil)
	if key == a.inc.builtOf {
		return
	}
	a.inc.builtOf = key
	a.inc.tl = rca.BuildLive(a.snap, a.logSum, reach)
	for name, ni := range a.nodes {
		if ni != nil && ni.Hardening["container"] != "" {
			a.inc.tl.Containerized[name] = ni.Hardening["container"]
		}
		if ni != nil && ni.Uptime > 0 && !ni.Collected.IsZero() {
			a.inc.tl.Boots[name] = ni.Collected.Add(-ni.Uptime)
		}
	}
	a.inc.list = rca.Extract(a.inc.tl, a.snap)
	// the probable causes without pod logs: reading them is the API
	// round trip an opened incident pays for, not the list
	a.inc.hyps = rca.Analyze(a.liveSource(false), a.inc.tl)
	a.inc.ctx = map[string]*rca.Context{}
}

// noteSSH keeps when a node's probes started failing and the latest error;
// a probe that answers clears it.
func (a *App) noteSSH(info *nodeinfo.Info) {
	if info.Err == nil {
		delete(a.sshDown, info.Node)
		return
	}
	if a.sshDown == nil {
		a.sshDown = map[string]rca.SSHFailure{}
	}
	f, ok := a.sshDown[info.Node]
	if !ok {
		f.Since = info.Collected
		if f.Since.IsZero() {
			f.Since = time.Now()
		}
	}
	f.Err = info.Err.Error()
	a.sshDown[info.Node] = f
}

// noteAPI keeps when the API stopped answering (no nodes listed, errors
// that say it did not answer) and the latest error; an answer clears it.
func (a *App) noteAPI(s *k8s.Snapshot) {
	if s == nil || len(s.Nodes) > 0 || !k8s.Unreachable(s.Errors) {
		a.apiDown = nil
		return
	}
	if a.apiDown == nil {
		a.apiDown = &rca.APIFailure{Since: s.Taken}
		if a.apiDown.Since.IsZero() {
			a.apiDown.Since = time.Now()
		}
	}
	a.apiDown.Err = rca.FirstUnreachable(s.Errors)
}

func (a *App) incFiltered() []rca.Incident {
	if a.inc.kind == 0 {
		return a.inc.list
	}
	k := rca.Kinds[a.inc.kind-1]
	var out []rca.Incident
	for _, in := range a.inc.list {
		if in.Kind == k {
			out = append(out, in)
		}
	}
	return out
}

func (a *App) incByID(id string) *rca.Incident {
	for i := range a.inc.list {
		if a.inc.list[i].ID == id {
			return &a.inc.list[i]
		}
	}
	return nil
}

// incidentsContent renders the list or the open incident's pane.
func (a *App) incidentsContent() content {
	a.incRefresh()
	if a.inc.open == "" {
		return a.incListContent()
	}
	return a.incPaneContent()
}

func incKindStyle(k rca.Kind) interface{ Render(...string) string } {
	switch k {
	case rca.KindAPI, rca.KindReboot, rca.KindOOM, rca.KindNodeOOM, rca.KindEviction, rca.KindNotReady, rca.KindSSH:
		return styleCrit
	case rca.KindRestart, rca.KindProbe, rca.KindPull, rca.KindSchedule, rca.KindPressure, rca.KindRejected, rca.KindDrain:
		return styleWarn
	}
	return styleInfo
}

func (a *App) incListContent() content {
	count := map[rca.Kind]int{}
	for _, in := range a.inc.list {
		count[in.Kind]++
	}
	chip := func(on bool, s string) string {
		if on {
			return styleSubOn.Render(s)
		}
		return styleDim.Render(s)
	}
	chips := []string{chip(a.inc.kind == 0, fmt.Sprintf(" all %d ", len(a.inc.list)))}
	for i, k := range rca.Kinds {
		if count[k] > 0 || a.inc.kind == i+1 {
			chips = append(chips, chip(a.inc.kind == i+1, fmt.Sprintf(" %s %d ", k.Label(), count[k])))
		}
	}
	where := "live: events, pod states and the node journals khealth collects"
	if a.offline != nil {
		where = "bundle gathered " + a.offline.Bundle.Manifest.Created.Local().Format("2006-01-02 15:04")
	}
	hdr := flow(a.width-2, 0, append([]string{styleTitle.Render("Incidents")}, chips...)...)
	hdr = append(hdr, hint("§t§ type  §enter§/§l§ open  §/§ find")+"  "+styleDim.Render(where))
	if len(a.inc.hyps) > 0 {
		hdr = append(hdr, styleBold.Render("Probable causes"))
		for i, h := range a.inc.hyps {
			if i >= 3 {
				hdr = append(hdr, styleDim.Render(fmt.Sprintf("  +%d more (khealth --analyze prints them all)", len(a.inc.hyps)-3)))
				break
			}
			st := styleInfo
			switch h.Confidence() {
			case "high":
				st = styleCrit
			case "medium":
				st = styleWarn
			}
			hdr = append(hdr, trunc("  "+st.Render("["+h.Confidence()+"]")+" "+h.Title+styleDim.Render("  "+h.Cause), a.width-2))
		}
	}
	list := a.incFiltered()
	cols := []column{{title: "WHEN", max: 15}, {title: "N", right: true, max: 5}, {title: "TYPE", max: 14}, {title: "WHAT", max: 48}, {title: "NODE", max: 18}, {title: "LAST"}}
	var cells [][]string
	for _, in := range list {
		n := ""
		if in.Count > 1 {
			n = fmt.Sprintf("x%d", in.Count)
		}
		cells = append(cells, []string{in.Time.Local().Format("Jan 02 15:04:05"), n, incKindStyle(in.Kind).Render(in.Kind.Label()), in.Object(), in.Node, in.Short()})
	}
	th, lines := renderTable(a.width-2, cols, cells)
	c := content{header: append(hdr, "", th), selectable: true}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: list[i].ID, text: l})
	}
	if len(list) == 0 {
		c.empty = "no incidents in the events, pod states and node journals"
		if a.offline == nil && len(a.logSum) == 0 {
			c.empty += " (the node journals arrive with the journal tier: a moment after the tab opens)"
		}
	}
	return c
}

// openIncident shows an incident's panes; its context is computed once
// (offline right away, live in the background: it reads pod logs and lists
// through the API).
func (a *App) openIncident(id string) tea.Cmd {
	in := a.incByID(id)
	if in == nil {
		return nil
	}
	if a.inc.open == "" {
		a.inc.listCur = a.cursor[tabIncidents]
	}
	a.inc.open = id
	a.sub[tabIncidents] = 1
	a.cursor[tabIncidents], a.scroll[tabIncidents] = 0, 0
	a.filters[tabIncidents] = ""
	if a.inc.ctx == nil {
		a.inc.ctx = map[string]*rca.Context{}
	}
	if _, ok := a.inc.ctx[id]; ok {
		return nil
	}
	inc, list, tl := *in, a.inc.list, a.inc.tl
	if a.offline != nil {
		a.inc.ctx[id] = inc.Context(a.inc.src, tl, list, rca.DefaultWindow)
		return nil
	}
	a.inc.loading = id
	src := a.liveSource(true)
	return func() tea.Msg {
		return incCtxMsg{id: id, ctx: inc.Context(src, tl, list, rca.DefaultWindow)}
	}
}

func (a *App) closeIncident() {
	a.inc.open = ""
	a.sub[tabIncidents] = 0
	a.cursor[tabIncidents], a.scroll[tabIncidents] = a.inc.listCur, 0
	a.filters[tabIncidents] = ""
}

// incSetPane moves between the panes of the open incident. The Timeline
// opens on the incident itself, not at the top of its window.
func (a *App) incSetPane(delta int) {
	n := a.sub[tabIncidents] + delta
	if n < 1 {
		n = 1
	}
	if n >= len(incidentPanes) {
		n = len(incidentPanes) - 1
	}
	if n == a.sub[tabIncidents] {
		return
	}
	a.sub[tabIncidents] = n
	a.cursor[tabIncidents], a.scroll[tabIncidents] = 0, 0
	in, ctx := a.incByID(a.inc.open), a.inc.ctx[a.inc.open]
	if incidentPanes[n] != "Timeline" || in == nil || ctx == nil {
		return
	}
	for i, g := range rca.Collapse(ctx.Timeline) {
		if !g.First.Before(in.Time) {
			a.cursor[tabIncidents] = i
			a.scroll[tabIncidents] = max(0, i-5)
			return
		}
	}
}

// handleIncidentKey is the tab's own keys; handled=false falls through to
// the generic ones (movement, find, tabs).
func (a *App) handleIncidentKey(key string) (tea.Cmd, bool) {
	switch key {
	case "t":
		if a.inc.open == "" {
			a.inc.kind = (a.inc.kind + 1) % (len(rca.Kinds) + 1)
			a.cursor[tabIncidents], a.scroll[tabIncidents] = 0, 0
			return nil, true
		}
	case "enter":
		id := a.selectedID()
		if a.inc.open == "" {
			return a.openIncident(id), true
		}
		switch {
		case strings.HasPrefix(id, "inc:"):
			return a.openIncident(strings.TrimPrefix(id, "inc:")), true
		case strings.HasPrefix(id, "pod:"):
			ns, pod, _ := strings.Cut(strings.TrimPrefix(id, "pod:"), "/")
			return a.openPodLogs(ns, pod, nil), true
		case strings.HasPrefix(id, "tl:"):
			a.setDetail(a.incidentDetail(id))
			return nil, true
		}
		return nil, true
	case "l", "right":
		if a.inc.open == "" {
			return a.openIncident(a.selectedID()), true
		}
		a.incSetPane(1)
		return nil, true
	case "h", "left":
		if a.inc.open != "" && a.sub[tabIncidents] <= 1 {
			a.closeIncident()
		} else if a.inc.open != "" {
			a.incSetPane(-1)
		}
		return nil, true
	case "esc", "q", "backspace":
		if a.inc.open != "" && !a.filterOn && a.filters[tabIncidents] == "" {
			a.closeIncident()
			return nil, true
		}
	case "L":
		if in := a.incByID(a.inc.open); in != nil && in.Pod != "" {
			return a.openPodLogs(in.Namespace, in.Pod, nil), true
		}
	}
	return nil, false
}

func (a *App) incPaneContent() content {
	in := a.incByID(a.inc.open)
	if in == nil {
		a.closeIncident()
		return a.incListContent()
	}
	pane := incidentPanes[max(1, min(a.sub[tabIncidents], len(incidentPanes)-1))]
	hdr := []string{
		styleTitle.Render(in.ID) + "  " + incKindStyle(in.Kind).Render(in.Kind.Label()) + "  " + styleBold.Render(in.Object()),
		flow(a.width-2, 2, kv("when", in.Time.Local().Format("Jan 02 15:04:05")+countSuffix(in)), kv("node", orDash(in.Node)), kv("workload", orDash(in.Workload)))[0],
	}
	hdr = append(hdr, "  "+trunc(in.Short(), a.width-4))
	hdr = append(hdr, hint("§esc§ list  §h/l§ views  §enter§ open the row  §L§ pod logs"), "")
	c := content{header: hdr}
	ctx := a.inc.ctx[in.ID]
	if ctx == nil {
		c.empty = "reading the workload, the node, the traffic and the logs around it..."
		c.spin = true
		return c
	}
	var rows []row
	add := func(id, text string) { rows = append(rows, row{id: id, text: text}) }
	w := a.width - 2
	switch pane {
	case "Cause":
		for _, l := range wrap(oneLine(in.Summary), w-2) {
			add("", styleDim.Render("  "+l))
		}
		add("", "")
		if ctx.Verdict != "" {
			for _, l := range wrap(ctx.Verdict, w) {
				add("", styleBold.Render(l))
			}
			add("", "")
		}
		if len(ctx.Suspects) == 0 {
			add("", styleDim.Render("no other workload or event points at it"))
		}
		for _, s := range ctx.Suspects {
			add("", fmt.Sprintf("%s  %s", scoreStyle(s.Score).Render(fmt.Sprintf("%3.0f%%", s.Score*100)), styleBold.Render(s.Who)))
			for _, r := range s.Reasons {
				for i, l := range wrap(r, w-8) {
					p := "      - "
					if i > 0 {
						p = "        "
					}
					add("", p+l)
				}
			}
		}
		if len(ctx.Related) > 0 {
			add("", "")
			add("", styleBold.Render(fmt.Sprintf("Around it (+/- %s)", ctx.Window))+styleDim.Render("  enter opens one"))
			for _, o := range ctx.Related {
				add("inc:"+o.ID, fmt.Sprintf("  %s  %s %s", o.Time.Local().Format("15:04:05"), incKindStyle(o.Kind).Render(fmt.Sprintf("%-14s", o.Kind.Label())), o.Object()))
			}
		}
	case "Workload":
		wv := ctx.Workload
		if wv == nil {
			add("", styleDim.Render("no workload: the incident is about a node or the cluster"))
			break
		}
		line := styleBold.Render(wv.Kind+"/"+wv.Name) + "  " + kv("namespace", wv.Namespace)
		if wv.Desired > 0 {
			line += "  " + kv("ready", fmt.Sprintf("%d/%d", wv.Ready, wv.Desired))
		}
		add("", line+"  "+kv("nodes", strings.Join(wv.Nodes, ", ")))
		if len(wv.Revisions) > 0 {
			add("", "")
			add("", styleBold.Render("Revisions"))
			for _, r := range wv.Revisions {
				mark := ""
				if r.Recent {
					mark = styleWarn.Render(fmt.Sprintf("  <- rolled out %s before", in.Time.Sub(r.Created).Round(time.Second)))
				}
				add("", fmt.Sprintf("  rev %-3s %s  pods %d  %s%s", r.Number, r.Created.Local().Format("Jan 02 15:04"), r.Replicas, strings.Join(r.Images, ","), mark))
			}
		}
		add("", "")
		add("", styleBold.Render("Pods")+styleDim.Render("  enter = logs"))
		for _, p := range wv.Pods {
			add("pod:"+p.Namespace+"/"+p.Name, fmt.Sprintf("  %-48s %-22s restarts %-3d mem %s / %s", trunc(p.Name, 48), trunc(p.Phase, 22), p.Restarts, memText(p.UseMem), memText(p.LimMem)))
		}
	case "Node":
		sh := ctx.Node
		if sh == nil {
			add("", styleDim.Render("the incident names no node"))
			break
		}
		add("", styleBold.Render(sh.Name)+"  "+styleDim.Render(strings.Join(sh.Roles, ","))+"  "+styleCrit.Render(strings.Join(sh.Conditions, " ")))
		add("", fmt.Sprintf("  requests  cpu %s  memory %s", pctBar(sh.ReqCPU, sh.AllocCPU, fmt.Sprintf("%dm of %dm", sh.ReqCPU, sh.AllocCPU)), pctBar(sh.ReqMem, sh.AllocMem, humanBytes(float64(sh.ReqMem))+" of "+humanBytes(float64(sh.AllocMem)))))
		if sh.UseMem >= 0 {
			add("", fmt.Sprintf("  in use    cpu %s  memory %s  %s", pctBar(sh.UseCPU, sh.AllocCPU, fmt.Sprintf("%dm", sh.UseCPU)), pctBar(sh.UseMem, sh.AllocMem, humanBytes(float64(sh.UseMem))), styleDim.Render("(when gathered, not at the incident)")))
		}
		add("", "")
		// the suspects first (with their score), then the incident's own
		// pod, then the rest by memory: the pods that matter at the top
		score := map[string]float64{}
		for _, s := range ctx.Suspects {
			who, _, _ := strings.Cut(s.Who, " ")
			score[who] = s.Score
		}
		pods := append([]rca.PodShape(nil), sh.Pods...)
		rank := func(p rca.PodShape) float64 {
			if sc, ok := score[p.Namespace+"/"+p.Name]; ok {
				return 2 + sc
			}
			if p.Victim {
				return 1.5
			}
			return 0
		}
		sort.SliceStable(pods, func(i, j int) bool { return rank(pods[i]) > rank(pods[j]) })
		cols := []column{{title: "POD", max: 50}, {title: "SUSPECT", right: true}, {title: "QOS", max: 10}, {title: "PRIO", right: true, max: 10}, {title: "MEM REQ", right: true}, {title: "MEM LIM", right: true}, {title: "MEM USE", right: true}, {title: "ARRIVED", right: true}, {title: ""}}
		var cells [][]string
		var ids []string
		for _, p := range pods {
			var flags []string
			if p.Victim {
				flags = append(flags, styleCrit.Render("this incident"))
			}
			if strings.Contains(p.Phase, "Evicted") {
				flags = append(flags, styleDim.Render("evicted"))
			}
			sus := ""
			if sc, ok := score[p.Namespace+"/"+p.Name]; ok {
				sus = scoreStyle(sc).Render(fmt.Sprintf("%.0f%%", sc*100))
			}
			arrived := ""
			if p.Arrived > 0 {
				arrived = p.Arrived.Round(time.Second).String() + " before"
			}
			cells = append(cells, []string{p.Namespace + "/" + p.Name, sus, p.QoS, fmt.Sprint(p.Priority), memText(p.ReqMem), memText(p.LimMem), memText(p.UseMem), arrived, strings.Join(flags, " ")})
			ids = append(ids, "pod:"+p.Namespace+"/"+p.Name)
		}
		th, lines := renderTable(w, cols, cells)
		add("", th)
		for i, l := range lines {
			add(ids[i], l)
		}
	case "Traffic":
		iv := ctx.Ingress
		if iv == nil {
			add("", styleDim.Render("no pods to match traffic against"))
			break
		}
		if len(iv.Services) > 0 {
			add("", kv("services", strings.Join(iv.Services, ", ")))
		}
		if len(iv.Routes) > 0 {
			add("", kv("routes", strings.Join(iv.Routes, "; ")))
		}
		if len(iv.Controllers) > 0 {
			add("", kv("controller logs", strings.Join(iv.Controllers, ", ")))
		}
		if iv.Note != "" {
			add("", styleDim.Render(iv.Note))
		}
		maxReq := 1
		for _, m := range iv.Minutes {
			maxReq = max(maxReq, m.Requests)
		}
		if len(iv.Minutes) > 0 {
			add("", "")
			add("", styleBold.Render("Requests per minute")+styleDim.Render("  (red = 5xx)"))
		}
		for _, m := range iv.Minutes {
			mark := ""
			if !in.Time.Before(m.Start) && in.Time.Before(m.Start.Add(time.Minute)) {
				mark = styleCrit.Render("  <- incident")
			}
			width := 30
			ok := (m.Requests - m.Errors5xx) * width / maxReq
			bad := m.Errors5xx * width / maxReq
			if m.Errors5xx > 0 && bad == 0 {
				bad = 1
			}
			add("", fmt.Sprintf("  %s %s%s%s %5d req %4d 5xx %4d 4xx  p95 %-7s%s", m.Start.Local().Format("15:04"),
				styleOK.Render(strings.Repeat("█", ok)), styleCrit.Render(strings.Repeat("█", bad)), strings.Repeat(" ", max(0, width-ok-bad)),
				m.Requests, m.Errors5xx, m.Errors4xx, m.P95.Round(time.Millisecond), mark))
		}
		if len(iv.Errors) > 0 {
			add("", "")
			add("", styleBold.Render("5xx closest to the incident"))
			for _, r := range iv.Errors {
				add("", fmt.Sprintf("  %s %s %s %s -> %s", r.Time.Local().Format("15:04:05"), styleCrit.Render(fmt.Sprint(r.Status)), r.Method, r.Path, r.Upstream))
			}
		}
	case "Timeline":
		groups := rca.Collapse(ctx.Timeline)
		if len(groups) == 0 {
			add("", styleDim.Render("nothing else logged on the node, in the namespace or by the control plane around it"))
		}
		for i, g := range groups {
			when := g.First.Local().Format("15:04:05")
			if g.Count > 1 {
				when += fmt.Sprintf(" x%-3d", g.Count)
			} else {
				when += "     "
			}
			node := g.Entry.Node
			if node == "" {
				node = "cluster"
			}
			add(fmt.Sprintf("tl:%d", i), fmt.Sprintf("%s %s %-14s %-20s %-28s %s", when, classStyle(g.Entry.Class).Render(fmt.Sprintf("%-5s", g.Entry.Class)), trunc(node, 14), trunc(g.Entry.Pattern, 20), trunc(g.Entry.Unit, 28), oneLine(g.Entry.Text)))
		}
	case "Logs":
		if len(ctx.LogTail) == 0 {
			add("", styleDim.Render("no log of the container (the incident names none, or it logged nothing)"))
			break
		}
		add("", styleDim.Render(ctx.LogRef))
		for _, l := range ctx.LogTail {
			add("", trunc(renderLogLine(l), w))
		}
	case "Cluster":
		cols := []column{{title: "NODE", max: 24}, {title: "ROLES", max: 24}, {title: "READY"}, {title: "PODS", right: true}, {title: "CPU REQ", right: true}, {title: "MEM REQ", right: true}, {title: "CPU USE", right: true}, {title: "MEM USE", right: true}, {title: "PRESSURE"}}
		var cells [][]string
		for _, n := range ctx.Cluster {
			use := func(p int) string {
				if p < 0 {
					return "-"
				}
				return pctText(float64(p), 75, 90)
			}
			ready := styleOK.Render(n.Ready)
			if n.Ready != "True" {
				ready = styleCrit.Render(n.Ready)
			}
			name := n.Name
			if n.Name == in.Node {
				name = styleBold.Render(n.Name + " *")
			}
			cells = append(cells, []string{name, strings.Join(n.Roles, ","), ready, fmt.Sprint(n.Pods), pctText(float64(n.CPUReqPct), 75, 90), pctText(float64(n.MemReqPct), 75, 90), use(n.CPUUsePct), use(n.MemUsePct), styleCrit.Render(strings.Join(n.Pressure, " "))})
		}
		th, lines := renderTable(w, cols, cells)
		add("", th)
		for _, l := range lines {
			add("", l)
		}
		add("", "")
		add("", styleDim.Render("* the incident's node. Requests are the pods present now; usage is metrics-server when gathered."))
	}
	c.rows = rows
	c.selectable = true
	return c
}

// incidentDetail shows one timeline entry with its evidence: offline, the
// lines around it in the bundle file.
func (a *App) incidentDetail(id string) (string, []string) {
	ctx := a.inc.ctx[a.inc.open]
	if ctx == nil || !strings.HasPrefix(id, "tl:") {
		return "", nil
	}
	var i int
	if _, err := fmt.Sscan(strings.TrimPrefix(id, "tl:"), &i); err != nil {
		return "", nil
	}
	groups := rca.Collapse(ctx.Timeline)
	if i < 0 || i >= len(groups) {
		return "", nil
	}
	g := groups[i]
	e := g.Entry
	w := a.width - 6
	out := []string{
		classStyle(e.Class).Render(e.Class.String()) + "  " + kv("pattern", e.Pattern) + "  " + kv("node", orDash(e.Node)) + "  " + kv("unit", orDash(e.Unit)),
		kv("time", e.Time.Local().Format(time.RFC3339Nano)) + countText(g),
		kv("source", e.Ref.String()),
		"",
	}
	out = append(out, wrapStyled(e.Text, w)...)
	if p := logs.Find(e.Pattern); p != nil {
		out = append(out, "", styleBold.Render("What it means"))
		out = append(out, wrap(p.Explain, w)...)
	}
	if a.offline != nil && e.Ref.Line > 0 {
		lines := readFileLines(a.offline.Bundle.Path(e.Ref.File))
		if len(lines) > 0 {
			out = append(out, "", styleBold.Render("In the bundle file"))
			for n := max(1, e.Ref.Line-5); n <= min(len(lines), e.Ref.Line+5); n++ {
				t := fmt.Sprintf("%6d  %s", n, lines[n-1])
				if n == e.Ref.Line {
					t = styleBold.Render(t)
				} else {
					t = styleDim.Render(t)
				}
				out = append(out, trunc(t, w))
			}
		}
	}
	return "Evidence", out
}

func countText(g rca.Group) string {
	if g.Count < 2 {
		return ""
	}
	return fmt.Sprintf("  (x%d until %s)", g.Count, g.Last.Local().Format("15:04:05"))
}

func countSuffix(in *rca.Incident) string {
	if in.Count < 2 {
		return ""
	}
	return fmt.Sprintf(" .. %s (x%d)", in.Last.Local().Format("15:04:05"), in.Count)
}

func scoreStyle(s float64) interface{ Render(...string) string } {
	switch {
	case s >= 0.75:
		return styleCrit
	case s >= 0.5:
		return styleWarn
	}
	return styleDim
}

func pctBar(v, of int64, label string) string {
	f := 0.0
	if of > 0 {
		f = float64(v) / float64(of)
	}
	st := styleOK
	switch {
	case f >= 0.9:
		st = styleCrit
	case f >= 0.75:
		st = styleWarn
	}
	return bar(f, 12, st) + " " + label
}

func memText(b int64) string {
	switch {
	case b < 0:
		return "?"
	case b == 0:
		return "-"
	}
	return humanBytes(float64(b))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func readFileLines(p string) []string {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// ---- the live source ------------------------------------------------------------

// liveSource reads what an incident's context needs beyond the snapshot
// through the API: ReplicaSets, pod metrics, HTTPRoutes and pod logs. It
// holds copies, so the background computation never races the UI.
type liveSource struct {
	snap   *k8s.Snapshot
	nodes  map[string]*nodeinfo.Info
	client *k8s.Client
	logs   bool

	mu   sync.Mutex
	objs map[string][]unstructured.Unstructured
}

func (a *App) liveSource(withLogs bool) *liveSource {
	nodes := make(map[string]*nodeinfo.Info, len(a.nodes))
	for k, v := range a.nodes {
		nodes[k] = v
	}
	return &liveSource{snap: a.snap, nodes: nodes, client: a.client, logs: withLogs, objs: map[string][]unstructured.Unstructured{}}
}

var liveGVR = map[string]schema.GroupVersionResource{
	"replicasets.apps":                     {Group: "apps", Version: "v1", Resource: "replicasets"},
	"pods.metrics.k8s.io":                  {Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"},
	"httproutes.gateway.networking.k8s.io": {Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"},
}

func (s *liveSource) Snap() *k8s.Snapshot             { return s.snap }
func (s *liveSource) Node(name string) *nodeinfo.Info { return s.nodes[name] }
func (s *liveSource) SSHStatus(string) string         { return "" }
func (s *liveSource) Objects(resource string) []unstructured.Unstructured {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.objs[resource]; ok {
		return l
	}
	var out []unstructured.Unstructured
	if gvr, ok := liveGVR[resource]; ok && s.client != nil && s.client.Dyn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if l, err := s.client.Dyn.Resource(gvr).List(ctx, metav1.ListOptions{}); err == nil {
			out = l.Items
		}
		cancel()
	}
	s.objs[resource] = out
	return out
}

func (s *liveSource) PodLog(ns, pod, container string, previous bool) ([]string, string) {
	if !s.logs || s.client == nil || s.client.CS == nil {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tail := int64(2000)
	rc, err := s.client.CS.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: container, Previous: previous, Timestamps: true, TailLines: &tail}).Stream(ctx)
	if err != nil {
		return nil, ""
	}
	defer rc.Close()
	var out []string
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	ref := "kubectl logs " + pod + " -n " + ns + " -c " + container
	if previous {
		ref += " --previous"
	}
	return out, ref
}
