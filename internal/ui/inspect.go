package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s-health-tui/internal/k8s"
)

// inspectLevel is one page of the object inspector (a stack of these forms
// the drill-down history).
type inspectLevel struct {
	title   string
	meta    []string     // summary lines
	refs    []k8s.ObjRef // navigable references
	dump    []string     // object YAML
	cursor  int
	scroll  int
	loading bool
	err     string
}

type inspectMsg struct {
	seq   int
	level inspectLevel
}

// openInspectRef pushes a loading level and fetches the object.
func (a *App) openInspectRef(ref k8s.ObjRef) tea.Cmd {
	lvl := inspectLevel{title: refTitle(ref), loading: true}
	a.inspect = append(a.inspect, lvl)
	a.showInspect()
	a.inspectSeq++
	seq := a.inspectSeq
	client := a.client
	snap := a.snap
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		u, err := client.GetObject(ctx, ref)
		if err != nil {
			return inspectMsg{seq: seq, level: inspectLevel{title: refTitle(ref), err: err.Error()}}
		}
		lvl := levelFromObject(u, snap)
		// controllers whose children are not in the snapshot (ReplicaSets)
		switch u.GetKind() {
		case "Deployment":
			if kids, err := client.ChildrenOf(ctx, schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, u.GetNamespace(), u.GetUID()); err == nil {
				lvl.refs = append(lvl.refs, kids...)
			}
		case "CronJob":
			if kids, err := client.ChildrenOf(ctx, schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, u.GetNamespace(), u.GetUID()); err == nil {
				lvl.refs = append(lvl.refs, kids...)
			}
		}
		return inspectMsg{seq: seq, level: lvl}
	}
}

// openInspectObject pushes a level for an object we already hold.
func (a *App) openInspectObject(u *unstructured.Unstructured, extraMeta []string) {
	lvl := levelFromObject(u, a.snap)
	if len(extraMeta) > 0 {
		lvl.meta = append(extraMeta, "")
	}
	a.inspect = append(a.inspect, lvl)
	a.showInspect()
}

// openInspectList pushes a level that is just a list of references.
func (a *App) openInspectList(title string, meta []string, refs []k8s.ObjRef) {
	a.inspect = append(a.inspect, inspectLevel{title: title, meta: meta, refs: refs})
	a.showInspect()
}

func refTitle(r k8s.ObjRef) string {
	if r.Namespace != "" {
		return r.Kind + " " + r.Namespace + "/" + r.Name
	}
	return r.Kind + " " + r.Name
}

func levelFromObject(u *unstructured.Unstructured, snap *k8s.Snapshot) inspectLevel {
	lvl := inspectLevel{title: u.GetKind() + " " + joinNS(u.GetNamespace(), u.GetName())}
	meta := []string{kv("apiVersion", u.GetAPIVersion()) + "  " + kv("uid", string(u.GetUID())) + "  " + kv("created", age(u.GetCreationTimestamp().Time)+" ago")}
	if u.GetDeletionTimestamp() != nil {
		meta = append(meta, styleCrit.Render("terminating since "+age(u.GetDeletionTimestamp().Time)+" ago")+"  "+kv("finalizers", strings.Join(u.GetFinalizers(), ",")))
	}
	if phase, ok, _ := unstructured.NestedString(u.Object, "status", "phase"); ok && phase != "" {
		meta = append(meta, kv("phase", phase))
	}
	if sum, bad := k8s.ConditionSummary(u.Object); sum != "" {
		if bad {
			meta = append(meta, kv("conditions", styleCrit.Render(sum)))
		} else {
			meta = append(meta, kv("conditions", styleOK.Render(sum)))
		}
	}
	if l := u.GetLabels(); len(l) > 0 {
		var kvs []string
		for _, k := range sortedKeys(l) {
			kvs = append(kvs, k+"="+l[k])
		}
		meta = append(meta, kv("labels", strings.Join(kvs, " ")))
	}
	lvl.meta = meta
	lvl.refs = k8s.ExtractRefs(u)
	if snap != nil {
		lvl.refs = append(lvl.refs, snap.Children(u.GetUID())...)
	}
	lvl.dump = strings.Split(strings.TrimRight(k8s.DumpYAML(u), "\n"), "\n")
	return lvl
}

func joinNS(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

func (a *App) handleInspectMsg(m inspectMsg) {
	if m.seq != a.inspectSeq || len(a.inspect) == 0 {
		return
	}
	top := &a.inspect[len(a.inspect)-1]
	if !top.loading {
		return
	}
	a.inspect[len(a.inspect)-1] = m.level
}

func (a *App) handleInspectKey(key string) (tea.Model, tea.Cmd) {
	if len(a.inspect) == 0 {
		if a.overlay == ovInspect {
			a.overlay = ovNone
		} else {
			a.sub[a.tab] = 0
			a.wlPods = false
		}
		return a, nil
	}
	top := &a.inspect[len(a.inspect)-1]
	visible := a.height - 8
	switch key {
	case "esc", "backspace", "q":
		a.inspect = a.inspect[:len(a.inspect)-1]
		if len(a.inspect) == 0 {
			if a.overlay == ovInspect {
				a.overlay = ovNone
			} else {
				a.sub[a.tab] = 0
				a.wlPods = false
			}
		}
	case "j", "down":
		if top.cursor < len(top.refs)-1 {
			top.cursor++
		}
	case "k", "up":
		if top.cursor > 0 {
			top.cursor--
		}
	case "enter":
		if top.cursor < len(top.refs) && !top.loading {
			return a, a.openInspectRef(top.refs[top.cursor])
		}
	case "J", "pgdown", " ", "ctrl+d":
		top.scroll += visible / 2
	case "K", "pgup", "ctrl+u":
		top.scroll -= visible / 2
	case "g", "home":
		top.scroll = 0
		top.cursor = 0
	case "G", "end":
		top.scroll = len(top.dump)
	}
	if top.scroll > len(top.dump)-3 {
		top.scroll = len(top.dump) - 3
	}
	if top.scroll < 0 {
		top.scroll = 0
	}
	return a, nil
}

// renderInspect draws the top inspector level.
func (a *App) renderInspect() (string, []string) {
	if len(a.inspect) == 0 {
		return "", nil
	}
	top := a.inspect[len(a.inspect)-1]
	w := a.width - 6
	crumbs := make([]string, 0, len(a.inspect))
	for _, l := range a.inspect {
		crumbs = append(crumbs, l.title)
	}
	title := strings.Join(crumbs, " › ")
	if len(a.inspect) > 3 {
		title = "… › " + strings.Join(crumbs[len(crumbs)-3:], " › ")
	}
	var lines []string
	if top.loading {
		lines = append(lines, a.spinner.View()+" loading...")
		return title, lines
	}
	if top.err != "" {
		lines = append(lines, styleCrit.Render(top.err), "", styleDim.Render("esc goes back"))
		return title, lines
	}
	for _, m := range top.meta {
		lines = append(lines, wrap(m, w)...)
	}
	lines = append(lines, "")
	if len(top.refs) == 0 {
		lines = append(lines, styleDim.Render("References: none found"))
	} else {
		lines = append(lines, styleTitle.Render(fmt.Sprintf("References (%d)", len(top.refs)))+styleDim.Render("  j/k select · enter opens · esc back · J/K or PgUp/PgDn scroll the YAML"))
		var rows [][]string
		for _, r := range top.refs {
			via := r.Via
			viaStyled := styleDim.Render(via)
			switch {
			case via == "owner":
				viaStyled = styleInfo.Render("owner")
			case via == "child":
				viaStyled = styleOK.Render("child")
			}
			rows = append(rows, []string{viaStyled, r.Kind, joinNS(r.Namespace, r.Name)})
		}
		h, rl := renderTable(w-2, []column{{title: "VIA", max: 40}, {title: "KIND"}, {title: "OBJECT"}}, rows)
		lines = append(lines, "  "+h)
		maxRows := 12
		start := 0
		if top.cursor >= maxRows {
			start = top.cursor - maxRows + 1
		}
		for i := start; i < len(rl) && i < start+maxRows; i++ {
			if i == top.cursor {
				lines = append(lines, styleSel.Render("> "+pad(rl[i], w-2)))
			} else {
				lines = append(lines, "  "+rl[i])
			}
		}
		if len(rl) > maxRows {
			lines = append(lines, styleDim.Render(fmt.Sprintf("  ... %d of %d shown", maxRows, len(rl))))
		}
	}
	if len(top.dump) > 0 {
		lines = append(lines, "", styleTitle.Render("YAML")+styleDim.Render(fmt.Sprintf("  (line %d of %d)", top.scroll+1, len(top.dump))))
		for i := top.scroll; i < len(top.dump); i++ {
			lines = append(lines, trunc(top.dump[i], w))
		}
	}
	return title, lines
}
