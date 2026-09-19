package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"k8s-health-tui/internal/k8s"
)

type crdCountMsg struct {
	seq  int
	crds []k8s.CRDInfo
}

// crdCountCmd fetches instance counts for all CRDs (once per refresh cycle).
func (a *App) crdCountCmd() tea.Cmd {
	if a.snap == nil || len(a.snap.CRDs) == 0 || a.crdCounting {
		return nil
	}
	a.crdCounting = true
	seq := a.seq
	client := a.client
	crds := append([]k8s.CRDInfo{}, a.snap.CRDs...)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		client.CountCRs(ctx, crds)
		return crdCountMsg{seq: seq, crds: crds}
	}
}

func (a *App) crdsContent() content {
	s := a.snap
	crds := s.CRDs
	if len(a.crdCounts) > 0 {
		crds = a.crdCounts
	}
	groups := map[string]bool{}
	problems := 0
	total := 0
	for _, c := range crds {
		groups[c.Group] = true
		if len(c.Problems) > 0 || !c.Established {
			problems++
		}
		if c.Count > 0 {
			total += c.Count
		}
	}
	countNote := "counting instances..."
	if len(a.crdCounts) > 0 {
		countNote = fmt.Sprintf("%d custom resources total", total)
	} else if !a.crdCounting {
		countNote = "counts pending"
	}
	hdr := []string{
		styleTitle.Render("Custom Resource Definitions") + "  " + kv("CRDs", fmt.Sprint(len(crds))) + "  " + kv("groups", fmt.Sprint(len(groups))) + "  " + kv("problems", colorCount(problems, "CRDs not established / with conditions", styleCrit)) + "  " + styleDim.Render(countNote),
		styleDim.Render("enter lists the instances (then enter again inspects one: status, conditions, references, YAML). / filters, a shows only CRDs with instances."),
	}
	var rows [][]string
	var ids []string
	for i, c := range crds {
		if a.problemOnly && c.Count == 0 {
			continue
		}
		state := styleOK.Render("established")
		if !c.Established {
			state = styleCrit.Render("not established")
		}
		if len(c.Problems) > 0 {
			state = styleWarn.Render(strings.Join(c.Problems, "; "))
		}
		count := styleDim.Render("?")
		switch {
		case c.Count > 0:
			count = fmt.Sprint(c.Count)
		case c.Count == 0:
			count = styleDim.Render("0")
		}
		rows = append(rows, []string{c.Kind, c.Group, strings.Join(c.Versions, ","), c.Scope, count, age(c.Created), state})
		ids = append(ids, fmt.Sprint(i))
	}
	h, lines := renderTable(a.width, []column{{title: "KIND"}, {title: "GROUP", max: 40}, {title: "VERSIONS", max: 24}, {title: "SCOPE"}, {title: "COUNT", right: true}, {title: "AGE", right: true}, {title: "STATE"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: "no CRDs (or no permission to list customresourcedefinitions)"}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// openCRDInstances lists a CRD's instances into the inspector.
func (a *App) openCRDInstances(id string) tea.Cmd {
	var idx int
	if _, err := fmt.Sscan(id, &idx); err != nil {
		return nil
	}
	crds := a.snap.CRDs
	if len(a.crdCounts) > 0 {
		crds = a.crdCounts
	}
	if idx < 0 || idx >= len(crds) {
		return nil
	}
	info := crds[idx]
	lvl := inspectLevel{title: info.Kind + " (" + info.Group + ")", loading: true}
	a.inspect = append(a.inspect, lvl)
	a.overlay = ovInspect
	a.inspectSeq++
	seq := a.inspectSeq
	client := a.client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		items, err := client.ListCRs(ctx, info, 500)
		lvl := inspectLevel{title: info.Kind + " (" + info.Group + ")"}
		if err != nil {
			lvl.err = err.Error()
			return inspectMsg{seq: seq, level: lvl}
		}
		bad := 0
		for _, it := range items {
			if it.Bad {
				bad++
			}
		}
		lvl.meta = []string{
			kv("crd", info.Name) + "  " + kv("versions", strings.Join(info.Versions, ",")+" (storage "+info.Storage+")") + "  " + kv("scope", info.Scope),
			kv("instances", fmt.Sprintf("%d listed (max 500)", len(items))) + "  " + kv("unhealthy", colorCount(bad, "with failed/false conditions", styleCrit)),
		}
		apiVersion := info.Group + "/" + info.Storage
		for _, it := range items {
			via := it.Phase
			if it.Ready != "" {
				if via != "" {
					via += " "
				}
				via += it.Ready
			}
			if via == "" {
				via = age(it.Created) + " old"
			}
			if it.Bad {
				via = "!! " + via
			}
			lvl.refs = append(lvl.refs, k8s.ObjRef{APIVersion: apiVersion, Kind: info.Kind, Namespace: it.Namespace, Name: it.Name, Via: via})
		}
		return inspectMsg{seq: seq, level: lvl}
	}
}
