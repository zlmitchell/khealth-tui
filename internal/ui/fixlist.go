package ui

import (
	"fmt"

	"github.com/zlmitchell/khealth-tui/internal/stig"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// fixListContent is the Security "Fix list" sub-tab: every open (FAIL /
// MANUAL) rule regrouped by what the fix changes - the file on the nodes,
// the Kubernetes object, the packages or units - so each file is opened
// once. enter on an item shows the rule it came from.
func (a *App) fixListContent() content {
	groups := a.fixList
	items, fails, files, objects := 0, 0, 0, 0
	for _, g := range groups {
		n, f := g.Open()
		items += n
		fails += f
		switch g.Kind {
		case stig.TargetFile:
			files++
		case stig.TargetResource:
			objects++
		}
	}
	hdr := []string{
		styleTitle.Render("Fix list") + "  " + kv("changes", fmt.Sprint(items)) + "  " + kv("fail", styleCrit.Render(fmt.Sprint(fails))) + "  " + kv("files", fmt.Sprint(files)) + "  " + kv("objects", fmt.Sprint(objects)),
		styleDim.Render("FAIL and MANUAL rules grouped by the file or object the fix changes; rules asking for the same change share one line. 'm' hides manual, '/' filters, enter shows the rule. The xlsx / markdown export carries the same list."),
	}
	w := a.width - 4
	c := content{header: hdr, selectable: true, empty: "nothing open: every evaluated rule passes or does not apply"}
	for _, g := range groups {
		var lines []row
		for _, it := range g.Items {
			if a.hideManual && it.Status == stig.Manual {
				continue
			}
			ids := it.IDs[0]
			if len(it.IDs) > 1 {
				ids += fmt.Sprintf(" +%d", len(it.IDs)-1)
			}
			where := ""
			if len(it.Nodes) > 0 && len(it.Nodes) < len(g.Nodes) {
				where = styleDim.Render("  only " + strutil.TruncList(it.Nodes, 3))
			}
			text := fmt.Sprintf("  ☐ %s %-3s %-18s %s", stigStyle(it.Status).Render(fmt.Sprintf("%-6s", it.Status.String())), it.Cat, ids, it.Change) + where
			lines = append(lines, row{id: fmt.Sprint(it.Result), text: trunc(text, w)})
		}
		if len(lines) == 0 {
			continue
		}
		head := styleBold.Render(g.Name)
		if len(g.Nodes) > 0 {
			head += styleDim.Render(fmt.Sprintf("  %d node(s): %s", len(g.Nodes), strutil.TruncList(g.Nodes, 4)))
		}
		if len(c.rows) > 0 {
			c.rows = append(c.rows, row{})
		}
		c.rows = append(c.rows, row{text: trunc(head, w)})
		if g.Hint != "" {
			c.rows = append(c.rows, row{text: trunc(styleDim.Render("  "+g.Hint), w)})
		}
		c.rows = append(c.rows, lines...)
	}
	if len(c.rows) == 0 && items > 0 {
		c.empty = "only MANUAL items open ('m' shows them)"
	}
	return c
}
