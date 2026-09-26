package export

import (
	"fmt"
	"io"
	"strings"
)

// fixSections titles the fix list's target kinds, in checklist order.
var fixSections = []struct{ kind, title string }{
	{"file", "Files on the nodes"},
	{"resource", "Kubernetes objects"},
	{"boot", "Kernel command line"},
	{"package", "Packages"},
	{"unit", "systemd units"},
	{"review", "Needs review"},
}

// WriteMarkdown writes the security scan's fix list as a markdown checklist:
// one heading per file or object, one checkbox per change.
func WriteMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder
	name := r.Cluster.Context
	if name == "" {
		name = r.Cluster.Server
	}
	fmt.Fprintf(&b, "# STIG / CIS fix list: %s\n\n", strings.TrimSpace(name+" ("+r.Cluster.Distribution+" "+r.Cluster.Version+")"))
	fmt.Fprintf(&b, "Generated %s by khealth %s.\n\n", r.GeneratedAt.Format("2006-01-02 15:04 MST"), r.Version)
	if r.Security == nil {
		b.WriteString("The security scan was not run: Shift+S on the Security tab, or `--export-scan`.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	changes, fails := 0, 0
	for _, g := range r.Security.Checklist {
		for _, it := range g.Items {
			changes++
			if it.Status == "FAIL" {
				fails++
			}
		}
	}
	if changes == 0 {
		b.WriteString("Nothing open: every evaluated rule passes or does not apply.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	fmt.Fprintf(&b, "%d changes (%d FAIL, %d MANUAL) across %d targets. Rules that ask for the same change share one line; MANUAL items need a decision and evidence before they close.\n",
		changes, fails, changes-fails, len(r.Security.Checklist))
	for _, sec := range fixSections {
		first := true
		for _, g := range r.Security.Checklist {
			if g.Kind != sec.kind {
				continue
			}
			if first {
				fmt.Fprintf(&b, "\n## %s\n", sec.title)
				first = false
			}
			if sec.kind == "review" {
				b.WriteString("\n")
			} else {
				fmt.Fprintf(&b, "\n### `%s`\n\n", g.Target)
			}
			var meta []string
			if len(g.Nodes) > 0 {
				meta = append(meta, "nodes: "+strings.Join(g.Nodes, ", "))
			}
			if g.Hint != "" {
				meta = append(meta, g.Hint)
			}
			if len(meta) > 0 {
				fmt.Fprintf(&b, "_%s_\n\n", strings.Join(meta, " · "))
			}
			for _, it := range g.Items {
				ids := strings.Join(it.IDs, ", ")
				only := ""
				if len(it.Nodes) > 0 && len(it.Nodes) < len(g.Nodes) {
					only = " (only " + strings.Join(it.Nodes, ", ") + ")"
				}
				if sec.kind == "review" {
					fmt.Fprintf(&b, "- [ ] **%s** CAT %s %s: %s%s\n", it.Status, it.Cat, ids, it.Title, only)
					if fix := oneLine(it.Change); fix != "" {
						fmt.Fprintf(&b, "  - fix: %s\n", fix)
					}
					continue
				}
				fmt.Fprintf(&b, "- [ ] **%s** CAT %s `%s` - %s: %s%s\n", it.Status, it.Cat, oneLine(it.Change), ids, it.Title, only)
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// oneLine folds a multi-line fix text for a list item.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "`", "'")), " ")
}
