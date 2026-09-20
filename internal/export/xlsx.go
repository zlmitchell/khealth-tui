package export

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"
)

// The workbook: Summary, Findings, one sheet per benchmark (Kubernetes STIG,
// RKE2 STIG, CIS, each OS STIG...), Nodes. Every table has a bold frozen
// header with an autofilter, status / severity cells are coloured, and the
// long text columns wrap.

var (
	sheetUnsafe   = regexp.MustCompile(`[\[\]:*?/\\]`)
	versionSuffix = regexp.MustCompile(` [vV][0-9].*$`) // " V2R6 (01 Apr 2026)", " v2.0.1 (Jun 2026) / ..."
)

// sheetName shortens a benchmark name to an Excel sheet name (31 chars,
// none of []:*?/\): "DISA Kubernetes STIG V2R6 (01 Apr 2026)" -> "Kubernetes STIG".
func sheetName(bench string) string {
	s := versionSuffix.ReplaceAllString(bench, "")
	if i := strings.Index(s, " ("); i > 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "DISA ")
	s = strings.TrimPrefix(s, "Rancher Government ")
	s = strings.TrimSuffix(s, " Benchmark")
	s = sheetUnsafe.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	if len(s) > 31 {
		s = strings.TrimSpace(s[:31])
	}
	if s == "" {
		s = "Benchmark"
	}
	return s
}

type styles struct {
	header, wrap, crit, warn, info, pass, fail, manual, na, title, dim int
}

func newStyles(f *excelize.File) (styles, error) {
	var st styles
	var err error
	mk := func(s *excelize.Style) int {
		if err != nil {
			return 0
		}
		var id int
		id, err = f.NewStyle(s)
		return id
	}
	fill := func(color string) excelize.Fill {
		return excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{color}}
	}
	st.header = mk(&excelize.Style{Font: &excelize.Font{Bold: true, Color: "FFFFFF"}, Fill: fill("305496"), Alignment: &excelize.Alignment{Vertical: "center"}})
	st.wrap = mk(&excelize.Style{Alignment: &excelize.Alignment{WrapText: true, Vertical: "top"}})
	st.title = mk(&excelize.Style{Font: &excelize.Font{Bold: true, Size: 14}})
	st.dim = mk(&excelize.Style{Font: &excelize.Font{Color: "808080"}})
	st.crit = mk(&excelize.Style{Font: &excelize.Font{Bold: true, Color: "9C0006"}, Fill: fill("FFC7CE"), Alignment: &excelize.Alignment{Vertical: "top"}})
	st.warn = mk(&excelize.Style{Font: &excelize.Font{Bold: true, Color: "9C5700"}, Fill: fill("FFEB9C"), Alignment: &excelize.Alignment{Vertical: "top"}})
	st.info = mk(&excelize.Style{Font: &excelize.Font{Color: "1F4E78"}, Fill: fill("DDEBF7"), Alignment: &excelize.Alignment{Vertical: "top"}})
	st.pass = mk(&excelize.Style{Font: &excelize.Font{Color: "006100"}, Fill: fill("C6EFCE"), Alignment: &excelize.Alignment{Vertical: "top"}})
	st.fail = st.crit
	st.manual = st.warn
	st.na = mk(&excelize.Style{Font: &excelize.Font{Color: "808080"}, Alignment: &excelize.Alignment{Vertical: "top"}})
	return st, err
}

func (st styles) forStatus(s string) int {
	switch s {
	case "CRIT", "FAIL":
		return st.crit
	case "WARN", "MANUAL":
		return st.warn
	case "INFO":
		return st.info
	case "PASS":
		return st.pass
	}
	return st.na
}

// table writes a header + rows starting at row 1, freezes the header,
// applies an autofilter and column widths; colourCol (1-based, 0 = none)
// gets the status style per row, wrapCols wrap.
func table(f *excelize.File, sheet string, st styles, headers []string, widths []float64, rows [][]string, colourCol int, wrapCols map[int]bool) error {
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		if err := f.SetCellValue(sheet, cell, h); err != nil {
			return err
		}
	}
	last, _ := excelize.CoordinatesToCellName(len(headers), 1)
	if err := f.SetCellStyle(sheet, "A1", last, st.header); err != nil {
		return err
	}
	for i, w := range widths {
		col, _ := excelize.ColumnNumberToName(i + 1)
		if err := f.SetColWidth(sheet, col, col, w); err != nil {
			return err
		}
	}
	for r, row := range rows {
		for c, v := range row {
			cell, _ := excelize.CoordinatesToCellName(c+1, r+2)
			if err := f.SetCellValue(sheet, cell, v); err != nil {
				return err
			}
			switch {
			case c+1 == colourCol:
				_ = f.SetCellStyle(sheet, cell, cell, st.forStatus(v))
			case wrapCols[c+1]:
				_ = f.SetCellStyle(sheet, cell, cell, st.wrap)
			}
		}
	}
	if len(rows) > 0 {
		end, _ := excelize.CoordinatesToCellName(len(headers), len(rows)+1)
		if err := f.AutoFilter(sheet, "A1:"+end, nil); err != nil {
			return err
		}
	}
	return f.SetPanes(sheet, &excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft"})
}

// WriteXLSX writes the workbook.
func WriteXLSX(path string, r *Report) error {
	f := excelize.NewFile()
	defer f.Close()
	st, err := newStyles(f)
	if err != nil {
		return err
	}
	if err := summarySheet(f, st, r); err != nil {
		return err
	}
	if err := findingsSheet(f, st, r); err != nil {
		return err
	}
	if r.Security != nil {
		used := map[string]int{}
		for _, b := range r.Security.Benchmarks {
			name := b.Sheet
			if n := used[name]; n > 0 {
				name = fmt.Sprintf("%s %d", name[:min(len(name), 28)], n+1)
			}
			used[b.Sheet]++
			if err := benchmarkSheet(f, st, name, b); err != nil {
				return err
			}
		}
	}
	if err := nodesSheet(f, st, r); err != nil {
		return err
	}
	f.SetActiveSheet(0)
	return f.SaveAs(path)
}

func summarySheet(f *excelize.File, st styles, r *Report) error {
	sheet := "Summary"
	if err := f.SetSheetName("Sheet1", sheet); err != nil {
		return err
	}
	set := func(row int, k string, v any) {
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", row), k)
		_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", row), v)
	}
	_ = f.SetCellValue(sheet, "A1", "khealth report")
	_ = f.SetCellStyle(sheet, "A1", "A1", st.title)
	row := 3
	set(row, "generated", r.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	row++
	set(row, "khealth version", r.Version)
	row++
	set(row, "context", r.Cluster.Context)
	row++
	set(row, "API server", r.Cluster.Server)
	row++
	set(row, "distribution", r.Cluster.Distribution)
	row++
	set(row, "kubernetes version", r.Cluster.Version)
	row++
	set(row, "nodes / pods / namespaces", fmt.Sprintf("%d / %d / %d", r.Cluster.Nodes, r.Cluster.Pods, r.Cluster.Namespaces))
	row += 2
	_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", row), "Findings")
	_ = f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), st.title)
	row++
	for _, sev := range []string{"CRIT", "WARN", "INFO"} {
		set(row, sev, r.Summary.Findings[sev])
		_ = f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), st.forStatus(sev))
		row++
	}
	set(row, "resolved recently", len(r.Resolved))
	row += 2
	_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", row), "Security scan")
	_ = f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), st.title)
	row++
	if r.Security == nil {
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", row), "not run (Shift+S on the Security tab)")
		_ = f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), st.dim)
	} else {
		headers := []string{"benchmark", "sheet", "score %", "PASS", "FAIL", "MANUAL", "N/A", "UNKNOWN", "rules"}
		for i, h := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, row)
			_ = f.SetCellValue(sheet, cell, h)
		}
		last, _ := excelize.CoordinatesToCellName(len(headers), row)
		_ = f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), last, st.header)
		row++
		for _, b := range r.Security.Benchmarks {
			score := any("n/a")
			if b.Score != nil {
				score = *b.Score
			}
			vals := []any{b.Name, b.Sheet, score, b.Counts["PASS"], b.Counts["FAIL"], b.Counts["MANUAL"], b.Counts["N/A"], b.Counts["UNKNOWN"], len(b.Rules)}
			for i, v := range vals {
				cell, _ := excelize.CoordinatesToCellName(i+1, row)
				_ = f.SetCellValue(sheet, cell, v)
			}
			row++
		}
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", row), "score = not a finding / (not a finding + open), as SCC / OpenSCAP report it (N/A and MANUAL excluded); IDs are a best-effort mapping, confirm against the release you are audited on")
		_ = f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), st.dim)
	}
	_ = f.SetColWidth(sheet, "A", "A", 44)
	_ = f.SetColWidth(sheet, "B", "B", 22)
	_ = f.SetColWidth(sheet, "C", "I", 10)
	return nil
}

func findingsSheet(f *excelize.File, st styles, r *Report) error {
	sheet := "Findings"
	if _, err := f.NewSheet(sheet); err != nil {
		return err
	}
	var rows [][]string
	for _, x := range r.Findings {
		rows = append(rows, []string{x.Severity, "ongoing", x.Area, x.Object, x.Message, x.Hint, strings.Join(x.Steps, "\n"), tsOrEmpty(x.FirstSeen), ""})
	}
	for _, x := range r.Resolved {
		rows = append(rows, []string{x.Severity, "resolved", x.Area, x.Object, x.Message, x.Hint, strings.Join(x.Steps, "\n"), tsOrEmpty(x.FirstSeen), tsOrEmpty(x.Resolved)})
	}
	return table(f, sheet, st, []string{"severity", "state", "area", "object", "message", "hint", "steps", "first seen", "resolved"},
		[]float64{9, 9, 10, 30, 80, 70, 50, 18, 18}, rows, 1, map[int]bool{5: true, 6: true, 7: true})
}

func benchmarkSheet(f *excelize.File, st styles, sheet string, b Benchmark) error {
	if _, err := f.NewSheet(sheet); err != nil {
		return err
	}
	headers := []string{"status", "cat", "id", "rule id", "group", "title", "detail", "fix", "check"}
	widths := []float64{9, 5, 14, 18, 12, 50, 70, 60, 60}
	for _, n := range b.nodes {
		headers = append(headers, n)
		widths = append(widths, 12)
	}
	var rows [][]string
	for _, rule := range b.Rules {
		row := []string{rule.Status, rule.Cat, rule.ID, rule.RuleID, rule.Group, rule.Title, rule.Detail, rule.Fix, rule.Check}
		for _, n := range b.nodes {
			row = append(row, rule.PerNode[n])
		}
		rows = append(rows, row)
	}
	if err := table(f, sheet, st, headers, widths, rows, 1, map[int]bool{6: true, 7: true, 8: true, 9: true}); err != nil {
		return err
	}
	// per-node outcome cells get the status colour too
	for r, rule := range b.Rules {
		for i, n := range b.nodes {
			if s := rule.PerNode[n]; s != "" {
				cell, _ := excelize.CoordinatesToCellName(10+i, r+2)
				_ = f.SetCellStyle(sheet, cell, cell, st.forStatus(s))
			}
		}
	}
	return nil
}

func nodesSheet(f *excelize.File, st styles, r *Report) error {
	sheet := "Nodes"
	if _, err := f.NewSheet(sheet); err != nil {
		return err
	}
	// hardening columns: the union of item names, in first-seen order
	var cols []string
	seen := map[string]bool{}
	for _, n := range r.Nodes {
		for _, it := range n.Hardening {
			if !seen[it.Name] {
				seen[it.Name] = true
				cols = append(cols, it.Name)
			}
		}
	}
	headers := []string{"node", "roles", "kubelet", "ready", "os", "kernel", "ssh"}
	widths := []float64{22, 20, 16, 7, 34, 26, 12}
	for _, c := range cols {
		headers = append(headers, c)
		widths = append(widths, 22)
	}
	var rows [][]string
	for _, n := range r.Nodes {
		row := []string{n.Name, strings.Join(n.Roles, ","), n.Version, fmt.Sprint(n.Ready), n.OS, n.Kernel, n.SSH}
		byName := map[string]HardeningItem{}
		for _, it := range n.Hardening {
			byName[it.Name] = it
		}
		for _, c := range cols {
			it, ok := byName[c]
			if !ok {
				row = append(row, "")
				continue
			}
			v := it.Runtime
			if it.Mismatch && it.Boot != "" {
				v += " (boot: " + it.Boot + ")"
			}
			row = append(row, v)
		}
		rows = append(rows, row)
	}
	if err := table(f, sheet, st, headers, widths, rows, 0, nil); err != nil {
		return err
	}
	for ri, n := range r.Nodes {
		byName := map[string]HardeningItem{}
		for _, it := range n.Hardening {
			byName[it.Name] = it
		}
		for ci, c := range cols {
			it, ok := byName[c]
			if !ok {
				continue
			}
			cell, _ := excelize.CoordinatesToCellName(8+ci, ri+2)
			switch {
			case it.Mismatch:
				_ = f.SetCellStyle(sheet, cell, cell, st.warn)
			case it.OK:
				_ = f.SetCellStyle(sheet, cell, cell, st.pass)
			default:
				_ = f.SetCellStyle(sheet, cell, cell, st.fail)
			}
		}
	}
	return nil
}

func tsOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}
