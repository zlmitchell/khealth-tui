package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/export"
)

// exportInput is everything the report needs from the app.
func (a *App) exportInput() export.Input {
	in := export.Input{
		Snap: a.snap, Nodes: a.nodes, Findings: a.findings, FirstSeen: a.firstSeen,
		StigRun: a.secScanned, Stig: a.stigRes,
		Context: a.cfg.Context, Version: config.Version, Now: time.Now(),
	}
	if a.client != nil {
		in.Server, in.Context = a.client.Host, a.client.Context
	}
	for _, r := range a.resolved {
		in.Resolved = append(in.Resolved, export.ResolvedFinding{Finding: r.Finding, First: r.First, Resolved: r.Resolved})
	}
	return in
}

// exportPrompt opens the format chooser (key e): a stray keypress must not
// write files.
func (a *App) exportPrompt() {
	if a.snap == nil {
		a.setStatus("nothing to export yet: waiting for the first snapshot")
		return
	}
	a.overlay = ovExport
}

// exportDir is where the report goes, absolute for the message.
func (a *App) exportDir() string {
	dir := a.cfg.Export.Dir
	if dir == "" {
		dir = "."
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// exportReport writes the report in the chosen format(s) and says where.
func (a *App) exportReport(json, xlsx bool) {
	if a.snap == nil {
		a.setStatus("nothing to export yet: waiting for the first snapshot")
		return
	}
	paths, err := export.WriteFormats(a.cfg.Export.Dir, export.Build(a.exportInput()), json, xlsx)
	if err != nil {
		a.setStatus("export failed: " + err.Error())
		return
	}
	var names []string
	for _, p := range paths {
		names = append(names, filepath.Base(p))
	}
	a.setStatus(fmt.Sprintf("exported %s in %s", strings.Join(names, " and "), a.exportDir()))
}

// renderExportPrompt is the e overlay.
func (a *App) renderExportPrompt() (string, []string) {
	r := export.Build(a.exportInput())
	lines := []string{
		styleBold.Render("Write the findings report to " + a.exportDir()),
		"",
		"  " + styleKey.Render("j") + "  " + export.FileBase(r) + ".json  " + styleDim.Render("(findings, resolved, security benchmarks, nodes - for diffing and alerting)"),
		"  " + styleKey.Render("x") + "  " + export.FileBase(r) + ".xlsx  " + styleDim.Render("(Summary, Findings, one sheet per benchmark, Nodes)"),
		"  " + styleKey.Render("b") + "  both",
		"",
		styleDim.Render("Nothing is re-collected: the report is what the screen shows. ") + styleKey.Render("esc") + styleDim.Render(" cancels."),
	}
	return "Export report", lines
}
