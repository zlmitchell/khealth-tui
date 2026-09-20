package ui

import (
	"fmt"
	"path/filepath"
	"time"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/export"
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

// exportReport writes the JSON + XLSX report (key e) and says where.
func (a *App) exportReport() {
	if a.snap == nil {
		a.setStatus("nothing to export yet: waiting for the first snapshot")
		return
	}
	jsonPath, xlsxPath, err := export.WriteFiles(a.cfg.Export.Dir, export.Build(a.exportInput()))
	if err != nil {
		a.setStatus("export failed: " + err.Error())
		return
	}
	dir := filepath.Dir(jsonPath)
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	a.setStatus(fmt.Sprintf("exported %s and %s in %s", filepath.Base(jsonPath), filepath.Base(xlsxPath), dir))
}
