package ui

import (
	"fmt"
	"os"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

// TestDumpViews writes ANSI-stripped renders to KHT_DUMP for visual inspection.
func TestDumpViews(t *testing.T) {
	path := os.Getenv("KHT_DUMP")
	if path == "" {
		t.Skip("set KHT_DUMP=<file> to dump views")
	}
	a := testApp()
	for i := 0; i < 40; i++ {
		a.recordSnapshot()
		for _, ni := range a.nodes {
			ni.CPUPct = float64((i * 7) % 100)
			a.recordNode(ni)
		}
		for _, p := range a.etcd {
			a.recordEtcd(p)
		}
	}
	f, _ := os.Create(path)
	defer f.Close()
	for _, tb := range []tab{tabOverview, tabNodes, tabEtcd, tabWorkloads, tabSecurity, tabLogs} {
		a.tab = tb
		fmt.Fprintf(f, "\n======== %s ========\n%s\n", tabNames[tb], ansi.Strip(a.View()))
	}
}
