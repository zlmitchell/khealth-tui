package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// e writes the JSON + XLSX report into export.dir and says where.
func TestExportKey(t *testing.T) {
	a := testApp()
	a.cfg.Export.Dir = filepath.Join(t.TempDir(), "reports")
	a.cfg.Context = "test-ctx"
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	if !strings.HasPrefix(a.status, "exported khealth-test-ctx-") || !strings.Contains(a.status, ".xlsx") {
		t.Fatalf("status: %q", a.status)
	}
	entries, err := os.ReadDir(a.cfg.Export.Dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("files: %v %v", entries, err)
	}
	// without a snapshot there is nothing to write
	a.snap = nil
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	if !strings.Contains(a.status, "nothing to export") {
		t.Errorf("status without snapshot: %q", a.status)
	}
}
