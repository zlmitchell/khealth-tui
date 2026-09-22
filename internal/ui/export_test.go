package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// e asks for the format first (a stray keypress must not write files);
// j/x/b write JSON, XLSX or both into export.dir and say where.
func TestExportKey(t *testing.T) {
	a := testApp()
	a.cfg.Export.Dir = filepath.Join(t.TempDir(), "reports")
	a.cfg.Context = "test-ctx"
	press := func(r rune) { a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}) }
	press('e')
	if a.overlay != ovExport {
		t.Fatalf("e did not open the export prompt (overlay %v)", a.overlay)
	}
	if _, err := os.ReadDir(a.cfg.Export.Dir); err == nil {
		t.Fatal("e wrote files before a format was chosen")
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.overlay != ovNone || !strings.Contains(a.status, "canceled") {
		t.Fatalf("esc: overlay %v status %q", a.overlay, a.status)
	}
	press('e')
	press('j')
	if !strings.HasPrefix(a.status, "exported khealth-test") || strings.Contains(a.status, ".xlsx") {
		t.Fatalf("json only: %q", a.status)
	}
	entries, _ := os.ReadDir(a.cfg.Export.Dir)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".json") {
		t.Fatalf("files after j: %v", entries)
	}
	press('e')
	press('b')
	if !strings.Contains(a.status, ".json and ") || !strings.Contains(a.status, ".xlsx") {
		t.Fatalf("both: %q", a.status)
	}
	entries, _ = os.ReadDir(a.cfg.Export.Dir)
	if len(entries) < 2 {
		t.Fatalf("files after b: %v", entries)
	}
	// without a snapshot there is nothing to write
	a.snap = nil
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	if !strings.Contains(a.status, "nothing to export") {
		t.Errorf("status without snapshot: %q", a.status)
	}
}
