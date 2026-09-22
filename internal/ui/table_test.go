package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestFlow(t *testing.T) {
	items := []string{styleTitle.Render("Cluster"), kv("context", "baremetal-a"), kv("server", "https://rancher.example.home/k8s/clusters/c-m-272hqdjd"), kv("version", "v1.35.8+rke2r1"), kv("distribution", "rke2")}
	lines := flow(60, 2, items...)
	if len(lines) < 2 {
		t.Fatalf("not wrapped: %q", lines)
	}
	for i, l := range lines {
		if w := ansi.StringWidth(l); w > 60 && !(i == 1 && strings.Contains(l, "rancher.example.home")) {
			t.Errorf("line %d is %d wide: %q", i, w, ansi.Strip(l))
		}
	}
	if !strings.HasPrefix(ansi.Strip(lines[1]), "  ") {
		t.Errorf("continuation not indented: %q", ansi.Strip(lines[1]))
	}
	if got := flow(200, 2, items...); len(got) != 1 {
		t.Errorf("fits on one line: %q", got)
	}
	if got := flow(40, 0, "", "a"); len(got) != 1 || got[0] != "a" {
		t.Errorf("empty items skipped: %q", got)
	}
}
