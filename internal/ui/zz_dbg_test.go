package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestDbgNode(t *testing.T) {
	a := testApp()
	a.width = 100
	_, lines := a.nodeDetail("cp-1")
	for _, l := range lines[:22] {
		t.Log(ansi.Strip(l))
	}
	_ = strings.Join
}
