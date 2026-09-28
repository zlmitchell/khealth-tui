package rca

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/logs"
)

func colorFixture() ([]Hypothesis, *Timeline, []Incident) {
	t := time.Date(2026, 9, 27, 22, 0, 0, 0, time.UTC)
	// an Artifactory line: the app colors its own log
	ev := Entry{Time: t, Node: "rancher", Kind: "pod", Unit: "artifactory-oss/artifactory-oss-0/artifactory", Class: logs.ClassError, Pattern: "generic-error",
		Text: "2026-09-28T00:22:56.062Z \x1b[1;32m[jfrt ]\x1b[0;39m \x1b[1;31m[ERROR]\x1b[0;39m unexpected error", Ref: Ref{File: "cluster/pods/a.log", Line: 3}}
	hs := []Hypothesis{
		{Title: "Node rancher rebooted", Score: 0.85, Cause: "requested by \x1b[33mthe hypervisor\x1b[0m", Effects: []string{"73 containers"}, Evidence: []Entry{ev}, Next: []string{"check it"}},
		{Title: "etcd disk latency", Score: 0.55, Cause: "663 slow applies"},
		{Title: "dnf-makecache failing", Score: 0.3, Cause: "11 failures"},
	}
	tl := &Timeline{Entries: []Entry{ev, {Time: t, Node: "rancher", Unit: "etcd", Class: logs.ClassWarn, Pattern: "etcd-slow-fsync", Text: "apply request took too long"}}, Lines: 2}
	ins := []Incident{
		{ID: "reboot-1", Kind: KindReboot, Time: t, Node: "rancher", Workload: "node/rancher", Summary: "the shutdown hung"},
		{ID: "pull-1", Kind: KindPull, Time: t, Namespace: "ci", Workload: "deploy/runner", Summary: "tag not found"},
	}
	return hs, tl, ins
}

func render(color bool) string {
	defer func(old bool) { Color = old }(Color)
	Color = color
	hs, tl, ins := colorFixture()
	var b bytes.Buffer
	WriteReport(&b, hs, tl, 60)
	WriteIncidents(&b, ins)
	return b.String()
}

// Colors change nothing but the colors: the colored report with its codes
// stripped is the plain one, column for column.
func TestColorIsOnlyColor(t *testing.T) {
	plain, colored := render(false), render(true)
	if strings.Contains(plain, "\x1b") {
		t.Errorf("plain output carries escape codes (the log's own included):\n%q", plain)
	}
	if got := escapes.ReplaceAllString(colored, ""); got != plain {
		t.Errorf("colored minus its codes differs from plain:\n%s\n---\n%s", got, plain)
	}
	for _, want := range []string{
		"\x1b[1;31m[high]\x1b[0m", "\x1b[33m[medium]\x1b[0m", "\x1b[36m[low]\x1b[0m", // confidence
		"\x1b[1mNode rancher rebooted\x1b[0m",          // title
		"\x1b[31merror\x1b[0m", "\x1b[33mwarn \x1b[0m", // timeline class, padded inside
		"\x1b[1;31mnode restart  \x1b[0m", "\x1b[33mimage pull    \x1b[0m", // incident kinds
	} {
		if !strings.Contains(colored, want) {
			t.Errorf("colored output lacks %q", want)
		}
	}
}

func TestCleanDropsLogEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[1;32m[jfrt ]\x1b[0;39m msg": "[jfrt ] msg",
		"\x1b]0;title\x07after":           "after",
		"bell\x07 and\r\ncr":              "bell and\ncr",
		"tab\tstays":                      "tab\tstays",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}
