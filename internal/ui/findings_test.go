package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/zlmitchell/khealth-tui/internal/checks"
)

func TestFindingKeyIgnoresDigitsAndSeverity(t *testing.T) {
	a := checks.Finding{Severity: checks.SevWarn, Area: "node", Object: "cp-1", Message: "certificate expires in 29d: /etc/kubernetes/pki/apiserver.crt"}
	b := a
	b.Severity, b.Message = checks.SevCrit, "certificate expires in 3d: /etc/kubernetes/pki/apiserver.crt"
	if findingKey(a) != findingKey(b) {
		t.Errorf("same issue with a moving number/severity must keep its key: %q vs %q", findingKey(a), findingKey(b))
	}
	c := a
	c.Object = "cp-2"
	if findingKey(a) == findingKey(c) {
		t.Errorf("different objects must not collide")
	}
}

func TestTrackFindingsFirstSeenAndResolved(t *testing.T) {
	a := &App{}
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	disk := checks.Finding{Severity: checks.SevWarn, Area: "node", Object: "w-1", Message: "disk 91% on /var"}
	pod := checks.Finding{Severity: checks.SevCrit, Area: "workload", Object: "default/app-1", Message: "CrashLoopBackOff, 7 restarts"}

	a.findings = []checks.Finding{disk, pod}
	a.trackFindings(t0)
	if a.firstSeen(disk) != t0 || a.firstSeen(pod) != t0 || len(a.resolved) != 0 {
		t.Fatalf("first evaluation: first=%v/%v resolved=%d", a.firstSeen(disk), a.firstSeen(pod), len(a.resolved))
	}

	// next refresh: the restart count moved, the disk finding is gone
	pod2 := pod
	pod2.Message = "CrashLoopBackOff, 9 restarts"
	a.findings = []checks.Finding{pod2}
	a.trackFindings(t0.Add(30 * time.Second))
	if a.firstSeen(pod2) != t0 {
		t.Errorf("a finding whose numbers changed must keep its first-seen time, got %v", a.firstSeen(pod2))
	}
	if len(a.resolved) != 1 || a.resolved[0].Object != "w-1" || a.resolved[0].First != t0 || a.resolved[0].Resolved != t0.Add(30*time.Second) {
		t.Fatalf("disk finding should be resolved at +30s: %+v", a.resolved)
	}

	// it comes back: resolved entry dropped, first-seen restarts
	a.findings = []checks.Finding{pod2, disk}
	a.trackFindings(t0.Add(60 * time.Second))
	if len(a.resolved) != 0 || a.firstSeen(disk) != t0.Add(60*time.Second) {
		t.Errorf("a finding that returns is ongoing again: resolved=%d first=%v", len(a.resolved), a.firstSeen(disk))
	}

	// gone for good: kept for resolvedKeep, then dropped
	a.findings = []checks.Finding{pod2}
	a.trackFindings(t0.Add(90 * time.Second))
	if len(a.resolved) != 1 {
		t.Fatalf("resolved again: %d", len(a.resolved))
	}
	a.trackFindings(t0.Add(90*time.Second + resolvedKeep + time.Second))
	if len(a.resolved) != 0 {
		t.Errorf("resolved findings must expire after %s", resolvedKeep)
	}
}

func TestOverviewShowsStateAndFirstSeen(t *testing.T) {
	a := testApp()
	a.recompute()
	if len(a.findings) == 0 {
		t.Fatalf("fixture has no findings")
	}
	// make one finding vanish on the next evaluation
	gone := a.findings[0]
	a.findingAge[findingKey(gone)] = findingTrack{F: gone, First: time.Now().Add(-5 * time.Minute)}
	a.findings = a.findings[1:]
	a.trackFindings(time.Now())
	if len(a.resolved) != 1 {
		t.Fatalf("expected one resolved finding, got %d", len(a.resolved))
	}
	a.tab = tabOverview
	c := a.currentContent()
	got := ansi.Strip(strings.Join(append(c.header, rowsText(c)...), "\n"))
	for _, want := range []string{"STATE", "FIRST SEEN", "ongoing", "resolved 0s ago", "5m ago", "1 resolved kept 15m"} {
		if !strings.Contains(got, want) {
			t.Errorf("overview lacks %q:\n%s", want, got)
		}
	}
	// the resolved row opens its own detail
	title, lines := a.detailFor(tabOverview, "r:0")
	if title != "Resolved finding" || !strings.Contains(ansi.Strip(strings.Join(lines, "\n")), gone.Message) {
		t.Errorf("resolved detail: %q %v", title, lines)
	}
	if title, lines := a.detailFor(tabOverview, "0"); title != "Finding" || !strings.Contains(ansi.Strip(strings.Join(lines, "\n")), "first seen") {
		t.Errorf("ongoing detail should show first seen: %q %v", title, lines)
	}
}
