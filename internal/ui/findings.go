package ui

import (
	"strings"
	"time"

	"k8s-health-tui/internal/checks"
)

// Findings are recomputed from scratch on every refresh, so the Overview
// keeps its own memory of when each one was first seen and which ones went
// away: an issue that has been there for 40 minutes reads differently from
// one that appeared 10 seconds ago, and a row that just resolved is worth
// showing for a while instead of silently vanishing.

// resolvedKeep is how long a resolved finding stays on the Overview.
const resolvedKeep = 15 * time.Minute

type findingTrack struct {
	F           checks.Finding // latest wording (counts and ages in the message move)
	First, Last time.Time
}

type resolvedFinding struct {
	checks.Finding
	First, Resolved time.Time
}

// findingKey identifies a finding across refreshes: area + object + message
// with every run of digits replaced by "#", so "expires in 29d" / "expires in 3d" or a restart
// count going up stay the same finding and keep their first-seen time.
// Severity is left out on purpose: an issue that escalates is still that issue.
func findingKey(f checks.Finding) string {
	var b strings.Builder
	b.WriteString(f.Area)
	b.WriteByte('|')
	b.WriteString(f.Object)
	b.WriteByte('|')
	inNum := false
	for _, r := range f.Message {
		if r >= '0' && r <= '9' {
			if !inNum {
				b.WriteByte('#')
			}
			inNum = true
			continue
		}
		inNum = false
		b.WriteRune(r)
	}
	return b.String()
}

// trackFindings records first-seen times for the current findings and moves
// the ones that disappeared since the previous evaluation to the resolved
// list (dropped again after resolvedKeep, or as soon as they come back).
func (a *App) trackFindings(now time.Time) {
	if a.findingAge == nil {
		a.findingAge = map[string]findingTrack{}
	}
	cur := map[string]bool{}
	for _, f := range a.findings {
		k := findingKey(f)
		cur[k] = true
		t, ok := a.findingAge[k]
		if !ok {
			t.First = now
		}
		t.F, t.Last = f, now
		a.findingAge[k] = t
	}
	for k, t := range a.findingAge {
		if cur[k] {
			continue
		}
		a.resolved = append(a.resolved, resolvedFinding{Finding: t.F, First: t.First, Resolved: now})
		delete(a.findingAge, k)
	}
	keep := a.resolved[:0]
	for _, r := range a.resolved {
		if now.Sub(r.Resolved) > resolvedKeep || cur[findingKey(r.Finding)] {
			continue
		}
		keep = append(keep, r)
	}
	a.resolved = keep
}

// firstSeen is when a current finding was first evaluated (zero if unknown).
func (a *App) firstSeen(f checks.Finding) time.Time {
	return a.findingAge[findingKey(f)].First
}
