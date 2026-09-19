package stig

import (
	"math"
	"sort"
	"strings"
)

// Score is an XCCDF / SCC-style scorecard for one benchmark, optionally for
// one node. It uses the XCCDF default scoring model as SCC and OpenSCAP
// report it for DISA content (every rule weighted equally): the score is
// the share of scored rules that are Not a Finding, where scored means
// Open or Not a Finding - Not Applicable and Not Reviewed rules are left
// out of the denominator, exactly as in an SCC summary.
//
//	Open           = FAIL
//	Not a Finding  = PASS
//	Not Applicable = N/A
//	Not Reviewed   = MANUAL / UNKNOWN
type Score struct {
	Benchmark                                     string // reference document ("custom" for unmapped IDs)
	Node                                          string // "" = cluster-wide or all nodes combined
	Open, NotAFinding, NotApplicable, NotReviewed int
	CatOpen                                       [3]int // Open per severity, index 0 = CAT I
	CatTotal                                      [3]int // scored (Open + Not a Finding) per severity
}

// Percent is the score (0-100), or NaN when nothing was scored.
func (s Score) Percent() float64 {
	if s.Open+s.NotAFinding == 0 {
		return math.NaN()
	}
	return float64(s.NotAFinding) * 100 / float64(s.Open+s.NotAFinding)
}

// Scored is the number of rules counted in the score.
func (s Score) Scored() int { return s.Open + s.NotAFinding }

func (s *Score) add(st Status, cat string) {
	idx := map[string]int{"I": 0, "II": 1, "III": 2}
	c, hasCat := idx[cat]
	switch st {
	case Pass:
		s.NotAFinding++
		if hasCat {
			s.CatTotal[c]++
		}
	case Fail:
		s.Open++
		if hasCat {
			s.CatOpen[c]++
			s.CatTotal[c]++
		}
	case NA:
		s.NotApplicable++
	default:
		s.NotReviewed++
	}
}

// benchmarkOf names the reference document behind a result.
func benchmarkOf(r Result) string {
	if r.Ref != "" {
		return r.Ref
	}
	for _, b := range Benchmarks {
		if b.Matches(r.ID) {
			return b.Name + " " + b.Version
		}
	}
	return "custom"
}

// Scores computes one scorecard per benchmark over the given results. With
// perNode, results that carry per-node outcomes (the OS STIG rules) are
// scored per node as well, so a RHEL 9 and an Ubuntu node each get their
// own line; the combined line (Node "") is always present.
func Scores(rs []Result, perNode bool) []Score {
	type key struct{ bench, node string }
	acc := map[key]*Score{}
	get := func(bench, node string) *Score {
		k := key{bench, node}
		if acc[k] == nil {
			acc[k] = &Score{Benchmark: bench, Node: node}
		}
		return acc[k]
	}
	for _, r := range rs {
		b := benchmarkOf(r)
		get(b, "").add(r.Status, r.Cat)
		if perNode && len(r.PerNode) > 0 {
			for n, st := range r.PerNode {
				get(b, n).add(st, r.Cat)
			}
		}
	}
	out := make([]Score, 0, len(acc))
	for _, s := range acc {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Benchmark != out[j].Benchmark {
			return out[i].Benchmark < out[j].Benchmark
		}
		return out[i].Node < out[j].Node
	})
	return out
}

// ShortBenchmark trims a reference name for narrow displays
// ("DISA RHEL 9 STIG V2R9 (01 Jul 2026)" -> "RHEL 9 STIG V2R9").
func ShortBenchmark(name string) string {
	name = strings.TrimPrefix(name, "DISA ")
	if i := strings.Index(name, " ("); i > 0 {
		name = name[:i]
	}
	return name
}
