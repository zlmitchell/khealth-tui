package rca

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// WriteIncidents prints the incident index: counts by kind, then one line
// per incident (newest first within a kind).
func WriteIncidents(w io.Writer, ins []Incident) {
	count := map[Kind]int{}
	for _, in := range ins {
		count[in.Kind]++
	}
	var parts []string
	for _, k := range Kinds {
		if count[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k.Label(), count[k]))
		}
	}
	fmt.Fprintf(w, "Incidents (%d): %s   (--incident ID for one in context)\n", len(ins), strings.Join(parts, ", "))
	for _, in := range ins {
		n := ""
		if in.Count > 1 {
			n = fmt.Sprintf(" x%d", in.Count)
		}
		fmt.Fprintf(w, "  %-12s %-19s %-14s %-44s %s\n", in.ID, stamp(in.Time)+n, clip(in.Kind.Label(), 14), clip(in.Object(), 44), clip(oneLine(in.Summary), 80))
	}
}

// WriteContext prints one incident in context.
func WriteContext(w io.Writer, c *Context) {
	in := c.Incident
	fmt.Fprintf(w, "%s  %s  %s\n", in.ID, in.Kind.Label(), in.Object())
	fmt.Fprintf(w, "  when:     %s", stamp(in.Time))
	if in.Count > 1 {
		fmt.Fprintf(w, " .. %s (x%d)", stamp(in.Last), in.Count)
	}
	fmt.Fprintf(w, "   node %s   workload %s\n", orDefault(in.Node, "-"), orDefault(in.Workload, "-"))
	fmt.Fprintf(w, "  what:     %s\n", oneLine(in.Summary))

	fmt.Fprintf(w, "\nWho caused it\n")
	if c.Verdict != "" {
		fmt.Fprintf(w, "  %s\n", c.Verdict)
	}
	if len(c.Suspects) == 0 {
		fmt.Fprintln(w, "  no other workload or event points at it")
	}
	for _, s := range c.Suspects {
		fmt.Fprintf(w, "  %3.0f%%  %s\n", s.Score*100, s.Who)
		for _, r := range s.Reasons {
			fmt.Fprintf(w, "        - %s\n", r)
		}
	}

	if wv := c.Workload; wv != nil {
		fmt.Fprintf(w, "\nWorkload %s/%s in %s", wv.Kind, wv.Name, wv.Namespace)
		if wv.Desired > 0 {
			fmt.Fprintf(w, "  ready %d/%d", wv.Ready, wv.Desired)
		}
		fmt.Fprintf(w, "  on %s\n", strings.Join(wv.Nodes, ", "))
		for _, r := range wv.Revisions {
			mark := ""
			if r.Recent {
				mark = "  <- rolled out " + in.Time.Sub(r.Created).Round(time.Second).String() + " before"
			}
			fmt.Fprintf(w, "  rev %-3s %-36s %s  pods %d  %s%s\n", r.Number, clip(r.Name, 36), stamp(r.Created), r.Replicas, strings.Join(r.Images, ","), mark)
		}
		for _, p := range wv.Pods {
			fmt.Fprintf(w, "  pod %-44s %-18s restarts %-3d mem %s/%s (use/limit)\n", clip(p.Name, 44), clip(p.Phase, 18), p.Restarts, humanOr(p.UseMem), humanOr(p.LimMem))
		}
	}

	if sh := c.Node; sh != nil {
		fmt.Fprintf(w, "\nNode %s at %s  [%s]", sh.Name, stamp(in.Time), strings.Join(sh.Roles, ","))
		if len(sh.Conditions) > 0 {
			fmt.Fprintf(w, "  %s", strings.Join(sh.Conditions, " "))
		}
		fmt.Fprintf(w, "\n  requests: cpu %dm of %dm (%d%%), memory %s of %s (%d%%)", sh.ReqCPU, sh.AllocCPU, pct(sh.ReqCPU, sh.AllocCPU), human(sh.ReqMem), human(sh.AllocMem), pct(sh.ReqMem, sh.AllocMem))
		if sh.UseMem >= 0 {
			fmt.Fprintf(w, "; in use at gather: cpu %dm, memory %s", sh.UseCPU, human(sh.UseMem))
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %-52s %-10s %5s %9s %9s %9s  %s\n", "pod (most memory first)", "qos", "prio", "mem req", "mem lim", "mem use", "")
		for i, p := range sh.Pods {
			if i >= 15 {
				fmt.Fprintf(w, "  ... %d more\n", len(sh.Pods)-i)
				break
			}
			var flags []string
			if p.Victim {
				flags = append(flags, "<- this incident")
			}
			if p.Arrived > 0 {
				flags = append(flags, "arrived "+p.Arrived.Round(time.Second).String()+" before")
			}
			fmt.Fprintf(w, "  %-52s %-10s %5d %9s %9s %9s  %s\n", clip(p.Namespace+"/"+p.Name, 52), p.QoS, p.Priority, humanOr(p.ReqMem), humanOr(p.LimMem), humanOr(p.UseMem), strings.Join(flags, ", "))
		}
	}

	if iv := c.Ingress; iv != nil {
		fmt.Fprintf(w, "\nTraffic")
		if len(iv.Services) > 0 {
			fmt.Fprintf(w, " to %s", strings.Join(iv.Services, ", "))
		}
		if len(iv.Routes) > 0 {
			fmt.Fprintf(w, " via %s", strings.Join(iv.Routes, "; "))
		}
		fmt.Fprintln(w)
		if iv.Note != "" {
			fmt.Fprintf(w, "  %s\n", iv.Note)
		}
		for _, m := range iv.Minutes {
			mark := ""
			if !in.Time.Before(m.Start) && in.Time.Before(m.Start.Add(time.Minute)) {
				mark = "  <- incident"
			}
			fmt.Fprintf(w, "  %s  %5d req  %4d 5xx  %4d 4xx  p95 %-8s%s\n", m.Start.Local().Format("15:04"), m.Requests, m.Errors5xx, m.Errors4xx, m.P95.Round(time.Millisecond), mark)
		}
		for i, r := range iv.Errors {
			if i >= 5 {
				break
			}
			fmt.Fprintf(w, "  %s %d %s %s -> %s  (%s)\n", r.Time.Local().Format("15:04:05"), r.Status, r.Method, r.Path, r.Upstream, r.Ref)
		}
	}

	if len(c.Related) > 0 {
		fmt.Fprintf(w, "\nAround it (+/- %s)\n", c.Window)
		for _, o := range c.Related {
			fmt.Fprintf(w, "  %s %-14s %-12s %s\n", stamp(o.Time), clip(o.Kind.Label(), 14), o.ID, o.Object())
		}
	}
	if len(c.LogTail) > 0 {
		fmt.Fprintf(w, "\nLast lines of %s (%s)\n", in.Container, c.LogRef)
		for _, l := range tail(c.LogTail, 10) {
			fmt.Fprintf(w, "  %s\n", clip(l, 160))
		}
	}
	if len(c.Timeline) > 0 {
		fmt.Fprintf(w, "\nTimeline (node %s, namespace %s, control plane)\n", orDefault(in.Node, "-"), orDefault(in.Namespace, "-"))
		for _, g := range Collapse(c.Timeline) {
			when := stamp(g.First)
			if g.Count > 1 {
				when += fmt.Sprintf(" x%d", g.Count)
			}
			fmt.Fprintf(w, "  %-22s %-5s %-20s %-30s %s\n", when, g.Entry.Class, clip(g.Entry.Pattern, 20), clip(g.Entry.Unit, 30), clip(oneLine(g.Entry.Text), 90))
		}
	}
	fmt.Fprintf(w, "\nCluster\n")
	for _, n := range c.Cluster {
		use := "  -"
		if n.MemUsePct >= 0 {
			use = fmt.Sprintf("cpu %3d%% mem %3d%%", n.CPUUsePct, n.MemUsePct)
		}
		fmt.Fprintf(w, "  %-20s %-22s ready %-7s pods %3d  requests cpu %3d%% mem %3d%%  use %s  %s\n", clip(n.Name, 20), clip(strings.Join(n.Roles, ","), 22), n.Ready, n.Pods, n.CPUReqPct, n.MemReqPct, use, strings.Join(n.Pressure, " "))
	}
}

func humanOr(b int64) string {
	switch {
	case b < 0:
		return "?"
	case b == 0:
		return "-"
	}
	return human(b)
}
