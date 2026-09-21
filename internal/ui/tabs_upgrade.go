package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// upgradeSection renders the upgrade-readiness block of the Addons tab:
// system-upgrade-controller plans with what they still owe, and on a
// Rancher management cluster the provisioned clusters with their machines'
// plan state. Nothing is printed when neither exists.
func (a *App) upgradeSection(s *k8s.Snapshot, add func(lines ...string), addRow func(id, line string)) {
	u := s.Upgrade
	if u == nil || (len(u.Plans) == 0 && len(u.Provisioned) == 0) {
		return
	}
	if len(u.Plans) > 0 {
		add("", styleTitle.Render("Upgrade plans")+styleDim.Render("  (system-upgrade-controller: one job per node, done = node carries the plan's hash label)"))
		var rows [][]string
		var ids []string
		for _, p := range u.Plans {
			done, pending := s.PlanNodes(p)
			target := p.Target()
			if target == "" {
				target = styleDim.Render("unresolved")
			}
			if p.Channel != "" {
				target += styleDim.Render(" (channel)")
			}
			var failed, active int
			var pull string
			for _, j := range p.Jobs {
				if j.FailedReason != "" || (j.Failed > 0 && j.Active == 0 && j.Succeeded == 0) {
					failed++
				}
				if j.Active > 0 {
					active++
				}
				if strings.Contains(j.PodState, "ImagePull") || strings.Contains(j.PodState, "ErrImage") {
					pull = j.PodState
				}
			}
			state := styleOK.Render("complete")
			switch {
			case len(p.Conditions) > 0:
				c := p.Conditions[0]
				state = styleWarn.Render(c.Type + " " + strings.ToLower(c.Status) + strutil.PrefixIf(": ", strutil.FirstLine(c.Message)))
			case failed > 0:
				state = styleCrit.Render(fmt.Sprintf("%d job(s) failed", failed) + strutil.PrefixIf(": ", pull))
			case len(p.Applying) > 0 || active > 0:
				state = styleWarn.Render("applying on " + strings.Join(p.Applying, ", "))
			case len(pending) > 0:
				state = styleDim.Render("waiting")
			}
			jobs := fmt.Sprintf("%d", len(p.Jobs))
			if failed > 0 {
				jobs += styleCrit.Render(fmt.Sprintf(" (%d failed)", failed))
			}
			rows = append(rows, []string{p.Namespace + "/" + p.Name, target, fmt.Sprint(len(done)), pendingText(pending), jobs, fmt.Sprint(p.Concurrency), okText(p.Cordon || p.Drain, "yes", "no"), state})
			ids = append(ids, "plan:"+p.Namespace+"/"+p.Name)
		}
		h, lines := renderTable(a.width, []column{{title: "PLAN"}, {title: "TARGET", max: 24}, {title: "DONE"}, {title: "PENDING", max: 30}, {title: "JOBS"}, {title: "CONC"}, {title: "DRAIN"}, {title: "STATE", max: 60}}, rows)
		add(h)
		for i, l := range lines {
			addRow(ids[i], l)
		}
	}
	if len(u.Provisioned) > 0 {
		add("", styleTitle.Render("Provisioned clusters")+styleDim.Render("  (Rancher v2prov: what the planner is waiting on, and whether rancher-system-agent on every machine applied its plan)"))
		if u.SecretsDenied {
			add(styleDim.Render("  machine plan secrets not readable with this token: plan state per machine unknown"))
		}
		var rows [][]string
		var ids []string
		for _, pc := range u.Provisioned {
			ver := pc.Version
			if pc.CPVersion != "" && pc.CPVersion != pc.Version {
				ver = pc.CPVersion + styleWarn.Render(" -> "+pc.Version)
			}
			var running, other int
			var inSync, pendingPlan, failedPlan, probes int
			var behind []string
			for _, m := range pc.Machines {
				if m.Phase == "Running" || m.Phase == "" {
					running++
				} else {
					other++
				}
				if m.Plan != nil && m.Plan.HasPlan {
					switch {
					case m.Plan.Failed:
						failedPlan++
					case m.Plan.InSync:
						inSync++
					default:
						pendingPlan++
					}
					if len(m.Plan.UnhealthyProbes()) > 0 {
						probes++
					}
				}
				if pc.Version != "" && m.Version != "" && !sameKubeVersion(m.Version, pc.Version) {
					behind = append(behind, strutil.FirstNonEmpty(m.Node, m.Name))
				}
			}
			machines := fmt.Sprintf("%d running", running)
			if other > 0 {
				machines += styleWarn.Render(fmt.Sprintf(", %d not", other))
			}
			plans := styleDim.Render("-")
			if inSync+pendingPlan+failedPlan > 0 {
				parts := []string{styleOK.Render(fmt.Sprintf("%d in sync", inSync))}
				if pendingPlan > 0 {
					parts = append(parts, styleWarn.Render(fmt.Sprintf("%d pending", pendingPlan)))
				}
				if failedPlan > 0 {
					parts = append(parts, styleCrit.Render(fmt.Sprintf("%d failed", failedPlan)))
				}
				if probes > 0 {
					parts = append(parts, styleWarn.Render(fmt.Sprintf("%d probes failing", probes)))
				}
				plans = strings.Join(parts, ", ")
			}
			note := ""
			if len(behind) > 0 {
				note = fmt.Sprintf("%d machine(s) not on %s: %s", len(behind), pc.Version, strutil.TruncList(behind, 3))
			}
			for _, c := range append(append([]k8s.CondSummary{}, pc.CPConditions...), pc.Conditions...) {
				if c.Message != "" {
					note = c.Type + ": " + strutil.FirstLine(c.Message)
					break
				}
			}
			rows = append(rows, []string{pc.Name, ver, okText(pc.Ready, "ready", "not ready"), okText(pc.CPReady, "ready", "not ready"), machines, plans, note})
			ids = append(ids, "provcluster:"+pc.Namespace+"/"+pc.Name)
		}
		h, lines := renderTable(a.width, []column{{title: "CLUSTER"}, {title: "VERSION", max: 30}, {title: "READY"}, {title: "CONTROL PLANE"}, {title: "MACHINES"}, {title: "AGENT PLANS", max: 40}, {title: "NOTE", max: 70}}, rows)
		add(h)
		for i, l := range lines {
			addRow(ids[i], l)
		}
	}
}

func pendingText(nodes []string) string {
	if len(nodes) == 0 {
		return styleOK.Render("0")
	}
	return styleWarn.Render(fmt.Sprintf("%d: %s", len(nodes), strutil.TruncList(nodes, 3)))
}

// sameKubeVersion compares major.minor.patch and, when both carry one, the
// build suffix (+rke2r1).
func sameKubeVersion(a, b string) bool {
	trim := func(v string) (string, string) {
		v = strings.TrimPrefix(strings.TrimSpace(v), "v")
		if i := strings.Index(v, "+"); i >= 0 {
			return v[:i], v[i+1:]
		}
		return v, ""
	}
	av, as := trim(a)
	bv, bs := trim(b)
	return av == bv && (as == "" || bs == "" || as == bs)
}

// planDetail is the Enter view of an upgrade plan row: every job with its
// node, state and message, and the nodes still pending.
func (a *App) planDetail(s *k8s.Snapshot, key string) []string {
	if s == nil || s.Upgrade == nil {
		return nil
	}
	for _, p := range s.Upgrade.Plans {
		if p.Namespace+"/"+p.Name != key {
			continue
		}
		done, pending := s.PlanNodes(p)
		lines := []string{styleTitle.Render("Plan " + key), ""}
		lines = append(lines, kv("target", p.Target())+"  "+kv("version", strutil.FirstNonEmpty(p.Version, "-"))+"  "+kv("channel", strutil.FirstNonEmpty(p.Channel, "-"))+"  "+kv("hash", strutil.FirstNonEmpty(p.Hash, "-")))
		lines = append(lines, kv("image", strutil.FirstNonEmpty(p.Image, "-"))+"  "+kv("concurrency", fmt.Sprint(p.Concurrency))+"  "+kv("cordon", fmt.Sprint(p.Cordon))+"  "+kv("drain", fmt.Sprint(p.Drain))+"  "+kv("created", age(p.Created)+" ago"))
		if p.Selector != nil {
			var sel []string
			for _, k := range strutil.SortedKeys(p.Selector.MatchLabels) {
				sel = append(sel, k+"="+p.Selector.MatchLabels[k])
			}
			for _, e := range p.Selector.MatchExpressions {
				sel = append(sel, fmt.Sprintf("%s %s %s", e.Key, strings.ToLower(string(e.Operator)), strings.Join(e.Values, "|")))
			}
			lines = append(lines, wrap("  "+kv("node selector", strings.Join(sel, ", ")), a.width-2)...)
		}
		for _, c := range p.Conditions {
			lines = append(lines, wrap("  "+styleWarn.Render(c.Type+" "+c.Status)+" "+c.Reason+strutil.PrefixIf(": ", c.Message), a.width-2)...)
		}
		lines = append(lines, "", kv("done", fmt.Sprintf("%d %s", len(done), strutil.TruncList(done, 8))), kv("pending", fmt.Sprintf("%d %s", len(pending), strutil.TruncList(pending, 8))), kv("applying", strings.Join(p.Applying, ", ")))
		if len(p.Jobs) > 0 {
			lines = append(lines, "", styleTitle.Render("Jobs"))
			var rows [][]string
			for _, j := range p.Jobs {
				st := styleDim.Render("-")
				switch {
				case j.FailedReason != "" || (j.Failed > 0 && j.Active == 0 && j.Succeeded == 0):
					st = styleCrit.Render("failed " + j.FailedReason)
				case j.Succeeded > 0:
					st = styleOK.Render("succeeded")
				case j.Active > 0:
					st = styleWarn.Render("active")
				}
				when := "-"
				if !j.Started.IsZero() {
					when = age(j.Started) + " ago"
					if !j.Completed.IsZero() {
						when += " (" + j.Completed.Sub(j.Started).Round(time.Second).String() + ")"
					}
				}
				rows = append(rows, []string{j.Name, j.Node, j.Version, st, when, strings.TrimSpace(j.PodState + strutil.PrefixIf(": ", strutil.FirstLine(j.PodMessage)))})
			}
			h, tl := renderTable(a.width, []column{{title: "JOB", max: 50}, {title: "NODE"}, {title: "VERSION"}, {title: "STATE"}, {title: "STARTED"}, {title: "POD", max: 60}}, rows)
			lines = append(lines, h)
			lines = append(lines, tl...)
		}
		return lines
	}
	return nil
}

// provClusterDetail is the Enter view of a provisioned cluster row: the
// conditions and every machine with its plan state.
func (a *App) provClusterDetail(s *k8s.Snapshot, key string) []string {
	if s == nil || s.Upgrade == nil {
		return nil
	}
	for _, pc := range s.Upgrade.Provisioned {
		if pc.Namespace+"/"+pc.Name != key {
			continue
		}
		lines := []string{styleTitle.Render("Provisioned cluster " + pc.Name), ""}
		lines = append(lines, kv("management name", strutil.FirstNonEmpty(pc.MgmtName, "-"))+"  "+kv("spec version", strutil.FirstNonEmpty(pc.Version, "-"))+"  "+kv("control plane version", strutil.FirstNonEmpty(pc.CPVersion, "-"))+"  "+kv("ready", okText(pc.Ready, "yes", "no"))+"  "+kv("control plane ready", okText(pc.CPReady, "yes", "no")))
		if len(pc.Conditions)+len(pc.CPConditions) > 0 {
			lines = append(lines, "", styleTitle.Render("Conditions not True"))
			for _, c := range pc.Conditions {
				lines = append(lines, wrap("  cluster "+styleWarn.Render(c.Type+" "+c.Status)+" "+c.Reason+strutil.PrefixIf(": ", c.Message), a.width-2)...)
			}
			for _, c := range pc.CPConditions {
				lines = append(lines, wrap("  control plane "+styleWarn.Render(c.Type+" "+c.Status)+" "+c.Reason+strutil.PrefixIf(": ", c.Message), a.width-2)...)
			}
		}
		if len(pc.Machines) > 0 {
			lines = append(lines, "", styleTitle.Render("Machines"))
			var rows [][]string
			for _, m := range pc.Machines {
				plan := styleDim.Render("unknown")
				if m.Plan != nil && m.Plan.HasPlan {
					switch {
					case m.Plan.Failed:
						plan = styleCrit.Render(fmt.Sprintf("failed %dx, agent gave up", m.Plan.Failures))
					case m.Plan.InSync:
						plan = styleOK.Render("in sync")
					default:
						plan = styleWarn.Render("pending")
						if m.Plan.Failing {
							plan += styleWarn.Render(fmt.Sprintf(" (%d failed attempts, retrying)", m.Plan.Failures))
						}
					}
					if u := m.Plan.UnhealthyProbes(); len(u) > 0 {
						plan += styleWarn.Render(" probes failing: " + strings.Join(u, ","))
					}
				}
				phase := m.Phase
				if phase != "Running" {
					phase = styleWarn.Render(phase)
				}
				note := ""
				if c := m.Conditions; len(c) > 0 {
					note = c[0].Type + " " + c[0].Status + strutil.PrefixIf(": ", strutil.FirstLine(strutil.FirstNonEmpty(c[0].Message, c[0].Reason)))
				}
				rows = append(rows, []string{m.Name, strutil.FirstNonEmpty(m.Node, "-"), strings.Join(m.Roles, ","), strutil.FirstNonEmpty(m.Version, "-"), phase, plan, note})
			}
			h, tl := renderTable(a.width, []column{{title: "MACHINE", max: 40}, {title: "NODE"}, {title: "ROLES"}, {title: "VERSION"}, {title: "PHASE"}, {title: "AGENT PLAN", max: 60}, {title: "CONDITION", max: 60}}, rows)
			lines = append(lines, h)
			lines = append(lines, tl...)
		}
		return lines
	}
	return nil
}
