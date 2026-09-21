package checks

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// evalUpgrade raises the upgrade-readiness findings: kubelet/API server
// version skew on every cluster, system-upgrade-controller plans (the jobs
// that failed, the nodes that wait, versions that skip a minor) and, on a
// Rancher management cluster, the provisioned clusters whose machines have
// not applied the plan Rancher wants.
func evalUpgrade(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	if s == nil {
		return
	}
	cv := distro.For(s.Distribution)
	rancherDist := distro.IsRancher(cv.Name)

	// ---- kubelet vs API server skew ----
	// The kubelet may be up to three minors older than kube-apiserver and
	// never newer; rke2/k3s agents newer than the servers are the same
	// mistake (agents upgraded first).
	if amaj, amin, _, ok := kubeVersion(s.Version); ok {
		for i := range s.Nodes {
			n := &s.Nodes[i]
			kmaj, kmin, _, ok := kubeVersion(n.Status.NodeInfo.KubeletVersion)
			if !ok || kmaj != amaj {
				continue
			}
			switch {
			case kmin > amin:
				hint := "upgrade the control plane before the kubelets"
				if rancherDist {
					hint = "upgrade the " + cv.Server + " nodes before the agents; an agent newer than the supervisor is unsupported"
				}
				add(SevCrit, "upgrade", n.Name, fmt.Sprintf("kubelet %s is newer than the API server %s: unsupported version skew", n.Status.NodeInfo.KubeletVersion, s.Version), hint)
			case amin-kmin > 3:
				add(SevWarn, "upgrade", n.Name, fmt.Sprintf("kubelet %s is %d minors behind the API server %s: outside the supported skew (3)", n.Status.NodeInfo.KubeletVersion, amin-kmin, s.Version), "upgrade this node")
			}
		}
	}

	u := s.Upgrade
	if u == nil {
		return
	}

	// ---- system-upgrade-controller plans ----
	pendingAny := false
	for _, p := range u.Plans {
		obj := p.Namespace + "/" + p.Name
		target := p.Target()
		done, pending := s.PlanNodes(p)
		if len(pending) > 0 {
			pendingAny = true
		}
		for _, c := range p.Conditions {
			switch c.Type {
			case "LatestResolved":
				add(SevWarn, "upgrade", obj, fmt.Sprintf("plan cannot resolve its version from channel %s: %s", strutil.FirstNonEmpty(p.Channel, p.Version), strutil.FirstNonEmpty(strutil.FirstLine(c.Message), c.Reason, "no answer from the channel yet ("+strings.ToLower(c.Status)+")")), "the controller resolves the channel from inside the cluster (proxy/airgap/DNS): kubectl -n "+p.Namespace+" logs deploy/system-upgrade-controller, or pin spec.version instead")
			case "Validated":
				add(SevWarn, "upgrade", obj, "plan rejected by the controller: "+strutil.FirstNonEmpty(c.Message, c.Reason), "kubectl -n "+p.Namespace+" describe plan "+p.Name)
			}
		}
		if target == "" {
			continue
		}
		tmaj, tmin, _, tok := kubeVersion(target)
		// skipping a minor: rke2/k3s (and Kubernetes) upgrade one minor at a time
		var skips, downgrades []string
		lowest := -1
		for _, node := range pending {
			n := s.Node(node)
			if n == nil || !tok {
				continue
			}
			nmaj, nmin, _, ok := kubeVersion(n.Status.NodeInfo.KubeletVersion)
			if !ok || nmaj != tmaj {
				continue
			}
			switch {
			case tmin-nmin > 1:
				skips = append(skips, node+" ("+n.Status.NodeInfo.KubeletVersion+")")
				if lowest < 0 || nmin < lowest {
					lowest = nmin
				}
			case tmin < nmin:
				downgrades = append(downgrades, node+" ("+n.Status.NodeInfo.KubeletVersion+")")
			}
		}
		if len(skips) > 0 {
			add(SevCrit, "upgrade", obj, fmt.Sprintf("plan targets %s but %s more than one minor behind: %s - skipping a minor version is not supported, the node will not come back healthy", target, pluralCount(len(skips), "node"), strutil.TruncList(skips, 3)), "upgrade one minor at a time: set spec.version to the latest v"+strconv.Itoa(tmaj)+"."+strconv.Itoa(lowest+1)+" release first")
		}
		if len(downgrades) > 0 {
			add(SevWarn, "upgrade", obj, fmt.Sprintf("plan targets %s, older than what %s run: %s - this is a downgrade", target, pluralCount(len(downgrades), "node"), strutil.TruncList(downgrades, 3)), "check spec.version / the channel")
		}
		// jobs: the newest one per node tells why a node is stuck
		latest := map[string]k8s.UpgradeJob{}
		for _, j := range p.Jobs {
			if prev, ok := latest[j.Node]; !ok || j.Started.After(prev.Started) {
				latest[j.Node] = j
			}
		}
		lastActivity := p.Created
		for node, j := range latest {
			if j.Started.After(lastActivity) {
				lastActivity = j.Started
			}
			switch {
			case j.FailedReason != "" || (j.Failed > 0 && j.Active == 0 && j.Succeeded == 0):
				msg := fmt.Sprintf("upgrade of %s to %s failed (job %s", node, target, j.Name)
				if j.FailedReason != "" {
					msg += ", " + j.FailedReason
				}
				msg += ")"
				hint := "kubectl -n " + p.Namespace + " logs job/" + j.Name + "; the node may be left cordoned"
				if j.PodState != "" {
					msg += ": " + j.PodState
					if j.PodMessage != "" {
						msg += " - " + shortMsg(j.PodMessage)
					}
					if isPullError(j.PodState) {
						hint = pullHint(p, node, j.PodMessage) + ", then delete the job to retry"
					}
				}
				add(SevCrit, "upgrade", obj, msg, hint)
			case j.Active > 0 && isPullError(j.PodState):
				add(SevCrit, "upgrade", obj, fmt.Sprintf("upgrade job for %s cannot start: %s (%s)", node, j.PodState, shortMsg(j.PodMessage)), pullHint(p, node, j.PodMessage))
			case j.Active > 0 && j.PodState != "" && j.PodState != "Running":
				add(SevWarn, "upgrade", obj, fmt.Sprintf("upgrade job for %s is not running: %s (%s)", node, j.PodState, strutil.FirstLine(j.PodMessage)), "kubectl -n "+p.Namespace+" describe job "+j.Name)
			case j.Active > 0 && !j.Started.IsZero() && in.Now.Sub(j.Started) > 30*time.Minute:
				add(SevWarn, "upgrade", obj, fmt.Sprintf("upgrade of %s to %s has been running for %s: the drain or the %s restart is stuck", node, target, in.Now.Sub(j.Started).Round(time.Minute), cv.Name), "kubectl -n "+p.Namespace+" logs job/"+j.Name+"; pods that refuse to drain (PDBs, local storage) hold the job")
			case j.Active > 0:
				add(SevInfo, "upgrade", obj, fmt.Sprintf("upgrading %s to %s now (%s ago)", node, target, in.Now.Sub(j.Started).Round(time.Minute)), "the node is cordoned/drained by the plan while the job runs")
			}
		}
		// a done label on a node that still runs the old version: the job
		// succeeded but the binary was not replaced (rpm installs are not
		// upgraded by the rke2-upgrade image) or the service never restarted
		for _, node := range done {
			n := s.Node(node)
			if n == nil || !tok {
				continue
			}
			nmaj, nmin, npatch, ok := kubeVersion(n.Status.NodeInfo.KubeletVersion)
			_, _, tpatch, _ := kubeVersion(target)
			if ok && (nmaj != tmaj || nmin != tmin || npatch != tpatch) {
				add(SevWarn, "upgrade", obj, fmt.Sprintf("%s is marked upgraded to %s but runs %s: the upgrade job succeeded without the %s restart taking effect", node, target, n.Status.NodeInfo.KubeletVersion, cv.Name), "an rpm-installed "+cv.Name+" is not upgraded by the upgrade image (use the package manager); otherwise restart "+cv.Server+" on the node")
			}
		}
		// nodes the plan owes with no job at all
		var waiting []string
		for _, node := range pending {
			if _, has := latest[node]; has {
				continue
			}
			if n := s.Node(node); n != nil && sameVersion(n.Status.NodeInfo.KubeletVersion, target) {
				continue // already there, only the label is missing
			}
			waiting = append(waiting, node)
		}
		if len(waiting) > 0 && len(p.Applying) == 0 && in.Now.Sub(lastActivity) > 10*time.Minute {
			hint := "kubectl -n " + p.Namespace + " logs deploy/system-upgrade-controller; the plan's nodeSelector and tolerations must match the node, and cordoned nodes are skipped unless the plan cordons itself"
			if r := s.Rancher; r != nil && r.SystemUpgradeOK != nil && !*r.SystemUpgradeOK {
				hint = "system-upgrade-controller is not ready: nothing schedules the upgrade jobs"
			}
			add(SevWarn, "upgrade", obj, fmt.Sprintf("plan targets %s but no upgrade job exists for %s (%s since the last activity)", target, strutil.TruncList(waiting, 3), in.Now.Sub(lastActivity).Round(time.Minute)), hint)
		}
	}
	if r := s.Rancher; r != nil && r.SystemUpgradeOK != nil && !*r.SystemUpgradeOK && pendingAny {
		add(SevCrit, "upgrade", "system-upgrade-controller", "system-upgrade-controller is not ready while plans have nodes to upgrade", "kubectl -n cattle-system describe deploy system-upgrade-controller")
	}

	// ---- Rancher management cluster: provisioned clusters ----
	for _, pc := range u.Provisioned {
		obj := pc.Name
		if !pc.Ready {
			sev := SevWarn
			msg := "provisioned cluster is not ready"
			if c := worstCondition(pc.Conditions); c != nil {
				msg += ": " + c.Type + " " + condText(*c)
				if condLooksFailed(*c) {
					sev = SevCrit
				}
			}
			add(sev, "upgrade", obj, msg, "Rancher UI: Cluster Management -> "+pc.Name+" -> conditions; kubectl -n "+pc.Namespace+" get clusters.provisioning.cattle.io "+pc.Name+" -o yaml")
		}
		for _, c := range pc.CPConditions {
			if c.Type == "Ready" && !pc.Ready {
				continue // said above
			}
			sev := SevInfo
			if condLooksFailed(c) {
				sev = SevCrit
			} else if c.Type == "Stable" || c.Type == "Reconciled" {
				sev = SevWarn
			}
			add(sev, "upgrade", obj, "control plane "+c.Type+": "+condText(c), "the planner's current step; kubectl -n "+pc.Namespace+" get rkecontrolplane "+pc.Name+" -o yaml")
		}
		if pc.Version != "" && pc.CPVersion != "" && pc.Version != pc.CPVersion {
			add(SevInfo, "upgrade", obj, fmt.Sprintf("cluster spec asks for %s, the control plane object still says %s: upgrade being rolled out", pc.Version, pc.CPVersion), "")
		}
		var behind, pendingPlan []string
		for _, m := range pc.Machines {
			mobj := pc.Name + "/" + strutil.FirstNonEmpty(m.Node, m.Name)
			if pc.Version != "" && m.Version != "" && !sameVersion(m.Version, pc.Version) {
				behind = append(behind, strutil.FirstNonEmpty(m.Node, m.Name)+" ("+m.Version+")")
			}
			if m.Phase != "" && m.Phase != "Running" {
				sev := SevWarn
				if m.Phase == "Failed" {
					sev = SevCrit
				}
				msg := "machine is " + m.Phase
				if c := worstCondition(m.Conditions); c != nil {
					msg += ": " + c.Type + " " + condText(*c)
				}
				add(sev, "upgrade", mobj, msg, "Rancher UI: cluster -> Machines; kubectl -n "+pc.Namespace+" describe machine "+m.Name)
			} else if c := worstCondition(m.Conditions); c != nil && condLooksFailed(*c) {
				add(SevWarn, "upgrade", mobj, "machine "+c.Type+" "+condText(*c), "kubectl -n "+pc.Namespace+" describe machine "+m.Name)
			}
			mp := m.Plan
			if mp == nil || !mp.HasPlan {
				continue
			}
			switch {
			case mp.Failed:
				msg := fmt.Sprintf("rancher-system-agent gave up on Rancher's plan after %d failure(s)", mp.Failures)
				if mp.Threshold > 0 {
					msg = fmt.Sprintf("rancher-system-agent gave up on Rancher's plan after %d/%d failures", mp.Failures, mp.Threshold)
				}
				add(SevCrit, "upgrade", mobj, msg, "journalctl -u rancher-system-agent on the node (the plan's instruction output is in the machine plan secret, applied-output); the plan stays failed until the node is fixed or Rancher generates a new plan (edit the cluster)")
			case !mp.InSync:
				pendingPlan = append(pendingPlan, strutil.FirstNonEmpty(m.Node, m.Name))
				if mp.Failing {
					limit := ""
					if mp.Threshold > 0 {
						limit = fmt.Sprintf(" of %d before Rancher gives up", mp.Threshold)
					}
					add(SevWarn, "upgrade", mobj, fmt.Sprintf("Rancher's plan is not applied yet: %d failed attempt(s)%s, the agent keeps retrying", mp.Failures, limit), "journalctl -u rancher-system-agent on the node")
				}
			}
			if unhealthy := mp.UnhealthyProbes(); len(unhealthy) > 0 {
				add(SevWarn, "upgrade", mobj, "rancher-system-agent health probes failing: "+strings.Join(unhealthy, ", "), "Rancher holds further plans (upgrades, config changes) for this node until the probes pass; check the named component on the node")
			}
		}
		if len(pendingPlan) > 0 {
			sev := SevInfo
			// a plan pending on a machine that has been around for a while is
			// an agent that stopped listening or a node that cannot apply it
			old := 0
			for _, m := range pc.Machines {
				if m.Plan != nil && m.Plan.HasPlan && !m.Plan.InSync && !m.Plan.Failed && in.Now.Sub(m.Created) > 30*time.Minute {
					old++
				}
			}
			if old > 0 {
				sev = SevWarn
			}
			add(sev, "upgrade", obj, fmt.Sprintf("Rancher plan pending on %d machine(s): %s", len(pendingPlan), strutil.TruncList(pendingPlan, 4)), "rancher-system-agent applies it when it polls; if it stays pending check the agent unit and its connection to "+"the Rancher server on those nodes")
		}
		if len(behind) > 0 {
			add(SevInfo, "upgrade", obj, fmt.Sprintf("%d/%d machine(s) not yet on %s: %s", len(behind), len(pc.Machines), pc.Version, strutil.TruncList(behind, 4)), "Rancher upgrades one machine at a time per role (rkeConfig.upgradeStrategy)")
		}
	}
	if u.SecretsDenied && len(u.Provisioned) > 0 {
		add(SevInfo, "upgrade", "rancher", "machine plan secrets are not readable with this token: pending/failed plans per machine are unknown", "grant get/list on secrets in fleet-default (type rke.cattle.io/machine-plan)")
	}
}

var kubeVersionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// kubeVersion parses "v1.35.8+rke2r1" / "1.35.8" into its numbers.
func kubeVersion(v string) (major, minor, patch int, ok bool) {
	m := kubeVersionRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	patch, _ = strconv.Atoi(m[3])
	return major, minor, patch, true
}

// sameVersion compares two versions on major.minor.patch, ignoring the
// distribution suffix (+rke2r1 vs +rke2r2 is a different build, but the
// kubelet reports the same Kubernetes version either way).
func sameVersion(a, b string) bool {
	am, an, ap, ok1 := kubeVersion(a)
	bm, bn, bp, ok2 := kubeVersion(b)
	if !ok1 || !ok2 {
		return a == b
	}
	if am != bm || an != bn || ap != bp {
		return false
	}
	// the build suffix matters when both carry one (v1.35.8+rke2r1 -> +rke2r2)
	as, bs := suffixOf(a), suffixOf(b)
	return as == "" || bs == "" || as == bs
}

func suffixOf(v string) string {
	if i := strings.Index(v, "+"); i >= 0 {
		return v[i+1:]
	}
	return ""
}

// pullHint tells a tag that does not exist (the version in the plan has no
// upgrade image) from a registry the node cannot reach.
func pullHint(p k8s.UpgradePlan, node, msg string) string {
	low := strings.ToLower(msg)
	if strings.Contains(low, "notfound") || strings.Contains(low, "not found") || strings.Contains(low, "manifest unknown") {
		return "there is no " + p.Image + " image for " + p.Target() + ": the version in spec.version does not exist (or has no upgrade image yet), check the release name"
	}
	return "the upgrade image " + p.Image + " is not pullable from " + node + " (registry/airgap): mirror it or fix registries.yaml"
}

// shortMsg keeps the first line of a pod message, cut to 160 characters.
func shortMsg(s string) string {
	s = strutil.FirstLine(s)
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}

func isPullError(state string) bool {
	return state == "ImagePullBackOff" || state == "ErrImagePull" || state == "InvalidImageName" || state == "ErrImageNeverPull"
}

func condText(c k8s.CondSummary) string {
	s := strings.ToLower(c.Status)
	if c.Reason != "" {
		s += " (" + c.Reason + ")"
	}
	if c.Message != "" {
		s += ": " + strutil.FirstLine(c.Message)
	}
	return s
}

// condLooksFailed says whether a non-True condition reports an error rather
// than progress.
func condLooksFailed(c k8s.CondSummary) bool {
	r := strings.ToLower(c.Reason + " " + c.Message)
	return strings.Contains(r, "error") || strings.Contains(r, "fail") || strings.Contains(r, "timed out") || strings.Contains(r, "timeout")
}

// worstCondition picks the condition to quote: a failed one first, then
// the first with a message.
func worstCondition(conds []k8s.CondSummary) *k8s.CondSummary {
	for i := range conds {
		if condLooksFailed(conds[i]) {
			return &conds[i]
		}
	}
	for i := range conds {
		if conds[i].Message != "" {
			return &conds[i]
		}
	}
	if len(conds) > 0 {
		return &conds[0]
	}
	return nil
}

func pluralCount(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
