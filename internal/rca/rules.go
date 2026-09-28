package rca

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/logs"
)

// Hypothesis is one candidate root cause with the effects seen after it.
type Hypothesis struct {
	Title    string    `json:"title"`
	Score    float64   `json:"score"` // 0..1: how well the evidence supports it
	Cause    string    `json:"cause"`
	Effects  []string  `json:"effects,omitempty"`
	Evidence []Entry   `json:"evidence"`
	Next     []string  `json:"next,omitempty"`
	First    time.Time `json:"first"` // earliest evidence: causes come before their effects
}

// Confidence names the score band.
func (h Hypothesis) Confidence() string {
	switch {
	case h.Score >= 0.75:
		return "high"
	case h.Score >= 0.5:
		return "medium"
	}
	return "low"
}

// Analyze runs every rule and returns the hypotheses, best supported first
// (earliest first among equals).
func Analyze(src Source, tl *Timeline) []Hypothesis {
	c := newCtx(src, tl)
	var hs []Hypothesis
	for _, rule := range rules {
		hs = append(hs, rule(c)...)
	}
	for i := range hs {
		if hs[i].Score > 1 {
			hs[i].Score = 1
		}
		if hs[i].First.IsZero() && len(hs[i].Evidence) > 0 {
			hs[i].First = hs[i].Evidence[0].Time
		}
	}
	sort.SliceStable(hs, func(i, j int) bool {
		if band(hs[i].Score) != band(hs[j].Score) {
			return hs[i].Score > hs[j].Score
		}
		return hs[i].First.Before(hs[j].First)
	})
	return hs
}

func band(s float64) int { return int(s * 10) }

var rules = []func(*ctx) []Hypothesis{
	etcdLatency, diskFull, memory, imagePull, crashLoop, livenessKills, nodeNotReady,
	scheduling, admission, sandboxAndVolumes, accessDenied, trustAndJoin, unitRestarts,
}

type ctx struct {
	src    Source
	now    time.Time // when the data was taken
	tl     *Timeline
	byName map[string][]Entry // by pattern / event reason / status reason
}

func newCtx(src Source, tl *Timeline) *ctx {
	c := &ctx{src: src, tl: tl, now: src.Snap().Taken, byName: map[string][]Entry{}}
	for _, e := range tl.Entries {
		c.byName[e.Pattern] = append(c.byName[e.Pattern], e)
	}
	return c
}

// p returns the entries of the named patterns / reasons, in time order,
// leaving out startup noise (a restart's expected errors).
func (c *ctx) p(names ...string) []Entry {
	var out []Entry
	for _, n := range names {
		for _, e := range c.byName[n] {
			if e.Class != logs.ClassStartup {
				out = append(out, e)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// all is p with the startup-class entries kept: an effect of an earlier
// cause counts even when the classifier could not tell it from start-up
// noise (no "up and running" marker in the window).
func (c *ctx) all(names ...string) []Entry {
	var out []Entry
	for _, n := range names {
		out = append(out, c.byName[n]...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

func after(es []Entry, t time.Time, window time.Duration) []Entry {
	var out []Entry
	for _, e := range es {
		if !e.Time.Before(t) && e.Time.Before(t.Add(window)) {
			out = append(out, e)
		}
	}
	return out
}

func where(es []Entry, keep func(Entry) bool) []Entry {
	var out []Entry
	for _, e := range es {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

// sample picks evidence: the first entries and the last one.
func sample(es []Entry, n int) []Entry {
	if len(es) <= n {
		return es
	}
	out := append([]Entry{}, es[:n-1]...)
	return append(out, es[len(es)-1])
}

// nodes names the nodes of es, the busiest first.
func nodes(es []Entry) string {
	count := map[string]int{}
	for _, e := range es {
		if e.Node != "" {
			count[e.Node]++
		}
	}
	var ns []string
	for n := range count {
		ns = append(ns, n)
	}
	sort.Slice(ns, func(i, j int) bool {
		if count[ns[i]] != count[ns[j]] {
			return count[ns[i]] > count[ns[j]]
		}
		return ns[i] < ns[j]
	})
	if len(ns) > 3 {
		ns = append(ns[:3], fmt.Sprintf("+%d more", len(ns)-3))
	}
	return strings.Join(ns, ", ")
}

func units(es []Entry) string {
	seen := map[string]bool{}
	var us []string
	for _, e := range es {
		u := e.Unit
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		us = append(us, u)
	}
	sort.Strings(us)
	if len(us) > 4 {
		us = append(us[:4], fmt.Sprintf("+%d more", len(us)-4))
	}
	return strings.Join(us, ", ")
}

func explain(pattern string) []string {
	if p := logs.Find(pattern); p != nil {
		return []string{p.Explain}
	}
	return nil
}

func clock(t time.Time) string { return t.Local().Format("15:04:05") }

// ---- etcd -----------------------------------------------------------------

// etcdLatency: a slow etcd disk (or network) comes first; leader elections,
// lost leases of the controllers and the kubelets, and NotReady nodes
// follow. The more of that chain appears after the first slow write, the
// more likely the disk is the cause rather than a symptom.
func etcdLatency(c *ctx) []Hypothesis {
	slow := c.p("etcd-slow-fsync")
	leader := c.p("leader-change")
	lease := c.all("lease-lost")
	nodeLease := c.all("node-lease")
	notReady := c.all("NodeNotReady", "node-ready-false", "node-ready-unknown")
	if len(slow) < 3 && len(leader) < 3 {
		return nil
	}
	var h Hypothesis
	var t0 time.Time
	if len(slow) >= 3 {
		t0 = slow[0].Time
		h = Hypothesis{
			Title: "etcd disk latency on " + nodes(slow),
			Cause: fmt.Sprintf("%d slow fsync / apply warnings from etcd, the first at %s", len(slow), clock(t0)),
			Score: 0.45, Next: append(explain("etcd-slow-fsync"), etcdWhere(c.src.Snap().Distribution)),
		}
		h.Evidence = sample(slow, 3)
	} else {
		t0 = leader[0].Time
		h = Hypothesis{
			Title: "Repeated etcd leader elections",
			Cause: fmt.Sprintf("%d leader changes and no slow-disk warnings: latency or packet loss between the control-plane nodes, or CPU starvation of etcd", len(leader)),
			Score: 0.4, Next: explain("leader-change"),
		}
		h.Evidence = sample(leader, 3)
	}
	window := 30 * time.Minute
	if l := after(leader, t0, window); len(l) > 0 && len(slow) >= 3 {
		h.Score += 0.2
		h.Effects = append(h.Effects, fmt.Sprintf("%d etcd leader elections from %s (%s)", len(l), clock(l[0].Time), nodes(l)))
		h.Evidence = append(h.Evidence, l[0])
	}
	if l := after(lease, t0, window); len(l) > 0 {
		h.Score += 0.15
		h.Effects = append(h.Effects, fmt.Sprintf("control-plane components lost their leader lease %d times from %s (%s)", len(l), clock(l[0].Time), nodes(l)))
		h.Evidence = append(h.Evidence, l[0])
	}
	if l := after(nodeLease, t0, window); len(l) > 0 {
		h.Score += 0.05
		h.Effects = append(h.Effects, fmt.Sprintf("kubelets failed to renew their node lease %d times (%s)", len(l), nodes(l)))
	}
	if l := after(notReady, t0, window); len(l) > 0 {
		h.Score += 0.1
		h.Effects = append(h.Effects, fmt.Sprintf("nodes went NotReady from %s: %s", clock(l[0].Time), nodes(l)))
		h.Evidence = append(h.Evidence, l[0])
	}
	h.First = t0
	return []Hypothesis{h}
}

// etcdWhere names the etcd data dir and where etcd's flags are set, in the
// cluster's own layout.
func etcdWhere(dist string) string {
	v := distro.For(dist)
	flags := "the etcd static pod's command (" + v.Manifests + "/etcd.yaml; kubelet restarts it)"
	if distro.IsRancher(v.Name) {
		flags = "etcd-arg in " + v.ConfigFile + ", then " + v.RestartServer
	}
	return "on " + v.Label + ": etcd's data is in " + v.EtcdDataDir + "; its flags go in " + flags
}

// ---- node resources --------------------------------------------------------

func diskFull(c *ctx) []Hypothesis {
	full := c.p("disk-full")
	pressure := c.p("node-diskpressure-true")
	evict := where(c.p("Evicted", "EvictionThresholdMet", "FreeDiskSpaceFailed", "ImageGCFailed", "eviction"), func(e Entry) bool {
		l := strings.ToLower(e.Text)
		return strings.Contains(l, "ephemeral-storage") || strings.Contains(l, "disk") || strings.Contains(l, "nodefs") || strings.Contains(l, "imagefs") || e.Pattern == "FreeDiskSpaceFailed" || e.Pattern == "ImageGCFailed"
	})
	if len(full)+len(pressure)+len(evict) == 0 {
		return nil
	}
	all := append(append(append([]Entry{}, full...), pressure...), evict...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	h := Hypothesis{Title: "Disk full or under pressure on " + nodes(all), Score: 0.3, First: all[0].Time,
		Next: []string{"df -h / df -i on the node (system/df.txt in the bundle): containerd images (crictl rmi --prune), pod logs, etcd data, core dumps; the kubelet's image GC and eviction thresholds are in config/kubelet.txt"}}
	if len(full) > 0 {
		h.Score += 0.4
		h.Cause = fmt.Sprintf("\"no space left on device\" %d times from %s", len(full), clock(full[0].Time))
	} else {
		h.Cause = "the kubelet reported disk pressure"
	}
	if len(pressure) > 0 {
		h.Score += 0.2
		h.Effects = append(h.Effects, "DiskPressure on "+nodes(pressure))
	}
	if len(evict) > 0 {
		h.Score += 0.15
		h.Effects = append(h.Effects, fmt.Sprintf("%d evictions / image GC failures (%s)", len(evict), units(evict)))
	}
	h.Evidence = append(append(sample(full, 2), sample(pressure, 1)...), sample(evict, 2)...)
	return []Hypothesis{h}
}

func memory(c *ctx) []Hypothesis {
	killed := c.p("terminated-oomkilled")
	kernel := c.p("oom")
	pressure := c.p("node-memorypressure-true")
	evict := where(c.p("Evicted", "EvictionThresholdMet"), func(e Entry) bool { return strings.Contains(strings.ToLower(e.Text), "memory") })
	sysOOM := c.p("SystemOOM", "OOMKilling")
	if len(killed)+len(kernel)+len(pressure)+len(evict)+len(sysOOM) == 0 {
		return nil
	}
	var hs []Hypothesis
	if len(killed) > 0 {
		h := Hypothesis{Title: "Containers killed for exceeding their memory limit (OOMKilled)", Score: 0.8, First: killed[0].Time,
			Cause:    fmt.Sprintf("%d container(s) last terminated as OOMKilled: %s", len(killed), units(killed)),
			Evidence: sample(killed, 3),
			Next:     []string{"raise the container's memory limit or fix its memory growth; the limit is resources.limits.memory in the pod spec (cluster/resources/pods.yaml)"}}
		for _, k := range sample(killed, 3) {
			if lim := memLimit(c, k.Unit); lim != "" {
				h.Effects = append(h.Effects, k.Unit+" memory limit "+lim)
			}
		}
		hs = append(hs, h)
	}
	nodeSide := append(append(append([]Entry{}, kernel...), pressure...), append(evict, sysOOM...)...)
	if len(nodeSide) > 0 {
		sort.SliceStable(nodeSide, func(i, j int) bool { return nodeSide[i].Time.Before(nodeSide[j].Time) })
		h := Hypothesis{Title: "Node memory exhausted on " + nodes(nodeSide), Score: 0.55, First: nodeSide[0].Time,
			Cause:    fmt.Sprintf("the kernel OOM killer or the kubelet's memory eviction acted %d times from %s", len(nodeSide), clock(nodeSide[0].Time)),
			Evidence: sample(nodeSide, 4),
			Next:     []string{"compare the pods' memory requests with the node (system/meminfo.txt, top.txt): requests below real use let the scheduler overcommit the node; set requests close to usage and reserve memory for the system (kube-reserved / system-reserved)"}}
		if len(pressure) > 0 {
			h.Score += 0.2
			h.Effects = append(h.Effects, "MemoryPressure on "+nodes(pressure))
		}
		if len(evict) > 0 {
			h.Score += 0.1
			h.Effects = append(h.Effects, fmt.Sprintf("%d pods evicted for memory", len(evict)))
		}
		hs = append(hs, h)
	}
	return hs
}

// memLimit finds the memory limit of ns/pod/container in the snapshot.
func memLimit(c *ctx, unit string) string {
	parts := strings.SplitN(unit, "/", 3)
	if len(parts) != 3 {
		return ""
	}
	for i := range c.src.Snap().Pods {
		p := &c.src.Snap().Pods[i]
		if p.Namespace != parts[0] || p.Name != parts[1] {
			continue
		}
		for _, ctr := range append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
			if ctr.Name == parts[2] {
				if q, ok := ctr.Resources.Limits[corev1.ResourceMemory]; ok {
					return q.String()
				}
				return "none"
			}
		}
	}
	return ""
}

// ---- images -----------------------------------------------------------------

var pullImage = regexp.MustCompile(`[Ff]ailed to pull image "([^"]+)"`)

// imagePull groups pull failures by image and names the cause from the
// registry's answer.
func imagePull(c *ctx) []Hypothesis {
	fails := where(c.p("Failed", "image-pull-fail", "registry-auth", "registry-tls"), func(e Entry) bool {
		return pullImage.MatchString(e.Text) || e.Kind != "event"
	})
	byImage := map[string][]Entry{}
	for _, e := range fails {
		img := "(image not named)"
		if m := pullImage.FindStringSubmatch(e.Text); m != nil {
			img = m[1]
		}
		byImage[img] = append(byImage[img], e)
	}
	// pods stuck on a pull even without events in the window
	for i := range c.src.Snap().Pods {
		p := &c.src.Snap().Pods[i]
		for j, cs := range p.Status.ContainerStatuses {
			if w := cs.State.Waiting; w != nil && (w.Reason == "ImagePullBackOff" || w.Reason == "ErrImagePull" || w.Reason == "InvalidImageName") {
				img := cs.Image
				if img == "" && j < len(p.Spec.Containers) {
					img = p.Spec.Containers[j].Image
				}
				if _, ok := byImage[img]; !ok {
					byImage[img] = []Entry{{Time: c.now, Kind: "status", Unit: p.Namespace + "/" + p.Name + "/" + cs.Name, Class: logs.ClassWarn, Pattern: w.Reason, Text: w.Message, Ref: Ref{File: "cluster/resources/pods.yaml"}}}
				}
			}
		}
	}
	var hs []Hypothesis
	for img, es := range byImage {
		if img == "(image not named)" && len(byImage) > 1 {
			continue // the journal lines of an image named elsewhere
		}
		sort.SliceStable(es, func(i, j int) bool { return es[i].Time.Before(es[j].Time) })
		why, next := pullCause(es)
		hs = append(hs, Hypothesis{
			Title: "Image cannot be pulled: " + img, Score: 0.8, First: es[0].Time,
			Cause: why, Evidence: sample(es, 3), Next: []string{next},
			Effects: []string{"pods waiting on it: " + units(where(es, func(e Entry) bool { return e.Unit != "" }))},
		})
	}
	return hs
}

func pullCause(es []Entry) (string, string) {
	var all strings.Builder
	for _, e := range es {
		all.WriteString(strings.ToLower(e.Text))
		all.WriteByte('\n')
	}
	t := all.String()
	switch {
	case strings.Contains(t, "401") || strings.Contains(t, "unauthorized") || strings.Contains(t, "no basic auth") || strings.Contains(t, "authorization failed") || strings.Contains(t, "pull access denied"):
		return "the registry refused the credentials (401 / pull access denied)", "check the imagePullSecret or registries.yaml configs for that registry host:port; the Nodes tab preflight probes each endpoint with the configured credentials"
	case strings.Contains(t, "x509") || strings.Contains(t, "certificate"):
		return "TLS verification of the registry failed", "give containerd the registry's CA (registries.yaml configs.<host>.tls.ca_file, or certs.d/<host>/hosts.toml) or fix the registry certificate"
	case strings.Contains(t, "no such host") || strings.Contains(t, "i/o timeout") || strings.Contains(t, "connection refused") || strings.Contains(t, "dial tcp") || strings.Contains(t, "network is unreachable"):
		return "the registry is unreachable from the node (DNS, firewall, proxy)", "resolve and curl the registry from the node; an airgapped cluster needs a mirror in registries.yaml / hosts.toml"
	case strings.Contains(t, "not found") || strings.Contains(t, "manifest unknown") || strings.Contains(t, "invalidimagename"):
		return "the image or tag does not exist in the registry", "check the image name and tag (a typo, a tag never pushed, or the wrong architecture)"
	case strings.Contains(t, "toomanyrequests") || strings.Contains(t, "rate limit"):
		return "the registry rate-limited the pulls", "authenticate to the registry or use a pull-through mirror"
	}
	return "pulls fail (the messages do not say why)", "read the event messages in the evidence; crictl pull <image> on the node shows the registry's answer"
}

// ---- containers -------------------------------------------------------------

var errLine = regexp.MustCompile(`(?i)\b(error|fatal|panic|exception|failed|cannot|can't|refused|denied|not found|no such|timeout|timed out|invalid|missing|unable)\b`)

// crashLoop explains restarting containers by how they ended and what they
// logged last. OOMKilled is left to memory.
func crashLoop(c *ctx) []Hypothesis {
	type group struct {
		pods  []*corev1.Pod
		ctr   string
		state corev1.ContainerStatus
	}
	groups := map[string]*group{}
	var order []string
	for i := range c.src.Snap().Pods {
		p := &c.src.Snap().Pods[i]
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			crash := cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff"
			t := cs.LastTerminationState.Terminated
			if !crash && (cs.RestartCount < 3 || t == nil) {
				continue
			}
			if t != nil && t.Reason == "OOMKilled" {
				continue
			}
			key := p.Namespace + "/" + OwnerOf(p) + "/" + cs.Name
			g := groups[key]
			if g == nil {
				g = &group{ctr: cs.Name, state: cs}
				groups[key] = g
				order = append(order, key)
			}
			g.pods = append(g.pods, p)
		}
	}
	var hs []Hypothesis
	for _, key := range order {
		g := groups[key]
		p := g.pods[0]
		unit := p.Namespace + "/" + p.Name + "/" + g.ctr
		h := Hypothesis{Title: "Container restarting: " + key, Score: 0.6}
		t := g.state.LastTerminationState.Terminated
		how := "restarting"
		if t != nil {
			how = fmt.Sprintf("exits with code %d (%s)", t.ExitCode, orDefault(t.Reason, "no reason"))
			h.First = t.FinishedAt.Time
		}
		h.Cause = fmt.Sprintf("%s, %d restarts, %d pod(s)", how, g.state.RestartCount, len(g.pods))
		// the liveness probe kills it: exit 137/143 after Unhealthy events
		probe := where(c.p("Unhealthy"), func(e Entry) bool {
			return strings.Contains(e.Unit, p.Namespace+"/"+p.Name) && strings.Contains(e.Text, "Liveness")
		})
		if len(probe) > 0 && t != nil && (t.ExitCode == 137 || t.ExitCode == 143) {
			h.Score = 0.8
			h.Cause = "the liveness probe fails and the kubelet kills the container: " + firstLine(probe[len(probe)-1].Text)
			h.Evidence = append(h.Evidence, sample(probe, 2)...)
			h.Next = append(h.Next, "the probe's endpoint, timeouts and initialDelaySeconds; a slow start needs a startupProbe")
		}
		ref, last := lastError(c, p, g.ctr)
		if last != "" {
			h.Score += 0.15
			h.Cause += "; last error logged: " + last
			h.Evidence = append(h.Evidence, Entry{Time: h.First, Kind: "pod", Unit: unit, Class: logs.ClassError, Pattern: "last-error", Text: last, Ref: ref})
		}
		if t != nil && t.ExitCode == 0 && g.state.State.Waiting != nil {
			h.Effects = append(h.Effects, "it exits 0: the command finishes instead of staying in the foreground")
		}
		for _, e := range c.p("terminated-" + strings.ToLower(orDefault(reason(t), "exit"))) {
			if e.Unit == unit {
				h.Evidence = append(h.Evidence, e)
				break
			}
		}
		h.Next = append(h.Next, "kubectl logs --previous "+p.Name+" -n "+p.Namespace+" -c "+g.ctr+" (in the bundle: cluster/pods/"+p.Namespace+"/"+p.Name+"/"+g.ctr+".previous.log)")
		hs = append(hs, h)
	}
	return hs
}

// livenessKills: the kubelet kills containers whose liveness probe fails,
// which reads as restarts with exit 137 and no error of the app's own.
func livenessKills(c *ctx) []Hypothesis {
	killed := where(c.all("Killing"), func(e Entry) bool { return strings.Contains(e.Text, "liveness probe") })
	failing := where(c.all("Unhealthy"), func(e Entry) bool { return strings.Contains(e.Text, "Liveness probe failed") })
	byObj := map[string][]Entry{}
	var order []string
	for _, e := range append(append([]Entry{}, failing...), killed...) {
		if byObj[e.Unit] == nil {
			order = append(order, e.Unit)
		}
		byObj[e.Unit] = append(byObj[e.Unit], e)
	}
	var hs []Hypothesis
	for _, obj := range order {
		es := byObj[obj]
		sort.SliceStable(es, func(i, j int) bool { return es[i].Time.Before(es[j].Time) })
		var probe, kill []Entry
		for _, e := range es {
			if e.Pattern == "Killing" {
				kill = append(kill, e)
			} else {
				probe = append(probe, e)
			}
		}
		if len(probe) == 0 {
			continue
		}
		h := Hypothesis{Title: "Liveness probe failing: " + strings.TrimPrefix(obj, "pod "), Score: 0.6, First: probe[0].Time,
			Cause:    "the probe fails: " + firstLine(probe[len(probe)-1].Text),
			Evidence: sample(es, 3),
			Next:     []string{"test the probe's command or endpoint inside the container; a slow start needs a startupProbe or a longer initialDelaySeconds, a busy app a longer timeoutSeconds / failureThreshold"}}
		if len(kill) > 0 {
			h.Score = 0.8
			h.Effects = append(h.Effects, "the kubelet killed the container for it ("+firstLine(kill[len(kill)-1].Text)+")")
		}
		hs = append(hs, h)
	}
	return hs
}

func reason(t *corev1.ContainerStateTerminated) string {
	if t == nil {
		return ""
	}
	return t.Reason
}

// lastError reads the container's previous log (else its current one)
// and returns its last error-looking line.
func lastError(c *ctx, p *corev1.Pod, ctr string) (Ref, string) {
	for _, prev := range []bool{true, false} {
		ls, file := c.src.PodLog(p.Namespace, p.Name, ctr, prev)
		for i := len(ls) - 1; i >= 0 && i >= len(ls)-200; i-- {
			_, body := parseAPI(ls[i])
			if body == "" {
				body = ls[i]
			}
			if strings.HasPrefix(body, "unable to retrieve container logs") {
				continue // the kubelet's answer for a log that is gone, not a log line (bundles before 2026-09-27)
			}
			if errLine.MatchString(body) {
				return Ref{File: file, Line: i + 1}, clip(strings.TrimSpace(body), 240)
			}
		}
	}
	return Ref{}, ""
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ---- nodes ------------------------------------------------------------------

// nodeNotReady looks at what a NotReady node logged just before it turned.
func nodeNotReady(c *ctx) []Hypothesis {
	var hs []Hypothesis
	for i := range c.src.Snap().Nodes {
		n := &c.src.Snap().Nodes[i]
		var ready *corev1.NodeCondition
		for j := range n.Status.Conditions {
			if n.Status.Conditions[j].Type == corev1.NodeReady {
				ready = &n.Status.Conditions[j]
			}
		}
		if ready == nil || ready.Status == corev1.ConditionTrue {
			continue
		}
		t := ready.LastTransitionTime.Time
		h := Hypothesis{Title: "Node " + n.Name + " NotReady", Score: 0.5, First: t,
			Cause: fmt.Sprintf("Ready=%s since %s: %s", ready.Status, clock(t), strings.TrimSpace(ready.Reason+" "+ready.Message))}
		before := where(c.tl.Entries, func(e Entry) bool {
			return e.Node == n.Name && e.Class >= logs.ClassWarn && e.Kind != "event" && !e.Time.Before(t.Add(-15*time.Minute)) && e.Time.Before(t.Add(2*time.Minute))
		})
		if len(before) > 0 {
			top := topPatterns(before, 3)
			h.Score += 0.15
			h.Cause += "; in the 15 minutes before, the node logged mostly " + strings.Join(top, ", ")
			h.Evidence = sample(before, 4)
			for _, p := range top {
				h.Next = append(h.Next, explain(strings.Fields(p)[0])...)
			}
		}
		if st, ok := c.src.(interface{ SSHStatus(string) string }); ok {
			if s := st.SSHStatus(n.Name); s != "" && s != "ok" && s != "not collected" {
				h.Score += 0.1
				h.Effects = append(h.Effects, "SSH to the node failed too ("+s+"): the machine is down, hung or cut off from the network, not only the kubelet")
			}
		}
		if len(h.Next) == 0 {
			h.Next = []string{"the kubelet and container runtime journals of the node (journal/kubelet.log, journal/rke2-*.log, files/rke2/agent/logs/kubelet.log)"}
		}
		hs = append(hs, h)
	}
	return hs
}

func topPatterns(es []Entry, n int) []string {
	count := map[string]int{}
	for _, e := range es {
		count[e.Pattern]++
	}
	var ps []string
	for p := range count {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool {
		if count[ps[i]] != count[ps[j]] {
			return count[ps[i]] > count[ps[j]]
		}
		return ps[i] < ps[j]
	})
	if len(ps) > n {
		ps = ps[:n]
	}
	for i, p := range ps {
		ps[i] = fmt.Sprintf("%s (x%d)", p, count[p])
	}
	return ps
}

// ---- scheduling and admission ------------------------------------------------

var leadCount = regexp.MustCompile(`^[0-9]+ `)

// scheduling groups FailedScheduling events by their reason text.
func scheduling(c *ctx) []Hypothesis {
	evs := c.p("FailedScheduling")
	if len(evs) == 0 {
		return nil
	}
	groups := map[string][]Entry{}
	for _, e := range evs {
		msg := e.Text
		if i := strings.Index(msg, "are available: "); i >= 0 {
			msg = msg[i+len("are available: "):]
		}
		if i := strings.Index(msg, " preemption:"); i >= 0 {
			msg = msg[:i]
		}
		// "1 Insufficient cpu, 2 node(s) had untolerated taint ..." -> the reasons
		var reasons []string
		for _, part := range strings.Split(strings.TrimSuffix(strings.TrimSpace(msg), "."), ", ") {
			reasons = append(reasons, strings.TrimSpace(leadCount.ReplaceAllString(part, "")))
		}
		msg = strings.Join(reasons, "; ")
		groups[msg] = append(groups[msg], e)
	}
	var hs []Hypothesis
	for msg, es := range groups {
		next := "compare the pods' requests, nodeSelector/affinity and tolerations with the nodes (cluster/resources/nodes.yaml)"
		l := strings.ToLower(msg)
		switch {
		case strings.Contains(l, "insufficient"):
			next = "the requests do not fit on any node: lower them, add capacity, or free it (kubectl describe node: Allocated resources)"
		case strings.Contains(l, "untolerated taint") || strings.Contains(l, "taint"):
			next = "the pods lack a toleration for the nodes' taints (control-plane, NotReady/unreachable or a custom one)"
		case strings.Contains(l, "affinity") || strings.Contains(l, "selector"):
			next = "no node matches the pods' nodeSelector / affinity; check the node labels"
		case strings.Contains(l, "persistentvolumeclaim") || strings.Contains(l, "volume"):
			next = "the pods' volumes cannot be bound or are pinned to other nodes: the PVC events and the StorageClass's volumeBindingMode"
		}
		hs = append(hs, Hypothesis{Title: "Pods cannot be scheduled", Score: 0.8, First: es[0].Time,
			Cause:    msg,
			Effects:  []string{"pods pending: " + units(es)},
			Evidence: sample(es, 2), Next: []string{next}})
	}
	return hs
}

var webhookName = regexp.MustCompile(`failed calling webhook "([^"]+)"`)

// admission explains pods (or ReplicaSets) that could not be created:
// PodSecurity, quota, admission webhooks.
func admission(c *ctx) []Hypothesis {
	evs := c.p("FailedCreate")
	if len(evs) == 0 {
		return nil
	}
	type kind struct{ title, next string }
	groups := map[kind][]Entry{}
	for _, e := range evs {
		l := strings.ToLower(e.Text)
		var k kind
		switch {
		case strings.Contains(l, "violates podsecurity"):
			next := "label the namespace with the pod-security level it needs (pod-security.kubernetes.io/enforce) or fix the pod's securityContext"
			if strings.EqualFold(c.src.Snap().Distribution, "rke2") {
				next += "; rke2's cis profile enforces restricted by default"
			}
			k = kind{"Pods rejected by Pod Security admission", next}
		case strings.Contains(l, "exceeded quota"):
			k = kind{"Pods rejected by a ResourceQuota", "raise the quota or the pods' requests (cluster/resources/resourcequotas.yaml)"}
		case strings.Contains(l, "failed calling webhook"):
			name := "an admission webhook"
			if m := webhookName.FindStringSubmatch(e.Text); m != nil {
				name = m[1]
			}
			k = kind{"Admission webhook " + name + " failing", "the webhook's Service has no ready endpoints or times out (cluster/resources/*webhookconfigurations*.yaml, endpointslices); with failurePolicy Fail it blocks every matching create"}
		default:
			k = kind{"Pods cannot be created", "read the FailedCreate messages in the evidence"}
		}
		groups[k] = append(groups[k], e)
	}
	var hs []Hypothesis
	for k, es := range groups {
		hs = append(hs, Hypothesis{Title: k.title, Score: 0.8, First: es[0].Time,
			Cause: firstLine(es[len(es)-1].Text), Effects: []string{"controllers that cannot create pods: " + units(es)},
			Evidence: sample(es, 2), Next: []string{k.next}})
	}
	return hs
}

// sandboxAndVolumes: pods that are scheduled but cannot start, because the
// CNI cannot set up their network or their volumes do not attach.
func sandboxAndVolumes(c *ctx) []Hypothesis {
	var hs []Hypothesis
	if es := c.p("FailedCreatePodSandBox"); len(es) > 0 {
		hs = append(hs, Hypothesis{Title: "Pod sandboxes fail (CNI) on " + nodes(es), Score: 0.75, First: es[0].Time,
			Cause: firstLine(es[len(es)-1].Text), Effects: []string{"pods stuck in ContainerCreating: " + units(es)},
			Evidence: sample(es, 3), Next: []string{"the CNI pods on those nodes (kube-system canal/calico/cilium) and /etc/cni/net.d (network/cni.txt in the bundle)"}})
	}
	if es := c.p("FailedMount", "FailedAttachVolume", "volume-fail"); len(es) > 0 {
		hs = append(hs, Hypothesis{Title: "Volumes fail to attach or mount", Score: 0.7, First: es[0].Time,
			Cause: firstLine(es[len(es)-1].Text), Effects: []string{"pods waiting for volumes: " + units(es)},
			Evidence: sample(es, 3), Next: []string{"the CSI driver pods and the VolumeAttachments (cluster/resources/volumeattachments.storage.k8s.io.yaml); a Multi-Attach error means the volume is still attached to a node that went away"}})
	}
	return hs
}

// ---- host ---------------------------------------------------------------------

func accessDenied(c *ctx) []Hypothesis {
	var hs []Hypothesis
	if es := c.p("fapolicyd-deny"); len(es) > 0 {
		hs = append(hs, Hypothesis{Title: "fapolicyd blocks executables on " + nodes(es), Score: 0.75, First: es[0].Time,
			Cause: fmt.Sprintf("%d denied execs (%s)", len(es), units(es)), Evidence: sample(es, 3), Next: explain("fapolicyd-deny")})
	}
	if es := c.p("selinux"); len(es) > 0 {
		hs = append(hs, Hypothesis{Title: "SELinux denials on " + nodes(es), Score: 0.6, First: es[0].Time,
			Cause: fmt.Sprintf("%d AVC denials in the logs (system/denials.txt holds the audit records)", len(es)), Evidence: sample(es, 3), Next: explain("selinux")})
	}
	return hs
}

// trustAndJoin: identity and trust errors that stop nodes from joining or
// components from talking, when they persist past a restart.
func trustAndJoin(c *ctx) []Hypothesis {
	var hs []Hypothesis
	for _, name := range []string{"token-mismatch", "ca-mismatch", "cluster-id", "etcd-member-missing", "clock-skew", "port-in-use", "swap", "kernel-defaults", "containerd-down", "kubelet-exit"} {
		es := where(c.p(name), func(e Entry) bool { return e.Class >= logs.ClassWarn })
		if len(es) < 2 {
			continue
		}
		p := logs.Find(name)
		title := name
		if p != nil {
			title = strings.SplitN(p.Explain, ".", 2)[0]
		}
		hs = append(hs, Hypothesis{Title: title + " (" + nodes(es) + ")", Score: 0.7, First: es[0].Time,
			Cause: fmt.Sprintf("%s logged %d times by %s, first at %s", name, len(es), units(es), clock(es[0].Time)), Evidence: sample(es, 3), Next: explain(name)})
	}
	return hs
}

// unitRestarts: systemd restarted a service; the errors just before the
// restart in the same log are what made it exit.
func unitRestarts(c *ctx) []Hypothesis {
	restarts := c.p("unit-restart")
	byUnit := map[string][]Entry{}
	var order []string
	for _, e := range restarts {
		k := e.Node + " " + e.Unit
		if byUnit[k] == nil {
			order = append(order, k)
		}
		byUnit[k] = append(byUnit[k], e)
	}
	var hs []Hypothesis
	for _, k := range order {
		es := byUnit[k]
		first := es[0]
		h := Hypothesis{Title: "Service " + first.Unit + " restarting on " + first.Node, Score: 0.45, First: first.Time,
			Cause: fmt.Sprintf("systemd restarted it %d times", len(es)), Evidence: sample(es, 2)}
		if len(es) >= 3 {
			h.Score += 0.1
		}
		// errors in the same file shortly before the first restart
		prior := where(c.tl.Entries, func(e Entry) bool {
			return e.Ref.File == first.Ref.File && e.Class == logs.ClassError && e.Ref.Line < first.Ref.Line && e.Ref.Line >= first.Ref.Line-50
		})
		if len(prior) > 0 {
			last := prior[len(prior)-1]
			h.Score += 0.15
			h.Cause += "; before the first restart it logged " + last.Pattern + ": " + clip(last.Text, 200)
			h.Evidence = append([]Entry{last}, h.Evidence...)
			h.Next = explain(last.Pattern)
		}
		hs = append(hs, h)
	}
	return hs
}
