package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

// controllerKinds are the pod owners that get their own rows; pods owned by
// anything else (nothing, a Node, a CR) are listed as standalone pods.
var controllerKinds = map[string]bool{"ReplicaSet": true, "DaemonSet": true, "StatefulSet": true, "Job": true, "Deployment": true, "CronJob": true}

// workloadsContent lists controllers, then pods not owned by a controller.
func (a *App) workloadsContent() content {
	switch a.subName() {
	case "Pods":
		return a.podsContent()
	case "Resources":
		return a.crdsContent()
	}
	s := a.snap
	var hdr []string
	var rows [][]string
	var ids []string
	unhealthy := 0
	total := 0

	type wl struct {
		kind, ns, name, ready, status, extra string
		age                                  time.Time
		bad                                  bool
	}
	var items []wl
	for i := range s.Deployments {
		d := &s.Deployments[i]
		if !a.inNamespace(d.Namespace) {
			continue
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		w := wl{kind: "Deployment", ns: d.Namespace, name: d.Name, ready: fmt.Sprintf("%d/%d", d.Status.ReadyReplicas, want), age: d.CreationTimestamp.Time, extra: images(d.Spec.Template.Spec)}
		switch {
		case d.Spec.Paused:
			w.status, w.bad = "Paused", false
		case want == 0:
			w.status = "Scaled to 0"
		case d.Status.UnavailableReplicas > 0 || d.Status.ReadyReplicas < want:
			w.status, w.bad = fmt.Sprintf("%d unavailable", want-d.Status.ReadyReplicas), true
		case d.Status.UpdatedReplicas < want:
			w.status = "Rolling out"
		default:
			w.status = "Available"
		}
		for _, c := range d.Status.Conditions {
			if c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse {
				w.status, w.bad = "Progress deadline exceeded", true
			}
		}
		items = append(items, w)
	}
	for i := range s.DaemonSets {
		d := &s.DaemonSets[i]
		if !a.inNamespace(d.Namespace) {
			continue
		}
		w := wl{kind: "DaemonSet", ns: d.Namespace, name: d.Name, ready: fmt.Sprintf("%d/%d", d.Status.NumberReady, d.Status.DesiredNumberScheduled), age: d.CreationTimestamp.Time, extra: images(d.Spec.Template.Spec)}
		switch {
		case d.Status.NumberReady < d.Status.DesiredNumberScheduled:
			w.status, w.bad = fmt.Sprintf("%d not ready", d.Status.DesiredNumberScheduled-d.Status.NumberReady), true
		case d.Status.NumberMisscheduled > 0:
			w.status, w.bad = fmt.Sprintf("%d misscheduled", d.Status.NumberMisscheduled), true
		case d.Status.UpdatedNumberScheduled < d.Status.DesiredNumberScheduled:
			w.status = "Rolling out"
		default:
			w.status = "Available"
		}
		items = append(items, w)
	}
	for i := range s.StatefulSets {
		d := &s.StatefulSets[i]
		if !a.inNamespace(d.Namespace) {
			continue
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		w := wl{kind: "StatefulSet", ns: d.Namespace, name: d.Name, ready: fmt.Sprintf("%d/%d", d.Status.ReadyReplicas, want), age: d.CreationTimestamp.Time, extra: images(d.Spec.Template.Spec)}
		switch {
		case want == 0:
			w.status = "Scaled to 0"
		case d.Status.ReadyReplicas < want:
			w.status, w.bad = fmt.Sprintf("%d not ready", want-d.Status.ReadyReplicas), true
		case d.Status.UpdateRevision != "" && d.Status.CurrentRevision != d.Status.UpdateRevision:
			w.status = "Rolling out"
		default:
			w.status = "Available"
		}
		items = append(items, w)
	}
	for i := range s.Jobs {
		j := &s.Jobs[i]
		if !a.inNamespace(j.Namespace) {
			continue
		}
		comp := int32(1)
		if j.Spec.Completions != nil {
			comp = *j.Spec.Completions
		}
		w := wl{kind: "Job", ns: j.Namespace, name: j.Name, ready: fmt.Sprintf("%d/%d", j.Status.Succeeded, comp), age: j.CreationTimestamp.Time, extra: images(j.Spec.Template.Spec)}
		w.status = "Running"
		if j.Status.Active == 0 && j.Status.Succeeded >= comp {
			w.status = "Complete"
		}
		for _, c := range j.Status.Conditions {
			if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
				w.status, w.bad = "Failed: "+c.Reason, true
			}
			if c.Type == batchv1.JobSuspended && c.Status == corev1.ConditionTrue {
				w.status = "Suspended"
			}
		}
		if len(j.OwnerReferences) > 0 && j.OwnerReferences[0].Kind == "CronJob" {
			w.extra = "from CronJob " + j.OwnerReferences[0].Name
		}
		items = append(items, w)
	}
	for i := range s.CronJobs {
		c := &s.CronJobs[i]
		if !a.inNamespace(c.Namespace) {
			continue
		}
		w := wl{kind: "CronJob", ns: c.Namespace, name: c.Name, ready: fmt.Sprintf("%d active", len(c.Status.Active)), age: c.CreationTimestamp.Time, extra: c.Spec.Schedule}
		last := "never run"
		if c.Status.LastScheduleTime != nil {
			last = "last " + age(c.Status.LastScheduleTime.Time) + " ago"
		}
		w.status = last
		if c.Spec.Suspend != nil && *c.Spec.Suspend {
			w.status = "Suspended"
		}
		if c.Status.LastScheduleTime != nil && (c.Status.LastSuccessfulTime == nil || c.Status.LastSuccessfulTime.Before(c.Status.LastScheduleTime)) && len(c.Status.Active) == 0 {
			w.status, w.bad = "last run did not succeed", true
		}
		items = append(items, w)
	}

	// standalone pods: no controller owner
	for i := range s.Pods {
		p := &s.Pods[i]
		if !a.inNamespace(p.Namespace) {
			continue
		}
		owner := ""
		if len(p.OwnerReferences) > 0 {
			o := p.OwnerReferences[0]
			if controllerKinds[o.Kind] {
				continue
			}
			owner = o.Kind + "/" + o.Name
		}
		if p.Status.Phase == corev1.PodSucceeded && a.problemOnly {
			continue
		}
		r, t := k8s.PodReady(p)
		st := k8s.PodStatus(p)
		w := wl{kind: "Pod", ns: p.Namespace, name: p.Name, ready: fmt.Sprintf("%d/%d", r, t), status: st, age: p.CreationTimestamp.Time, bad: !k8s.PodHealthy(p) && p.Status.Phase != corev1.PodSucceeded}
		if owner != "" {
			w.extra = "owner " + owner
		} else {
			w.extra = "no owner (bare pod)"
		}
		if p.Spec.NodeName != "" {
			w.extra += " on " + p.Spec.NodeName
		}
		items = append(items, w)
	}

	for _, w := range items {
		total++
		if w.bad {
			unhealthy++
		}
		if a.problemOnly && !w.bad {
			continue
		}
		st := w.status
		switch {
		case w.bad:
			st = styleCrit.Render(st)
		case st == "Available" || st == "Complete":
			st = styleOK.Render(st)
		case strings.HasPrefix(st, "Rolling") || st == "Running" || st == "Pending":
			st = styleWarn.Render(st)
		default:
			st = styleDim.Render(st)
		}
		rows = append(rows, []string{kindStyle(w.kind), w.ns, w.name, w.ready, st, age(w.age), w.extra})
		ids = append(ids, wlID(w.kind, w.ns, w.name))
	}

	mode := "controllers + standalone pods"
	if a.problemOnly {
		mode = "problems only (a toggles)"
	}
	hdr = append(hdr, styleTitle.Render("Inspect: workloads")+"  "+kv("items", fmt.Sprint(total))+"  "+kv("unhealthy", colorCount(unhealthy, "", styleCrit))+"  "+styleDim.Render(mode)+"  "+styleKey.Render("enter")+styleDim.Render(" inspect + references  ")+styleKey.Render("t")+styleDim.Render(" rollout restart  ")+styleKey.Render("L")+styleDim.Render(" tail logs  ")+styleKey.Render("→")+styleDim.Render(" pods / resources / object"))
	hdr = append(hdr, a.podsSummaryLine())
	h, lines := renderTable(a.width, []column{{title: "KIND"}, {title: "NAMESPACE", max: 24}, {title: "NAME", max: 48}, {title: "READY", right: true}, {title: "STATUS", max: 30}, {title: "AGE", right: true}, {title: "IMAGES / DETAILS"}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: styleOK.Render("nothing to show")}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

func kindStyle(k string) string {
	switch k {
	case "Deployment":
		return styleInfo.Render(k)
	case "DaemonSet":
		return styleTitle.Render(k)
	case "StatefulSet":
		return styleWarn.Render(k)
	case "Pod":
		return styleDim.Render(k)
	}
	return k
}

func wlID(kind, ns, name string) string { return kind + "|" + ns + "|" + name }

func parseWLID(id string) (kind, ns, name string, ok bool) {
	f := strings.SplitN(id, "|", 3)
	if len(f) != 3 {
		return "", "", "", false
	}
	return f[0], f[1], f[2], true
}

func images(spec corev1.PodSpec) string {
	var imgs []string
	for _, c := range spec.Containers {
		img := c.Image
		if i := strings.LastIndex(img, "/"); i >= 0 {
			img = img[i+1:]
		}
		imgs = append(imgs, img)
	}
	return strings.Join(imgs, ", ")
}

// podsSummaryLine renders the pod status bar shared by both views.
func (a *App) podsSummaryLine() string {
	s := a.snap
	var okPods, badPods, pendPods, donePods float64
	for i := range s.Pods {
		p := &s.Pods[i]
		if !a.inNamespace(p.Namespace) {
			continue
		}
		switch {
		case p.Status.Phase == corev1.PodSucceeded:
			donePods++
		case p.Status.Phase == corev1.PodPending:
			pendPods++
		case k8s.PodHealthy(p):
			okPods++
		default:
			badPods++
		}
	}
	psegs := []seg{{okPods, styleOK, "healthy"}, {badPods, styleCrit, "unhealthy"}, {pendPods, styleWarn, "pending"}, {donePods, styleDim, "completed"}}
	return kv("pods", stacked(40, psegs)) + "  " + legend(psegs) + "  " + styleDim.Render("unhealthy trend ") + sparkStyled(a.values("pods.unhealthy"), 16, 0, 1, 5)
}

// podsContent is the flat all-pods view (p toggles).
func (a *App) podsContent() content {
	s := a.snap
	hdr := []string{styleTitle.Render("All pods") + "  " + styleKey.Render("←") + styleDim.Render(" controllers  ") + styleKey.Render("enter") + styleDim.Render(" inspect + references  ") + styleKey.Render("L") + styleDim.Render(" tail logs"), a.podsSummaryLine()}
	var rows [][]string
	var ids []string
	total := 0
	for i := range s.Pods {
		p := &s.Pods[i]
		if !a.inNamespace(p.Namespace) {
			continue
		}
		total++
		if a.problemOnly && k8s.PodHealthy(p) {
			continue
		}
		st := k8s.PodStatus(p)
		stText := st
		switch {
		case st == "Running" || st == "Completed" || st == "Succeeded":
			stText = styleOK.Render(st)
		case st == "CrashLoopBackOff" || strings.Contains(st, "Err") || strings.Contains(st, "BackOff") || st == "Failed" || st == "Error":
			stText = styleCrit.Render(st)
		default:
			stText = styleWarn.Render(st)
		}
		r, t := k8s.PodReady(p)
		readyText := fmt.Sprintf("%d/%d", r, t)
		if r < t && p.Status.Phase == corev1.PodRunning {
			readyText = styleWarn.Render(readyText)
		}
		restarts, last := k8s.PodRestarts(p)
		rsText := fmt.Sprint(restarts)
		if restarts > 0 && !last.IsZero() {
			rsText += styleDim.Render(" (" + age(last) + " ago)")
			if restarts >= a.cfg.Thresholds.RestartWarn {
				rsText = styleWarn.Render(fmt.Sprint(restarts)) + styleDim.Render(" ("+age(last)+" ago)")
			}
		}
		owner := ""
		if len(p.OwnerReferences) > 0 {
			owner = p.OwnerReferences[0].Kind + "/" + p.OwnerReferences[0].Name
		}
		rows = append(rows, []string{p.Namespace, p.Name, readyText, stText, rsText, age(p.CreationTimestamp.Time), p.Spec.NodeName, owner})
		ids = append(ids, wlID("Pod", p.Namespace, p.Name))
	}
	hdr = append(hdr, styleDim.Render(fmt.Sprintf("%d pods, showing %d", total, len(rows))))
	h, lines := renderTable(a.width, []column{{title: "NAMESPACE", max: 28}, {title: "NAME", max: 60}, {title: "READY", right: true}, {title: "STATUS"}, {title: "RESTARTS"}, {title: "AGE", right: true}, {title: "NODE"}, {title: "OWNER", max: 40}}, rows)
	hdr = append(hdr, h)
	c := content{header: hdr, selectable: true, empty: styleOK.Render("no pods to show")}
	for i, l := range lines {
		c.rows = append(c.rows, row{id: ids[i], text: l})
	}
	return c
}

// workloadObject returns the typed snapshot object for a workload row.
func (a *App) workloadObject(id string) (runtime.Object, corev1.PodSpec, *metav1.LabelSelector, bool) {
	kind, ns, name, ok := parseWLID(id)
	if !ok {
		return nil, corev1.PodSpec{}, nil, false
	}
	s := a.snap
	switch kind {
	case "Deployment":
		for i := range s.Deployments {
			if d := &s.Deployments[i]; d.Namespace == ns && d.Name == name {
				d.APIVersion, d.Kind = "apps/v1", "Deployment"
				return d, d.Spec.Template.Spec, d.Spec.Selector, true
			}
		}
	case "DaemonSet":
		for i := range s.DaemonSets {
			if d := &s.DaemonSets[i]; d.Namespace == ns && d.Name == name {
				d.APIVersion, d.Kind = "apps/v1", "DaemonSet"
				return d, d.Spec.Template.Spec, d.Spec.Selector, true
			}
		}
	case "StatefulSet":
		for i := range s.StatefulSets {
			if d := &s.StatefulSets[i]; d.Namespace == ns && d.Name == name {
				d.APIVersion, d.Kind = "apps/v1", "StatefulSet"
				return d, d.Spec.Template.Spec, d.Spec.Selector, true
			}
		}
	case "Job":
		for i := range s.Jobs {
			if d := &s.Jobs[i]; d.Namespace == ns && d.Name == name {
				d.APIVersion, d.Kind = "batch/v1", "Job"
				return d, d.Spec.Template.Spec, d.Spec.Selector, true
			}
		}
	case "CronJob":
		for i := range s.CronJobs {
			if d := &s.CronJobs[i]; d.Namespace == ns && d.Name == name {
				d.APIVersion, d.Kind = "batch/v1", "CronJob"
				return d, d.Spec.JobTemplate.Spec.Template.Spec, nil, true
			}
		}
	case "Pod":
		for i := range s.Pods {
			if p := &s.Pods[i]; p.Namespace == ns && p.Name == name {
				p.APIVersion, p.Kind = "v1", "Pod"
				return p, p.Spec, nil, true
			}
		}
	}
	return nil, corev1.PodSpec{}, nil, false
}

// openWorkload pushes the selected workload into the inspector with its pods.
func (a *App) openWorkload(id string) {
	obj, _, selector, ok := a.workloadObject(id)
	if !ok {
		return
	}
	u, err := k8s.ToUnstructured(obj)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	var extra []string
	if u.GetKind() == "Pod" {
		_, extra = a.podDetail(u.GetNamespace() + "/" + u.GetName())
	}
	a.openInspectObject(u, extra)
	top := &a.inspect[len(a.inspect)-1]
	if selector != nil {
		seen := map[string]bool{}
		for _, r := range top.refs {
			seen[r.Key()] = true
		}
		for _, p := range podsMatching(a.snap, u.GetNamespace(), selector) {
			r := k8s.ObjRef{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: p.Name, Via: "pod " + k8s.PodStatus(p)}
			if !seen[r.Key()] {
				top.refs = append(top.refs, r)
			}
		}
	}
}

func podsMatching(s *k8s.Snapshot, ns string, sel *metav1.LabelSelector) []*corev1.Pod {
	ls, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return nil
	}
	var out []*corev1.Pod
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Namespace == ns && ls.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

// startRolloutRestart prepares a kubectl-style rollout restart (annotation
// patch on the pod template) for the selected Deployment/DaemonSet/StatefulSet.
func (a *App) startRolloutRestart() {
	if !a.cfg.Actions.Enabled {
		a.setStatus("mutating actions are disabled (--read-only / actions.enabled: false)")
		return
	}
	kind, ns, name, ok := parseWLID(a.selectedID())
	if !ok {
		return
	}
	if kind != "Deployment" && kind != "DaemonSet" && kind != "StatefulSet" {
		a.setStatus("rollout restart applies to Deployments, DaemonSets and StatefulSets")
		return
	}
	client := a.client
	a.pendingAct = &action{
		title: fmt.Sprintf("Rollout restart %s %s/%s", kind, ns, name),
		short: "rollout restart",
		desc: []string{
			"Patches spec.template.metadata.annotations[kubectl.kubernetes.io/restartedAt] with the current time,",
			"which is exactly what `kubectl rollout restart` does: pods are replaced according to the update strategy.",
		},
		run: func(ctx context.Context) (string, error) {
			patch := []byte(fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, time.Now().UTC().Format(time.RFC3339)))
			var err error
			switch kind {
			case "Deployment":
				_, err = client.CS.AppsV1().Deployments(ns).Patch(ctx, name, types.StrategicMergePatchType, patch, metav1.PatchOptions{FieldManager: "khealth"})
			case "DaemonSet":
				_, err = client.CS.AppsV1().DaemonSets(ns).Patch(ctx, name, types.StrategicMergePatchType, patch, metav1.PatchOptions{FieldManager: "khealth"})
			case "StatefulSet":
				_, err = client.CS.AppsV1().StatefulSets(ns).Patch(ctx, name, types.StrategicMergePatchType, patch, metav1.PatchOptions{FieldManager: "khealth"})
			}
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s/%s restarted (restartedAt annotation set)", strings.ToLower(kind), name), nil
		},
	}
	a.overlay = ovConfirm
}

var _ tea.Model = (*App)(nil)
