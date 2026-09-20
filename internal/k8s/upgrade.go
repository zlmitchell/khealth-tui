package k8s

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Upgrade readiness from the API. Two sources:
//
//   - system-upgrade-controller Plans (upgrade.cattle.io/v1): what Rancher
//     installs to upgrade imported rke2/k3s clusters, and what operators use
//     by hand. A Plan names a version (or a release channel it resolves),
//     selects nodes by label and runs one Job per node; a node is done when
//     it carries the label plan.upgrade.cattle.io/<plan> = the plan's latest
//     hash. The Jobs and their pods say why a node is stuck.
//   - on a Rancher management cluster, the clusters Rancher provisions itself
//     (v2prov): the provisioning Cluster and RKEControlPlane conditions carry
//     the planner's progress message ("waiting for etcd", "draining node x",
//     ...), the CAPI Machines the phase of every node, and each machine plan
//     secret whether rancher-system-agent on that node has applied the plan
//     Rancher wants (checksum in sync), how often it failed and which
//     health probes fail. Reading the plan secrets needs get/list on secrets
//     in fleet-default; when denied the machines are still shown.
//
// Fetch reads both in parallel with the rest of the snapshot; the absence of
// the CRDs is remembered for perf.denied_ttl like the other optional APIs.

// UpgradeInfo is the upgrade picture of the cluster.
type UpgradeInfo struct {
	Plans         []UpgradePlan // system-upgrade-controller plans
	PlansCRD      bool          // upgrade.cattle.io/v1 exists (no plans is then a fact, not an unknown)
	Provisioned   []ProvCluster // management cluster: v2prov downstream clusters
	SecretsDenied bool          // machine plan secrets could not be read (RBAC)
}

// UpgradePlan is one system-upgrade-controller Plan.
type UpgradePlan struct {
	Namespace, Name string
	Version         string // spec.version ("" when a channel is used)
	Channel         string // spec.channel
	Latest          string // status.latestVersion (resolved)
	Hash            string // status.latestHash: nodes carrying it as plan label are done
	Image           string // spec.upgrade.image
	Concurrency     int64
	Cordon, Drain   bool
	Selector        *metav1.LabelSelector
	Applying        []string      // status.applying: nodes with a running job
	Conditions      []CondSummary // status.conditions that are not True (LatestResolved, Validated, Complete)
	Complete        bool          // Complete condition true (SUC >= 0.13)
	Jobs            []UpgradeJob  // jobs of this plan still around (SUC keeps the last ones)
	Created         time.Time
}

// UpgradeJob is a job system-upgrade-controller ran for a plan on one node.
type UpgradeJob struct {
	Name, Node, Version string
	Active, Succeeded   int32
	Failed              int32
	FailedReason        string // Failed condition reason (BackoffLimitExceeded, DeadlineExceeded)
	FailedMessage       string
	PodState            string // waiting reason / terminated reason of the upgrade container when not running (ImagePullBackOff, Error, ...)
	PodMessage          string
	Started             time.Time
	Completed           time.Time
}

// CondSummary is one status condition worth reporting.
type CondSummary struct {
	Type, Status, Reason, Message string
}

// ProvCluster is a cluster Rancher provisions (clusters.provisioning.cattle.io
// with rkeConfig) as seen from the management cluster.
type ProvCluster struct {
	Namespace, Name string
	MgmtName        string // status.clusterName (c-m-xxxx)
	Version         string // spec.kubernetesVersion
	Ready           bool
	Conditions      []CondSummary // provisioning cluster conditions that are not True
	CPVersion       string        // rkecontrolplane spec.kubernetesVersion
	CPReady         bool
	CPConditions    []CondSummary // rkecontrolplane conditions that are not True (the planner's progress message lives here)
	Machines        []ProvMachine
}

// ProvMachine is a CAPI Machine of a provisioned cluster with its plan
// secret.
type ProvMachine struct {
	Name, Node, Phase string
	Version           string // status.nodeInfo.kubeletVersion
	Roles             []string
	Conditions        []CondSummary // conditions that are not True
	Plan              *MachinePlan  // nil when the plan secret was not readable / not found
	Created           time.Time
}

// MachinePlan is the rke.cattle.io/machine-plan secret of a machine: the plan
// Rancher wants applied and what rancher-system-agent reported back. The
// rules are the planner's SecretToNode: in sync when appliedPlan equals plan
// byte for byte; failed when failed-checksum is the sha256 of the current
// plan, failure-count is above zero and (when a failure-threshold is set)
// has reached it.
type MachinePlan struct {
	HasPlan   bool
	InSync    bool            // appliedPlan == plan
	Failed    bool            // the agent gave up on the current plan
	Failing   bool            // the current plan has failed attempts but the threshold is not reached (the agent retries)
	Failures  int             // failure-count
	Threshold int             // failure-threshold (0: unset, -1: never give up)
	Probes    map[string]bool // probe name -> healthy (probe-statuses)
}

var (
	sucPlanGVR      = schema.GroupVersionResource{Group: "upgrade.cattle.io", Version: "v1", Resource: "plans"}
	provClusterGVR  = schema.GroupVersionResource{Group: "provisioning.cattle.io", Version: "v1", Resource: "clusters"}
	rkeCPGVR        = schema.GroupVersionResource{Group: "rke.cattle.io", Version: "v1", Resource: "rkecontrolplanes"}
	capiMachineGVRs = []schema.GroupVersionResource{
		{Group: "cluster.x-k8s.io", Version: "v1beta1", Resource: "machines"},
		{Group: "cluster.x-k8s.io", Version: "v1beta2", Resource: "machines"},
	}
	machinePlanSecretType = "rke.cattle.io/machine-plan"
	sucPlanLabel          = "upgrade.cattle.io/plan"
	sucNodeLabel          = "upgrade.cattle.io/node"
	sucVersionLabel       = "upgrade.cattle.io/version"
)

// upgradeInfo collects the Plans and, on a management cluster, the
// provisioned clusters. jobs and pods come from the snapshot lists so the
// upgrade jobs are matched without extra calls.
func (c *Client) upgradeInfo(ctx context.Context) *UpgradeInfo {
	ui := &UpgradeInfo{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		l, err := c.dynList(ctx, "plans.upgrade.cattle.io", sucPlanGVR)
		if err != nil {
			return
		}
		plans := make([]UpgradePlan, 0, len(l.Items))
		for _, it := range l.Items {
			plans = append(plans, parsePlan(it))
		}
		sort.Slice(plans, func(i, j int) bool {
			return plans[i].Namespace+"/"+plans[i].Name < plans[j].Namespace+"/"+plans[j].Name
		})
		mu.Lock()
		ui.Plans, ui.PlansCRD = plans, true
		mu.Unlock()
	}()
	// provisioning.cattle.io only exists on a management cluster; elsewhere
	// the 404 is remembered like every other optional API
	wg.Add(1)
	go func() {
		defer wg.Done()
		pc, denied := c.provisionedClusters(ctx)
		mu.Lock()
		ui.Provisioned, ui.SecretsDenied = pc, denied
		mu.Unlock()
	}()
	wg.Wait()
	return ui
}

func parsePlan(it unstructured.Unstructured) UpgradePlan {
	o := it.Object
	p := UpgradePlan{Namespace: it.GetNamespace(), Name: it.GetName(), Created: it.GetCreationTimestamp().Time}
	p.Version, _, _ = unstructured.NestedString(o, "spec", "version")
	p.Channel, _, _ = unstructured.NestedString(o, "spec", "channel")
	p.Image, _, _ = unstructured.NestedString(o, "spec", "upgrade", "image")
	p.Concurrency, _, _ = unstructured.NestedInt64(o, "spec", "concurrency")
	p.Cordon, _, _ = unstructured.NestedBool(o, "spec", "cordon")
	if d, ok, _ := unstructured.NestedMap(o, "spec", "drain"); ok && d != nil {
		p.Drain = true
	}
	if sel, ok, _ := unstructured.NestedMap(o, "spec", "nodeSelector"); ok && sel != nil {
		var ls metav1.LabelSelector
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(sel, &ls); err == nil {
			p.Selector = &ls
		}
	}
	p.Latest, _, _ = unstructured.NestedString(o, "status", "latestVersion")
	p.Hash, _, _ = unstructured.NestedString(o, "status", "latestHash")
	p.Applying, _, _ = unstructured.NestedStringSlice(o, "status", "applying")
	for _, cnd := range statusConditions(o) {
		if cnd.Type == "Complete" && cnd.Status == "True" {
			p.Complete = true
		}
		if cnd.Status != "True" {
			p.Conditions = append(p.Conditions, cnd)
		}
	}
	return p
}

// statusConditions reads status.conditions of an unstructured object.
func statusConditions(o map[string]any) []CondSummary {
	raw, ok, _ := unstructured.NestedSlice(o, "status", "conditions")
	if !ok {
		return nil
	}
	var out []CondSummary
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		cnd := CondSummary{}
		cnd.Type, _, _ = unstructured.NestedString(m, "type")
		cnd.Status, _, _ = unstructured.NestedString(m, "status")
		cnd.Reason, _, _ = unstructured.NestedString(m, "reason")
		cnd.Message, _, _ = unstructured.NestedString(m, "message")
		if cnd.Type != "" {
			out = append(out, cnd)
		}
	}
	return out
}

// AttachUpgradeJobs matches the snapshot's Jobs and Pods to the plans (called
// by Fetch once every list is in).
func (s *Snapshot) AttachUpgradeJobs() {
	if s.Upgrade == nil || len(s.Upgrade.Plans) == 0 {
		return
	}
	podsByJob := map[string][]*corev1.Pod{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if jn := p.Labels["job-name"]; jn != "" && p.Labels[sucPlanLabel] != "" {
			podsByJob[p.Namespace+"/"+jn] = append(podsByJob[p.Namespace+"/"+jn], p)
		}
	}
	byPlan := map[string][]UpgradeJob{}
	for i := range s.Jobs {
		j := &s.Jobs[i]
		plan := j.Labels[sucPlanLabel]
		if plan == "" {
			continue
		}
		uj := UpgradeJob{Name: j.Name, Node: j.Labels[sucNodeLabel], Version: j.Labels[sucVersionLabel], Active: j.Status.Active, Succeeded: j.Status.Succeeded, Failed: j.Status.Failed}
		if j.Status.StartTime != nil {
			uj.Started = j.Status.StartTime.Time
		}
		if j.Status.CompletionTime != nil {
			uj.Completed = j.Status.CompletionTime.Time
		}
		for _, cnd := range j.Status.Conditions {
			if cnd.Type == batchv1.JobFailed && cnd.Status == corev1.ConditionTrue {
				uj.FailedReason, uj.FailedMessage = cnd.Reason, cnd.Message
			}
		}
		uj.PodState, uj.PodMessage = upgradePodState(podsByJob[j.Namespace+"/"+j.Name])
		byPlan[j.Namespace+"/"+plan] = append(byPlan[j.Namespace+"/"+plan], uj)
	}
	for i := range s.Upgrade.Plans {
		p := &s.Upgrade.Plans[i]
		p.Jobs = byPlan[p.Namespace+"/"+p.Name]
		sort.Slice(p.Jobs, func(a, b int) bool { return p.Jobs[a].Started.After(p.Jobs[b].Started) })
	}
}

// upgradePodState names why the newest pod of an upgrade job is not running:
// the waiting reason of a container that never started (ImagePullBackOff:
// the upgrade image is not reachable from the node) or the terminated
// reason with the exit code.
func upgradePodState(pods []*corev1.Pod) (string, string) {
	var newest *corev1.Pod
	for _, p := range pods {
		if newest == nil || p.CreationTimestamp.After(newest.CreationTimestamp.Time) {
			newest = p
		}
	}
	if newest == nil {
		return "", ""
	}
	if newest.Status.Phase == corev1.PodSucceeded {
		return "", ""
	}
	all := append(append([]corev1.ContainerStatus{}, newest.Status.InitContainerStatuses...), newest.Status.ContainerStatuses...)
	for _, cs := range all {
		if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "PodInitializing" && w.Reason != "ContainerCreating" {
			return w.Reason, w.Message
		}
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 {
			msg := t.Message
			if msg == "" {
				msg = "exit " + strconv.Itoa(int(t.ExitCode))
			}
			return t.Reason, msg
		}
	}
	if newest.Status.Phase == corev1.PodPending && newest.Status.Reason != "" {
		return newest.Status.Reason, newest.Status.Message
	}
	for _, cnd := range newest.Status.Conditions {
		if cnd.Type == corev1.PodScheduled && cnd.Status == corev1.ConditionFalse {
			return cnd.Reason, cnd.Message
		}
	}
	return "", ""
}

// PlanNodes splits the nodes a plan selects into done (label = latest hash)
// and pending.
func (s *Snapshot) PlanNodes(p UpgradePlan) (done, pending []string) {
	sel := labels.Everything()
	if p.Selector != nil {
		if ls, err := metav1.LabelSelectorAsSelector(p.Selector); err == nil {
			sel = ls
		}
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !sel.Matches(labels.Set(n.Labels)) {
			continue
		}
		if p.Hash != "" && n.Labels["plan.upgrade.cattle.io/"+p.Name] == p.Hash {
			done = append(done, n.Name)
		} else {
			pending = append(pending, n.Name)
		}
	}
	sort.Strings(done)
	sort.Strings(pending)
	return
}

// Target is the version the plan is converging on: spec.version when
// pinned (the controller copies it to latestVersion with "+" turned into
// "-"), otherwise what the channel resolved to.
func (p UpgradePlan) Target() string {
	if p.Version != "" {
		return p.Version
	}
	return p.Latest
}

// provisionedClusters reads the v2prov clusters of a management cluster.
func (c *Client) provisionedClusters(ctx context.Context) ([]ProvCluster, bool) {
	cl, err := c.dynList(ctx, "clusters.provisioning.cattle.io", provClusterGVR)
	if err != nil {
		return nil, false
	}
	var out []ProvCluster
	for _, it := range cl.Items {
		o := it.Object
		if _, ok, _ := unstructured.NestedMap(o, "spec", "rkeConfig"); !ok {
			continue // imported cluster: Rancher does not run its nodes
		}
		pc := ProvCluster{Namespace: it.GetNamespace(), Name: it.GetName()}
		pc.MgmtName, _, _ = unstructured.NestedString(o, "status", "clusterName")
		pc.Version, _, _ = unstructured.NestedString(o, "spec", "kubernetesVersion")
		pc.Ready, _, _ = unstructured.NestedBool(o, "status", "ready")
		for _, cnd := range statusConditions(o) {
			if cnd.Status != "True" {
				pc.Conditions = append(pc.Conditions, cnd)
			}
		}
		out = append(out, pc)
	}
	if len(out) == 0 {
		return nil, false
	}
	byKey := map[string]*ProvCluster{}
	for i := range out {
		byKey[out[i].Namespace+"/"+out[i].Name] = &out[i]
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var machines *unstructured.UnstructuredList
	var plans map[string]*MachinePlan // machine name -> plan
	denied := false
	wg.Add(3)
	go func() {
		defer wg.Done()
		l, err := c.dynList(ctx, "rkecontrolplanes.rke.cattle.io", rkeCPGVR)
		if err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, it := range l.Items {
			pc := byKey[it.GetNamespace()+"/"+it.GetName()]
			if pc == nil {
				continue
			}
			o := it.Object
			pc.CPVersion, _, _ = unstructured.NestedString(o, "spec", "kubernetesVersion")
			pc.CPReady, _, _ = unstructured.NestedBool(o, "status", "ready")
			for _, cnd := range statusConditions(o) {
				if cnd.Status != "True" {
					pc.CPConditions = append(pc.CPConditions, cnd)
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		for _, gvr := range capiMachineGVRs {
			l, err := c.dynList(ctx, "machines."+gvr.Group+"/"+gvr.Version, gvr)
			if err == nil {
				mu.Lock()
				machines = l
				mu.Unlock()
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		if err, ok := c.Denied("machine-plan-secrets"); ok {
			mu.Lock()
			denied = apierrors.IsForbidden(err)
			mu.Unlock()
			return
		}
		l, err := c.CS.CoreV1().Secrets("").List(ctx, metav1.ListOptions{FieldSelector: "type=" + machinePlanSecretType})
		if err != nil {
			c.NoteDenied("machine-plan-secrets", err, false)
			mu.Lock()
			denied = apierrors.IsForbidden(err)
			mu.Unlock()
			return
		}
		m := map[string]*MachinePlan{}
		for i := range l.Items {
			sec := &l.Items[i]
			name := sec.Labels["rke.cattle.io/machine-name"]
			if name == "" {
				name = strings.TrimSuffix(sec.Name, "-machine-plan")
			}
			m[sec.Namespace+"/"+name] = parseMachinePlan(sec)
		}
		mu.Lock()
		plans = m
		mu.Unlock()
	}()
	wg.Wait()

	if machines != nil {
		for _, it := range machines.Items {
			o := it.Object
			clusterName, _, _ := unstructured.NestedString(o, "spec", "clusterName")
			pc := byKey[it.GetNamespace()+"/"+clusterName]
			if pc == nil {
				continue
			}
			m := ProvMachine{Name: it.GetName(), Created: it.GetCreationTimestamp().Time}
			m.Node, _, _ = unstructured.NestedString(o, "status", "nodeRef", "name")
			m.Phase, _, _ = unstructured.NestedString(o, "status", "phase")
			m.Version, _, _ = unstructured.NestedString(o, "status", "nodeInfo", "kubeletVersion")
			for _, role := range []string{"control-plane", "etcd", "worker"} {
				if it.GetLabels()["rke.cattle.io/"+role+"-role"] == "true" {
					m.Roles = append(m.Roles, role)
				}
			}
			for _, cnd := range statusConditions(o) {
				if cnd.Status != "True" {
					m.Conditions = append(m.Conditions, cnd)
				}
			}
			m.Plan = plans[it.GetNamespace()+"/"+it.GetName()]
			pc.Machines = append(pc.Machines, m)
		}
		for i := range out {
			sort.Slice(out[i].Machines, func(a, b int) bool { return out[i].Machines[a].Name < out[i].Machines[b].Name })
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace+"/"+out[i].Name < out[j].Namespace+"/"+out[j].Name })
	return out, denied
}

// parseMachinePlan reads what the planner and rancher-system-agent exchange
// through the machine plan secret: the plan bytes, the plan the agent
// applied, the checksum it failed on, the failure counters and the probe
// statuses.
func parseMachinePlan(sec *corev1.Secret) *MachinePlan {
	mp := &MachinePlan{Probes: map[string]bool{}}
	plan := sec.Data["plan"]
	mp.HasPlan = len(plan) > 0
	mp.InSync = mp.HasPlan && bytes.Equal(plan, sec.Data["appliedPlan"])
	mp.Threshold, _ = strconv.Atoi(strings.TrimSpace(string(sec.Data["failure-threshold"])))
	if fc := strings.TrimSpace(string(sec.Data["failure-count"])); fc != "" && mp.HasPlan && string(sec.Data["failed-checksum"]) == sha256Hex(plan) {
		mp.Failures, _ = strconv.Atoi(fc)
		if mp.Failures > 0 {
			mp.Failed = true
			if len(sec.Data["failure-threshold"]) > 0 && (mp.Failures < mp.Threshold || mp.Threshold == -1) {
				mp.Failed, mp.Failing = false, true
			}
		}
	}
	if ps := sec.Data["probe-statuses"]; len(ps) > 0 {
		var probes map[string]struct {
			Healthy bool `json:"healthy"`
		}
		if json.Unmarshal(ps, &probes) == nil {
			for name, p := range probes {
				mp.Probes[name] = p.Healthy
			}
		}
	}
	return mp
}

// UnhealthyProbes lists the failing probe names, sorted.
func (m *MachinePlan) UnhealthyProbes() []string {
	var out []string
	for name, ok := range m.Probes {
		if !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// sha256Hex is the planner's PlanHash: the hex sha256 of the plan bytes.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Node finds a node of the snapshot by name.
func (s *Snapshot) Node(name string) *corev1.Node {
	for i := range s.Nodes {
		if s.Nodes[i].Name == name {
			return &s.Nodes[i]
		}
	}
	return nil
}
