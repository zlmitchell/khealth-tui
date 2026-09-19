// Package checks evaluates the collected data against thresholds and
// produces a ranked list of findings.
package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/helmcheck"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/logs"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/stig"
)

// Severity of a finding.
type Severity int

const (
	SevInfo Severity = iota
	SevWarn
	SevCrit
)

func (s Severity) String() string {
	switch s {
	case SevCrit:
		return "CRIT"
	case SevWarn:
		return "WARN"
	}
	return "INFO"
}

// Finding is one health observation.
type Finding struct {
	Severity Severity
	Area     string // cluster, node, workload, etcd, storage, ssh, security, images, helm, logs, addons
	Object   string
	Message  string
	Hint     string
	Steps    []string // ordered remediation steps (triage findings)
}

// Input bundles all collected data.
type Input struct {
	Snap       *k8s.Snapshot
	Nodes      map[string]*nodeinfo.Info
	Etcd       map[string]*etcd.Probe
	EtcdExec   *etcd.Probe // cluster-wide view via kubectl exec (optional)
	S3         *k8s.S3SecretInfo
	Logs       map[string]*logs.Summary
	Stig       []stig.Result
	HelmLatest map[string]helmcheck.Latest
	SSHEnabled bool
	SSHErr     string
	Cfg        config.Config
	Now        time.Time
}

// Evaluate produces findings sorted by severity.
func Evaluate(in Input) []Finding {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	var f []Finding
	add := func(sev Severity, area, obj, msg, hint string) {
		f = append(f, Finding{Severity: sev, Area: area, Object: obj, Message: msg, Hint: hint})
	}
	addF := func(x Finding) { f = append(f, x) }
	thr := in.Cfg.Thresholds
	s := in.Snap
	if s == nil {
		return nil
	}

	// ---- API / cluster ----
	for _, e := range s.Errors {
		add(SevWarn, "cluster", "api", "could not list "+e, "check RBAC for the kubeconfig user")
	}
	for _, c := range s.Readyz {
		if !c.OK {
			add(SevCrit, "cluster", "readyz", fmt.Sprintf("%s failed %s", c.Name, c.Detail), "kubectl get --raw /readyz?verbose")
		}
	}
	for _, c := range s.Livez {
		if !c.OK {
			add(SevCrit, "cluster", "livez", fmt.Sprintf("%s failed %s", c.Name, c.Detail), "kubectl get --raw /livez?verbose")
		}
	}
	if in.SSHErr != "" {
		add(SevWarn, "ssh", "config", "SSH disabled: "+in.SSHErr, "fix ssh.* settings or run with --no-ssh to silence")
	}
	if !s.MetricsAvailable && !in.SSHEnabled {
		add(SevInfo, "cluster", "metrics", "metrics-server not available and SSH disabled: no live CPU/memory usage", "install metrics-server or enable SSH")
	}

	// ---- nodes (API) ----
	versions := map[string]int{}
	for i := range s.Nodes {
		versions[s.Nodes[i].Status.NodeInfo.KubeletVersion]++
	}
	podsByNode := map[string][]corev1.Pod{}
	for i := range s.Pods {
		podsByNode[s.Pods[i].Spec.NodeName] = append(podsByNode[s.Pods[i].Spec.NodeName], s.Pods[i])
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if st, msg := k8s.NodeCondition(n, corev1.NodeReady); st != corev1.ConditionTrue {
			add(SevCrit, "node", n.Name, "not Ready: "+firstLine(msg), "check kubelet / rke2 service and the Logs tab")
		}
		for _, ct := range []corev1.NodeConditionType{corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure} {
			if st, msg := k8s.NodeCondition(n, ct); st == corev1.ConditionTrue {
				add(SevWarn, "node", n.Name, string(ct)+": "+firstLine(msg), "")
			}
		}
		if st, msg := k8s.NodeCondition(n, corev1.NodeNetworkUnavailable); st == corev1.ConditionTrue {
			add(SevCrit, "node", n.Name, "NetworkUnavailable: "+firstLine(msg), "CNI not running on this node")
		}
		if n.Spec.Unschedulable {
			add(SevInfo, "node", n.Name, "cordoned (unschedulable)", "kubectl uncordon when maintenance is done")
		}
		if len(versions) > 1 && versions[n.Status.NodeInfo.KubeletVersion] < len(s.Nodes)/2+1 {
			add(SevWarn, "node", n.Name, "kubelet version "+n.Status.NodeInfo.KubeletVersion+" differs from majority", "finish the upgrade")
		}
		if maxPods := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourcePods); maxPods > 0 {
			running := 0
			for _, p := range podsByNode[n.Name] {
				if p.Status.Phase == corev1.PodRunning || p.Status.Phase == corev1.PodPending {
					running++
				}
			}
			if float64(running) >= 0.9*float64(maxPods) {
				add(SevWarn, "node", n.Name, fmt.Sprintf("pod count %d/%d near allocatable limit", running, maxPods), "raise max-pods or add nodes")
			}
		}
		cpuReq, memReq := k8s.SumRequests(podsByNode[n.Name])
		if alloc := k8s.QuantityMilli(n.Status.Allocatable, corev1.ResourceCPU); alloc > 0 && float64(cpuReq) > 0.95*float64(alloc) {
			add(SevInfo, "node", n.Name, fmt.Sprintf("CPU requests %d%% of allocatable", cpuReq*100/alloc), "scheduling headroom is low")
		}
		if alloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourceMemory); alloc > 0 && float64(memReq) > 0.95*float64(alloc) {
			add(SevInfo, "node", n.Name, fmt.Sprintf("memory requests %d%% of allocatable", memReq*100/alloc), "scheduling headroom is low")
		}
		if m, ok := s.NodeMetrics[n.Name]; ok {
			if _, hasSSH := in.Nodes[n.Name]; !hasSSH || in.Nodes[n.Name].Err != nil {
				if alloc := k8s.QuantityMilli(n.Status.Allocatable, corev1.ResourceCPU); alloc > 0 && m.CPUMilli*100/alloc >= int64(thr.CPUWarnPct) {
					add(SevWarn, "node", n.Name, fmt.Sprintf("CPU usage %d%% (metrics-server)", m.CPUMilli*100/alloc), "")
				}
				if alloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourceMemory); alloc > 0 && m.MemBytes*100/alloc >= int64(thr.MemWarnPct) {
					add(SevWarn, "node", n.Name, fmt.Sprintf("memory usage %d%% (metrics-server)", m.MemBytes*100/alloc), "")
				}
			}
		}
	}

	// ---- control-plane isolation ----
	for _, iso := range s.ControlPlaneIsolation() {
		if len(iso.UserPods) > 0 {
			sev := SevWarn
			if iso.Protected {
				sev = SevInfo // scheduled deliberately with tolerations
			}
			add(sev, "node", iso.Node, fmt.Sprintf("%d user workload pod(s) on control-plane node: %s", len(iso.UserPods), truncList(iso.UserPods, 3)), "rke2: node-taint: [CriticalAddonsOnly=true:NoExecute] on servers; move workloads to agents")
		}
		if !iso.Protected {
			add(SevWarn, "node", iso.Node, "control-plane node has no NoSchedule/NoExecute taint", "rke2 config.yaml on servers: node-taint: [\"CriticalAddonsOnly=true:NoExecute\"]")
		}
		unset := []string{}
		for _, comp := range []string{"kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"} {
			if r, ok := iso.CPComponents[comp]; ok && !r.Set {
				unset = append(unset, comp)
			}
		}
		if iso.AllocCPU > 0 && len(unset) > 0 {
			pct := iso.AllCPUReq * 100 / iso.AllocCPU
			memPct := int64(0)
			if iso.AllocMem > 0 {
				memPct = iso.AllMemReq * 100 / iso.AllocMem
			}
			if pct >= 60 || memPct >= 60 {
				add(SevWarn, "node", iso.Node, fmt.Sprintf("control-plane pods %s have no resource requests while other pods already request %d%% CPU / %d%% memory: the control plane is not guaranteed capacity", strings.Join(unset, ","), pct, memPct), "rke2 config.yaml: control-plane-resource-requests: [kube-apiserver-cpu=500m,kube-apiserver-memory=1Gi,etcd-cpu=500m,etcd-memory=1Gi,...]")
			} else {
				add(SevInfo, "node", iso.Node, fmt.Sprintf("control-plane pods %s run without resource requests (best effort)", strings.Join(unset, ",")), "rke2: control-plane-resource-requests in config.yaml")
			}
		}
	}

	// ---- nodes (SSH) ----
	for name, ni := range in.Nodes {
		if ni == nil {
			continue
		}
		if ni.Err != nil {
			add(SevWarn, "ssh", name, "collection failed: "+ni.Err.Error(), "check ssh.user/key, sudo, host key, and node address")
			continue
		}
		for _, m := range ni.Mounts {
			switch {
			case m.UsePct >= thr.DiskCritPct:
				add(SevCrit, "node", name, fmt.Sprintf("%s %d%% used (%s)", m.Mountpoint, m.UsePct, m.Filesystem), "free space: crictl rmi --prune, rotate logs, etcd defrag")
			case m.UsePct >= thr.DiskWarnPct:
				add(SevWarn, "node", name, fmt.Sprintf("%s %d%% used (%s)", m.Mountpoint, m.UsePct, m.Filesystem), "")
			}
			if m.InodePct >= thr.InodeWarnPct {
				add(SevWarn, "node", name, fmt.Sprintf("%s inodes %d%% used", m.Mountpoint, m.InodePct), "")
			}
		}
		switch {
		case ni.MemPct >= float64(thr.MemCritPct):
			add(SevCrit, "node", name, fmt.Sprintf("memory %.0f%% used", ni.MemPct), "")
		case ni.MemPct >= float64(thr.MemWarnPct):
			add(SevWarn, "node", name, fmt.Sprintf("memory %.0f%% used", ni.MemPct), "")
		}
		if ni.CPUPct >= float64(thr.CPUWarnPct) {
			add(SevWarn, "node", name, fmt.Sprintf("CPU %.0f%% busy", ni.CPUPct), "")
		}
		if ni.CPUs > 0 && ni.Load1/float64(ni.CPUs) >= thr.LoadPerCPUWarn {
			add(SevWarn, "node", name, fmt.Sprintf("load %.1f on %d CPUs", ni.Load1, ni.CPUs), "")
		}
		if ni.SwapTotal > 0 && ni.SwapTotal-ni.SwapFree > 0 {
			add(SevInfo, "node", name, "swap in use", "kubelet expects swap off unless NodeSwap is configured")
		}
		for _, svc := range ni.Services {
			critical := svc.Name == "kubelet" || svc.Name == "containerd" || svc.Name == "rke2-server" || svc.Name == "rke2-agent" || svc.Name == "k3s" || svc.Name == "k3s-agent" || svc.Name == "etcd"
			if critical && svc.Active != "active" {
				add(SevCrit, "node", name, fmt.Sprintf("service %s is %s/%s", svc.Name, svc.Active, svc.Sub), "systemctl status "+svc.Name+"; see Logs tab")
			}
			if svc.Name == "rancher-system-agent" && svc.Active != "active" {
				add(SevWarn, "node", name, "rancher-system-agent is "+svc.Active, "Rancher cannot deliver plans to this node")
			}
		}
		for _, u := range ni.Units {
			if u.NRestarts > 0 && !u.Started.IsZero() && in.Now.Sub(u.Started) < 24*time.Hour {
				add(SevWarn, "node", name, fmt.Sprintf("%s restarted %d time(s) (last start %s ago)", u.Name, u.NRestarts, roundDur(in.Now.Sub(u.Started))), "see Logs tab")
			}
		}
		if ni.NTPSynced != nil && !*ni.NTPSynced {
			add(SevWarn, "node", name, "system clock not NTP-synchronised", "enable chrony/systemd-timesyncd")
		}
		if d := ni.ClockOffset; d > thr.ClockSkewWarn || d < -thr.ClockSkewWarn {
			add(SevWarn, "node", name, fmt.Sprintf("clock offset %s vs this machine", d), "certificates and etcd need synchronised clocks")
		}
		for _, c := range ni.Certs {
			left := c.NotAfter.Sub(in.Now)
			switch {
			case left <= 0:
				add(SevCrit, "node", name, "certificate expired: "+c.Path, "rke2: restart rotates client certs; kubeadm certs renew all")
			case left < thr.CertExpiryWarn:
				add(SevWarn, "node", name, fmt.Sprintf("certificate expires in %dd: %s", int(left.Hours()/24), c.Path), "")
			}
		}
		if ni.Hardening["reboot_required"] == "yes" {
			add(SevInfo, "node", name, "reboot required (pending kernel/security updates)", "drain and reboot in a maintenance window")
		}
		for _, it := range ni.HardeningItems() {
			if it.Mismatch {
				add(SevWarn, "security", name, fmt.Sprintf("%s: runtime %q but boot config %q", it.Name, it.Runtime, it.Boot), "a reboot will change the effective state; align config and runtime")
			}
		}
		// registries.yaml present but containerd has no mirror hosts -> not applied
		if len(ni.RegistryMirrors) > 0 && len(ni.ContainerdHosts) == 0 {
			add(SevWarn, "addons", name, "registries.yaml defines mirrors but containerd has no certs.d hosts configured", "restart rke2 to regenerate containerd config, or check the YAML")
		}
		if ni.Heavy {
			unused, bytes := ni.UnusedImages()
			if float64(bytes)/1e9 >= thr.UnusedImagesGB {
				add(SevInfo, "images", name, fmt.Sprintf("%d unused images (%.1f GB)", len(unused), float64(bytes)/1e9), "crictl rmi --prune (keep airgap images if you rely on them)")
			}
		}
	}

	// ---- logs ----
	for name, ls := range in.Logs {
		if ls == nil {
			continue
		}
		if n := ls.Counts[logs.ClassError]; n > 0 {
			top := ls.TopPatterns(logs.ClassError, 3)
			add(SevWarn, "logs", name, fmt.Sprintf("%d error log lines (%s)", n, strings.Join(top, ", ")), "Logs tab: Enter on the node for explanations")
		}
		if n := ls.Counts[logs.ClassWarn]; n > 20 {
			top := ls.TopPatterns(logs.ClassWarn, 3)
			add(SevInfo, "logs", name, fmt.Sprintf("%d warning log lines (%s)", n, strings.Join(top, ", ")), "")
		}
	}

	// ---- etcd ----
	evalEtcd(in, add, addF)

	// ---- workloads ----
	for i := range s.Pods {
		p := &s.Pods[i]
		ref := p.Namespace + "/" + p.Name
		st := k8s.PodStatus(p)
		restarts, lastRestart := k8s.PodRestarts(p)
		switch {
		case st == "CrashLoopBackOff":
			add(SevCrit, "workload", ref, "CrashLoopBackOff", "kubectl logs --previous")
		case st == "ImagePullBackOff" || st == "ErrImagePull" || st == "InvalidImageName":
			add(SevCrit, "workload", ref, st, "check image name/tag, registry credentials, registries.yaml")
		case st == "CreateContainerConfigError" || st == "CreateContainerError" || strings.HasPrefix(st, "Init:") && st != "Init:Running":
			add(SevWarn, "workload", ref, st, "kubectl describe pod")
		case st == "Evicted":
			add(SevInfo, "workload", ref, "Evicted", "kubectl delete pod to clean up")
		case p.Status.Phase == corev1.PodPending && in.Now.Sub(p.CreationTimestamp.Time) > thr.PendingPodAge:
			add(SevWarn, "workload", ref, "Pending for "+roundDur(in.Now.Sub(p.CreationTimestamp.Time)), "kubectl describe pod (scheduling / PVC / image)")
		case p.Status.Phase == corev1.PodFailed && st != "Evicted" && p.Labels["job-name"] == "":
			add(SevWarn, "workload", ref, "Failed: "+st, "")
		case p.Status.Phase == corev1.PodUnknown:
			add(SevWarn, "workload", ref, "Unknown phase", "node may be unreachable")
		case st == "Terminating" && p.DeletionTimestamp != nil && in.Now.Sub(p.DeletionTimestamp.Time) > 10*time.Minute:
			add(SevWarn, "workload", ref, "Terminating for "+roundDur(in.Now.Sub(p.DeletionTimestamp.Time)), "stuck finalizer or unreachable node")
		}
		if restarts >= thr.RestartWarn && !lastRestart.IsZero() && in.Now.Sub(lastRestart) < 24*time.Hour {
			add(SevWarn, "workload", ref, fmt.Sprintf("%d restarts (last %s ago)", restarts, roundDur(in.Now.Sub(lastRestart))), "")
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason == "OOMKilled" && in.Now.Sub(cs.LastTerminationState.Terminated.FinishedAt.Time) < 24*time.Hour {
				add(SevWarn, "workload", ref, "container "+cs.Name+" was OOMKilled", "raise memory limit")
			}
		}
		if p.Status.Phase == corev1.PodRunning && st == "Running" && p.DeletionTimestamp == nil {
			if r, t := k8s.PodReady(p); r < t && in.Now.Sub(p.CreationTimestamp.Time) > thr.PendingPodAge {
				add(SevWarn, "workload", ref, fmt.Sprintf("%d/%d containers ready", r, t), "readiness probe failing")
			}
		}
	}
	for i := range s.Deployments {
		d := &s.Deployments[i]
		if d.Spec.Replicas != nil && *d.Spec.Replicas > 0 && d.Status.UnavailableReplicas > 0 {
			add(SevWarn, "workload", d.Namespace+"/deploy/"+d.Name, fmt.Sprintf("%d/%d replicas available", d.Status.AvailableReplicas, *d.Spec.Replicas), "")
		}
	}
	for i := range s.DaemonSets {
		d := &s.DaemonSets[i]
		if d.Status.DesiredNumberScheduled > 0 && d.Status.NumberReady < d.Status.DesiredNumberScheduled {
			add(SevWarn, "workload", d.Namespace+"/ds/"+d.Name, fmt.Sprintf("%d/%d ready", d.Status.NumberReady, d.Status.DesiredNumberScheduled), "")
		}
	}
	for i := range s.StatefulSets {
		d := &s.StatefulSets[i]
		if d.Spec.Replicas != nil && *d.Spec.Replicas > 0 && d.Status.ReadyReplicas < *d.Spec.Replicas {
			add(SevWarn, "workload", d.Namespace+"/sts/"+d.Name, fmt.Sprintf("%d/%d ready", d.Status.ReadyReplicas, *d.Spec.Replicas), "")
		}
	}
	for i := range s.Jobs {
		j := &s.Jobs[i]
		for _, c := range j.Status.Conditions {
			if c.Type == "Failed" && c.Status == corev1.ConditionTrue && in.Now.Sub(c.LastTransitionTime.Time) < 24*time.Hour {
				add(SevWarn, "workload", j.Namespace+"/job/"+j.Name, "failed: "+c.Reason, "")
			}
		}
	}
	for i := range s.CronJobs {
		c := &s.CronJobs[i]
		if c.Spec.Suspend != nil && *c.Spec.Suspend {
			add(SevInfo, "workload", c.Namespace+"/cronjob/"+c.Name, "suspended", "")
		}
	}

	// ---- storage ----
	for key, u := range MergePVCUsage(s, in.Nodes) {
		pct := u.UsedPct()
		switch {
		case pct >= float64(thr.DiskCritPct):
			add(SevCrit, "storage", "pvc/"+key, fmt.Sprintf("%.0f%% used (%s of %s) on %s", pct, human(float64(u.Used)), human(float64(u.Capacity)), u.Node), "expand the PVC (allowVolumeExpansion) or clean up data")
		case pct >= float64(thr.DiskWarnPct):
			add(SevWarn, "storage", "pvc/"+key, fmt.Sprintf("%.0f%% used (%s of %s)", pct, human(float64(u.Used)), human(float64(u.Capacity))), "")
		}
		if u.Inodes > 0 && float64(u.InodesUsed)*100/float64(u.Inodes) >= float64(thr.InodeWarnPct) {
			add(SevWarn, "storage", "pvc/"+key, fmt.Sprintf("inodes %d%% used", u.InodesUsed*100/u.Inodes), "")
		}
	}
	for i := range s.PVCs {
		p := &s.PVCs[i]
		switch p.Status.Phase {
		case corev1.ClaimPending:
			if in.Now.Sub(p.CreationTimestamp.Time) > thr.PendingPodAge {
				add(SevWarn, "storage", p.Namespace+"/pvc/"+p.Name, "Pending", "no provisioner / storage class / capacity")
			}
		case corev1.ClaimLost:
			add(SevCrit, "storage", p.Namespace+"/pvc/"+p.Name, "Lost", "")
		}
	}
	for i := range s.PVs {
		p := &s.PVs[i]
		switch p.Status.Phase {
		case corev1.VolumeFailed:
			add(SevCrit, "storage", "pv/"+p.Name, "Failed: "+p.Status.Message, "")
		case corev1.VolumeReleased:
			add(SevInfo, "storage", "pv/"+p.Name, "Released (retained volume no longer bound)", "delete or reclaim")
		}
	}
	defaults := 0
	for i := range s.StorageClasses {
		if s.StorageClasses[i].Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
			defaults++
		}
	}
	if len(s.StorageClasses) > 0 && defaults == 0 {
		add(SevInfo, "storage", "storageclass", "no default StorageClass", "PVCs without storageClassName will stay Pending")
	} else if defaults > 1 {
		add(SevWarn, "storage", "storageclass", fmt.Sprintf("%d default StorageClasses", defaults), "keep exactly one default")
	}

	// ---- addons / rancher ----
	if r := s.Rancher; r != nil && r.Managed {
		if !r.ClusterAgentOK {
			add(SevCrit, "addons", "rancher", "cattle-cluster-agent not ready ("+r.ClusterAgent+") - cluster disconnected from Rancher "+r.Server, "check agent logs, Rancher URL/CA")
		}
		if r.FleetAgentOK != nil && !*r.FleetAgentOK {
			add(SevWarn, "addons", "rancher", "fleet-agent not ready", "GitOps/Fleet deployments will stall")
		}
	}
	for _, hc := range s.HelmCharts {
		if hc.Failed {
			add(SevWarn, "helm", hc.Namespace+"/"+hc.Name, "HelmChart install job failed", "kubectl -n kube-system logs job/"+hc.JobName)
		}
	}
	for _, rel := range s.HelmReleases {
		st := strings.ToLower(rel.Status)
		if st != "deployed" && st != "superseded" {
			add(SevWarn, "helm", rel.Namespace+"/"+rel.Name, "release status "+rel.Status, "helm history / rollback")
		}
		if l, ok := in.HelmLatest[rel.Chart]; ok && l.Version != "" && helmcheck.CompareVersions(l.Version, rel.Version) > 0 {
			add(SevInfo, "helm", rel.Namespace+"/"+rel.Name, fmt.Sprintf("chart %s %s -> %s available (%s)", rel.Chart, rel.Version, l.Version, l.Source), "")
		}
	}

	// ---- security ----
	if len(in.Stig) > 0 {
		c := stig.Counts(in.Stig)
		if c[stig.Fail] > 0 {
			var cat1 []string
			for _, r := range in.Stig {
				if r.Status == stig.Fail && r.Cat == "I" {
					cat1 = append(cat1, r.ID)
				}
			}
			sev := SevInfo
			msg := fmt.Sprintf("%d STIG/CIS checks failing, %d manual", c[stig.Fail], c[stig.Manual])
			if len(cat1) > 0 {
				sev = SevWarn
				msg += " (CAT I: " + strings.Join(cat1, ", ") + ")"
			}
			add(sev, "security", "stig", msg, "Security tab")
		}
	}

	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity
		}
		if f[i].Area != f[j].Area {
			return f[i].Area < f[j].Area
		}
		return f[i].Object < f[j].Object
	})
	return f
}

func evalEtcd(in Input, add func(Severity, string, string, string, string), addF func(Finding)) {
	s := in.Snap
	thr := in.Cfg.Thresholds
	etcdNodes := 0
	for i := range s.Nodes {
		if k8s.IsEtcdNode(s.Nodes, &s.Nodes[i]) {
			etcdNodes++
		}
	}
	if etcdNodes > 0 && etcdNodes%2 == 0 {
		add(SevWarn, "etcd", "cluster", fmt.Sprintf("%d etcd nodes (even number gives no extra fault tolerance)", etcdNodes), "use 1, 3 or 5")
	}

	var latestLocal time.Time
	latestLocalNode := ""
	backupMechanism := false
	rke2 := s.Distribution == "rke2" || s.Distribution == "k3s"
	snapshotsDisabled := false
	var s3Secret string
	s3Enabled := false
	leaders := map[string]bool{}
	memberCounts := map[int]bool{}

	// correlated per-member triage first; it owns the members it reports
	triaged := triageEtcd(in, addF)

	if x := in.EtcdExec; x != nil && x.Err == nil {
		for _, h := range x.EndpointHealth {
			if !h.Healthy {
				who := h.Endpoint
				if m := x.MemberByEndpoint(h.Endpoint); m != nil {
					who = m.Name
				}
				if triaged[who] {
					continue
				}
				add(SevCrit, "etcd", who, "endpoint unhealthy: "+firstLine(h.Error), "etcdctl endpoint health via "+x.EtcdctlVia)
			}
		}
		for _, a := range x.Alarms {
			add(SevCrit, "etcd", "cluster", "alarm "+a.Type+" on member "+a.MemberID, "etcdctl alarm disarm after compaction/defrag")
		}
		if len(x.Members) > 0 && etcdNodes > 0 && len(x.Members) != etcdNodes {
			add(SevWarn, "etcd", "cluster", fmt.Sprintf("%d etcd members but %d etcd nodes in the cluster", len(x.Members), etcdNodes), "stale member? etcdctl member list")
		}
		for _, m := range x.Members {
			if m.IsLearner {
				add(SevInfo, "etcd", "cluster", "member "+m.Name+" is a learner", "")
			}
		}
		vers := map[string]bool{}
		for _, st := range x.Statuses {
			if st.Leader != "" {
				leaders[st.Leader] = true
			}
			if st.Version != "" {
				vers[st.Version] = true
			}
			for _, e := range st.Errors {
				add(SevCrit, "etcd", "cluster", "endpoint "+st.Endpoint+": "+e, "")
			}
		}
		if len(vers) > 1 {
			add(SevWarn, "etcd", "cluster", "mixed etcd versions across members", "finish the upgrade")
		}
	}

	for name, p := range in.Etcd {
		if p == nil {
			continue
		}
		if p.Err != nil {
			add(SevWarn, "etcd", name, "probe failed: "+p.Err.Error(), "")
			continue
		}
		if p.Dist == "unknown" && p.Health == nil {
			add(SevInfo, "etcd", name, "no local etcd detected (external etcd?)", "set etcd.endpoint/ca_cert/client_cert/client_key in config")
			continue
		}
		if p.Health != nil && !p.Health.Healthy && !triaged[name] {
			add(SevCrit, "etcd", name, "unhealthy: "+firstLine(p.Health.Reason), "")
		}
		if m := p.Metrics; m != nil {
			if !m.HasLeader {
				add(SevCrit, "etcd", name, "member has no leader", "quorum lost or network partition")
			}
			if m.Quota > 0 && m.DBSize > 0 {
				pct := m.DBSize / m.Quota * 100
				switch {
				case pct >= 95:
					add(SevCrit, "etcd", name, fmt.Sprintf("db size %.0f%% of quota (%s / %s)", pct, human(m.DBSize), human(m.Quota)), "compact + defrag now, raise quota-backend-bytes")
				case pct >= float64(thr.EtcdDBWarnPct):
					add(SevWarn, "etcd", name, fmt.Sprintf("db size %.0f%% of quota (%s / %s)", pct, human(m.DBSize), human(m.Quota)), "etcdctl defrag")
				}
			}
			if m.DBSize > 100e6 && m.DBSizeInUse > 0 {
				frag := (m.DBSize - m.DBSizeInUse) / m.DBSize * 100
				if frag >= float64(thr.EtcdFragWarnPct) {
					add(SevInfo, "etcd", name, fmt.Sprintf("db %.0f%% fragmented (%s allocated, %s in use)", frag, human(m.DBSize), human(m.DBSizeInUse)), "etcdctl defrag (one member at a time)")
				}
			}
			if m.WalFsyncAvgMs > thr.EtcdFsyncWarnMs {
				add(SevWarn, "etcd", name, fmt.Sprintf("WAL fsync avg %.1fms (want <%.0fms)", m.WalFsyncAvgMs, thr.EtcdFsyncWarnMs), "etcd disk too slow; use dedicated SSD")
			}
			if m.BackendCommitAvgMs > 25 {
				add(SevWarn, "etcd", name, fmt.Sprintf("backend commit avg %.1fms (want <25ms)", m.BackendCommitAvgMs), "disk latency")
			}
			if m.ProposalsPending > 5 {
				add(SevWarn, "etcd", name, fmt.Sprintf("%.0f proposals pending", m.ProposalsPending), "")
			}
			if m.ProposalsFailed > 0 {
				add(SevInfo, "etcd", name, fmt.Sprintf("%.0f failed proposals since start", m.ProposalsFailed), "usually leader elections")
			}
			if m.LeaderChanges > 10 {
				add(SevWarn, "etcd", name, fmt.Sprintf("%.0f leader changes since start", m.LeaderChanges), "network/disk latency between control-plane nodes")
			}
			if m.PeerRTTAvgMs > 50 {
				add(SevWarn, "etcd", name, fmt.Sprintf("peer RTT avg %.0fms", m.PeerRTTAvgMs), "control-plane nodes too far apart")
			}
		}
		for _, a := range p.Alarms {
			add(SevCrit, "etcd", name, "alarm "+a.Type+" on member "+a.MemberID, "etcdctl alarm disarm after compaction/defrag")
		}
		if len(p.Members) > 0 && in.EtcdExec == nil {
			memberCounts[len(p.Members)] = true
			if len(p.Members) != etcdNodes && etcdNodes > 0 {
				add(SevWarn, "etcd", name, fmt.Sprintf("%d etcd members but %d etcd nodes in the cluster", len(p.Members), etcdNodes), "stale member? etcdctl member list")
			}
			for _, m := range p.Members {
				if m.IsLearner {
					add(SevInfo, "etcd", name, "member "+m.Name+" is a learner", "")
				}
			}
		}
		vers := map[string]bool{}
		for _, st := range p.Statuses {
			if st.Leader != "" {
				leaders[st.Leader] = true
			}
			if st.Version != "" {
				vers[st.Version] = true
			}
			for _, e := range st.Errors {
				add(SevCrit, "etcd", name, "endpoint "+st.Endpoint+": "+e, "")
			}
		}
		if len(vers) > 1 {
			add(SevWarn, "etcd", name, "mixed etcd versions across members", "finish the upgrade")
		}
		if fs := p.DataDirFS; fs != nil {
			switch {
			case fs.UsePct >= thr.DiskCritPct:
				add(SevCrit, "etcd", name, fmt.Sprintf("data dir filesystem %s %d%% used", fs.Mount, fs.UsePct), "etcd stops writing when the disk fills")
			case fs.UsePct >= thr.DiskWarnPct:
				add(SevWarn, "etcd", name, fmt.Sprintf("data dir filesystem %s %d%% used", fs.Mount, fs.UsePct), "")
			}
		}
		if v := p.RKE2Config["etcd-disable-snapshots"]; v == "true" {
			snapshotsDisabled = true
		}
		if v := p.RKE2Config["etcd-s3"]; v == "true" {
			s3Enabled = true
		}
		if v := p.RKE2Config["etcd-s3-config-secret"]; v != "" {
			s3Secret = v
		}
		if f, _, ok := p.LatestSnapshot(); ok {
			backupMechanism = true
			if f.ModTime.After(latestLocal) {
				latestLocal = f.ModTime
				latestLocalNode = name
			}
		}
		if len(p.BackupHints) > 0 {
			backupMechanism = true
		}
	}
	if len(leaders) > 1 {
		add(SevCrit, "etcd", "cluster", fmt.Sprintf("members disagree on the leader (%d leaders reported)", len(leaders)), "split brain / partition")
	}

	// cluster-level snapshot records (rke2)
	var latestRec *k8s.EtcdSnapshotRecord
	failed := 0
	s3Snaps := 0
	for i := range s.RKE2Snapshots {
		r := &s.RKE2Snapshots[i]
		if r.Status == "failed" {
			failed++
		}
		if r.S3 {
			s3Snaps++
		}
		if r.Status != "failed" && (latestRec == nil || r.Created.After(latestRec.Created)) {
			latestRec = r
		}
	}
	if len(s.RKE2Snapshots) > 0 {
		backupMechanism = true
	}
	for i := range s.CronJobs {
		if strings.Contains(strings.ToLower(s.CronJobs[i].Name), "etcd") {
			backupMechanism = true
		}
	}
	if failed > 0 {
		add(SevWarn, "etcd", "backups", fmt.Sprintf("%d failed snapshot record(s) in cluster", failed), "check ETCDSnapshotFile objects / rke2-etcd-snapshots configmap")
	}

	if len(in.Etcd) == 0 && !in.SSHEnabled && !rke2 {
		return
	}
	switch {
	case snapshotsDisabled:
		add(SevWarn, "etcd", "backups", "rke2 etcd snapshots are disabled (etcd-disable-snapshots: true)", "enable scheduled snapshots or ensure an external backup")
	case !backupMechanism && (len(in.Etcd) > 0 || rke2):
		add(SevWarn, "etcd", "backups", "no etcd backup mechanism detected (no snapshots, timers, crons or CronJobs)", "rke2: snapshots are on by default - check the snapshot dir; upstream: set etcd.backup_dirs")
	default:
		latest := latestLocal
		src := "local on " + latestLocalNode
		if latestRec != nil && latestRec.Created.After(latest) {
			latest = latestRec.Created
			src = "cluster record " + latestRec.Name
		}
		if !latest.IsZero() && in.Now.Sub(latest) > in.Cfg.Etcd.MaxBackupAge {
			add(SevWarn, "etcd", "backups", fmt.Sprintf("latest etcd snapshot is %s old (%s)", roundDur(in.Now.Sub(latest)), src), "check etcd-snapshot-schedule-cron / backup job")
		}
	}
	if s3Enabled {
		if s3Secret != "" && (in.S3 == nil || !in.S3.Found) {
			add(SevWarn, "etcd", "backups", "etcd-s3-config-secret "+s3Secret+" not found in kube-system", "create the secret or fix the name")
		}
		if len(s.RKE2Snapshots) > 0 && s3Snaps == 0 {
			add(SevWarn, "etcd", "backups", "S3 snapshots enabled but no snapshot record is marked as uploaded to S3", "check S3 credentials/endpoint in rke2-server logs")
		}
	}
}

// MergePVCUsage combines kubelet stats/summary usage with the SSH df fallback
// (PV mount paths mapped to claims through the PV's claimRef).
func MergePVCUsage(s *k8s.Snapshot, nodes map[string]*nodeinfo.Info) map[string]k8s.VolumeUsage {
	out := map[string]k8s.VolumeUsage{}
	for k, v := range s.PVCUsage {
		out[k] = v
	}
	if len(nodes) == 0 {
		return out
	}
	claimByPV := map[string]string{}
	claimByPath := map[string]string{}
	for i := range s.PVs {
		pv := &s.PVs[i]
		if pv.Spec.ClaimRef != nil {
			claim := pv.Spec.ClaimRef.Namespace + "/" + pv.Spec.ClaimRef.Name
			claimByPV[pv.Name] = claim
			if hp := pv.Spec.HostPath; hp != nil {
				claimByPath[hp.Path] = claim
			}
			if lp := pv.Spec.Local; lp != nil {
				claimByPath[lp.Path] = claim
			}
		}
	}
	requested := map[string]int64{}
	for i := range s.PVCs {
		pvc := &s.PVCs[i]
		if q, ok := pvc.Spec.Resources.Requests["storage"]; ok {
			requested[pvc.Namespace+"/"+pvc.Name] = q.Value()
		}
	}
	for i := range s.PVCs {
		if v := s.PVCs[i].Spec.VolumeName; v != "" {
			claimByPV[v] = s.PVCs[i].Namespace + "/" + s.PVCs[i].Name
		}
	}
	for node, ni := range nodes {
		if ni == nil || ni.Err != nil {
			continue
		}
		for _, m := range ni.PVMounts {
			key, ok := claimByPV[m.PV]
			if !ok {
				continue
			}
			if _, have := out[key]; have {
				continue
			}
			out[key] = k8s.VolumeUsage{Capacity: m.SizeKB * 1024, Used: m.UsedKB * 1024, Available: m.AvailKB * 1024, Node: node, Pod: "(ssh df)"}
		}
		// hostPath/local PVs: du of the directory; capacity = the claim's request
		// (not enforced by the provisioner, so it is a soft limit)
		for path, kb := range ni.PVDirs {
			key, ok := claimByPath[path]
			if !ok {
				continue
			}
			if _, have := out[key]; have {
				continue
			}
			u := k8s.VolumeUsage{Used: kb * 1024, Capacity: requested[key], Node: node, Pod: "(ssh du, request not enforced)"}
			if u.Capacity > u.Used {
				u.Available = u.Capacity - u.Used
			}
			out[key] = u
		}
	}
	return out
}

func truncList(l []string, n int) string {
	if len(l) <= n {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:n], ", ") + fmt.Sprintf(" (+%d more)", len(l)-n)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func roundDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func human(b float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f%s", b, units[i])
	}
	return fmt.Sprintf("%.1f%s", b, units[i])
}
