// Package checks evaluates the collected data against thresholds and
// produces a ranked list of findings.
package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/helmcheck"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/stig"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
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
	S3Reach    map[string]etcd.S3Check // S3 endpoint reachability per etcd node
	Logs       map[string]*logs.Summary
	Stig       []stig.Result
	APIServer  string // kubeconfig server URL, compared with the apiserver certificate SANs
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
	cv := distro.For(s.Distribution) // wording for hints: units, config files, commands
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
			add(SevCrit, "node", n.Name, "not Ready: "+strutil.FirstLine(msg), "check the "+cv.Server+" unit / kubelet and the Logs tab")
		}
		for _, ct := range []corev1.NodeConditionType{corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure} {
			if st, msg := k8s.NodeCondition(n, ct); st == corev1.ConditionTrue {
				add(SevWarn, "node", n.Name, string(ct)+": "+strutil.FirstLine(msg), "")
			}
		}
		if st, msg := k8s.NodeCondition(n, corev1.NodeNetworkUnavailable); st == corev1.ConditionTrue {
			add(SevCrit, "node", n.Name, "NetworkUnavailable: "+strutil.FirstLine(msg), "CNI not running on this node")
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
			add(sev, "node", iso.Node, fmt.Sprintf("%d user workload pod(s) on control-plane node: %s", len(iso.UserPods), strutil.TruncList(iso.UserPods, 3)), cv.NodeTaint+"; move workloads to worker nodes")
		}
		if !iso.Protected {
			add(SevWarn, "node", iso.Node, "control-plane node has no NoSchedule/NoExecute taint", cv.NodeTaint)
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

	// ---- cloud provider / CSI (API) ----
	evalCloud(in, add)
	evalUpgrade(in, add)
	evalNetwork(in, add)

	// ---- nodes (SSH) ----
	// Nodes presenting the same SSH host key are clones that were never
	// re-keyed: the key was copied with the image, so one node's key
	// authenticates every one of them, and known_hosts cannot tell them
	// apart. The same image usually carries one /etc/machine-id too.
	byKey := map[string][]string{}
	for name, ni := range in.Nodes {
		if ni != nil && ni.HostKey != "" {
			byKey[ni.HostKey] = append(byKey[ni.HostKey], name)
		}
	}
	for _, names := range byKey {
		if len(names) < 2 {
			continue
		}
		sort.Strings(names)
		for i, name := range names {
			others := append(append([]string{}, names[:i]...), names[i+1:]...)
			add(SevWarn, "node", name, "SSH host key is shared with "+strings.Join(others, ", ")+" (cloned image not re-keyed)", "rm /etc/ssh/ssh_host_*; ssh-keygen -A; restart sshd; ssh-keygen -R <addr> on clients; check /etc/machine-id is unique too")
		}
	}
	evalAddresses(in, add) // node-ip pinned to a gone address, server: pointing at one (address.go)
	for name, ni := range in.Nodes {
		if ni == nil {
			continue
		}
		nv := distro.For(ni.Dist)
		if ni.Dist == "" || ni.Dist == "unknown" {
			nv = cv
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
		evalPreflight(name, ni, in, add) // swap, fapolicyd, auditd, mounts, accounts, proxies, vSphere ISO, registries (preflight.go)
		active := map[string]bool{}
		for _, svc := range ni.Services {
			if svc.Active == "active" {
				active[svc.Name] = true
			}
		}
		for _, svc := range ni.Services {
			critical := svc.Name == "kubelet" || svc.Name == "containerd" || svc.Name == "rke2-server" || svc.Name == "rke2-agent" || svc.Name == "k3s" || svc.Name == "k3s-agent" || svc.Name == "etcd"
			// rke2/k3s install both unit files on every node and exactly one
			// runs: the server unit carries the agent (kubelet, containerd)
			// too, so an inactive agent unit next to an active server is
			// the normal state. Only the unit the node's role calls for is
			// required.
			switch svc.Name {
			case "rke2-agent", "k3s-agent":
				if active[strings.TrimSuffix(svc.Name, "-agent")] || ni.ControlPlane {
					continue
				}
			case "rke2-server", "k3s":
				if active[svc.Name+"-agent"] || !ni.ControlPlane {
					continue
				}
			case "etcd":
				// rke2, k3s and kubeadm run etcd as a static pod; a leftover
				// etcd.service unit on such a node is not the cluster's etcd
				if distro.IsRancher(ni.Dist) || ni.Dist == "kubeadm" || !ni.ControlPlane {
					continue
				}
			}
			if critical && svc.Active != "active" {
				add(SevCrit, "node", name, fmt.Sprintf("service %s is %s/%s", svc.Name, svc.Active, svc.Sub), "systemctl status "+svc.Name+"; see Logs tab")
			}
			if svc.Name == "rancher-system-agent" && svc.Active != "active" {
				add(SevWarn, "node", name, "rancher-system-agent is "+svc.Active, "Rancher cannot deliver plans to this node")
			}
		}
		for _, u := range ni.Units {
			if u.NRestarts > 0 && !u.Started.IsZero() && in.Now.Sub(u.Started) < 24*time.Hour {
				add(SevWarn, "node", name, fmt.Sprintf("%s restarted %d time(s) (last start %s ago)", u.Name, u.NRestarts, strutil.HumanDur(in.Now.Sub(u.Started))), "see Logs tab")
			}
		}
		if ni.NTPSynced != nil && !*ni.NTPSynced {
			add(SevWarn, "node", name, "system clock not NTP-synchronized", "enable chrony/systemd-timesyncd")
		}
		if d := ni.ClockOffset; d > thr.ClockSkewWarn || d < -thr.ClockSkewWarn {
			add(SevWarn, "node", name, fmt.Sprintf("clock offset %s vs this machine", d), "certificates and etcd need synchronized clocks")
		}
		for _, c := range ni.Certs {
			left := c.NotAfter.Sub(in.Now)
			switch {
			case left <= 0:
				add(SevCrit, "node", name, "certificate expired: "+c.Path, nv.CertRenew)
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
			add(SevWarn, "addons", name, "registries.yaml defines mirrors but containerd has no certs.d hosts configured", nv.RegistryReload+", or check the YAML")
		}
		// upstream: certs.d/hosts.toml is only read when config.toml names the directory
		if !distro.IsRancher(nv.Name) && len(ni.ContainerdHosts) > 0 && ni.ContainerdSetting("config_path") == "" {
			add(SevWarn, "addons", name, fmt.Sprintf("containerd certs.d has hosts.toml for %s but config.toml sets no config_path: the mirrors are not applied", strings.Join(ni.ContainerdHosts, ", ")), `[plugins."io.containerd.cri.v1.images".registry] config_path = "/etc/containerd/certs.d" (containerd 2.x; io.containerd.grpc.v1.cri on 1.x), then `+nv.RegistryReload)
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
		// rancher-system-agent: Rancher rewrites the node config through plans,
		// so a plan event explains config that differs from what was set locally
		ago := func(m logs.Match) string {
			if m.Time.IsZero() {
				return ""
			}
			return " (last " + in.Now.Sub(m.Time).Round(time.Minute).String() + " ago)"
		}
		if n := ls.ByName["rancher-plan-failed"]; n > 0 {
			add(SevCrit, "node", name, fmt.Sprintf("Rancher plan failed %d time(s)%s: node config may be half-applied", n, ago(ls.Last("rancher-plan-failed"))), "journalctl -u rancher-system-agent; compare config.yaml.d/50-rancher.yaml with the other nodes (RKE2 tab)")
		}
		if n := ls.ByName["rancher-plan-applied"]; n > 0 {
			add(SevInfo, "node", name, fmt.Sprintf("Rancher applied a plan %d time(s)%s: config.yaml.d/50-rancher.yaml and the rke2 unit were rewritten from the Rancher cluster spec", n, ago(ls.Last("rancher-plan-applied"))), "expected after an upgrade or cluster edit in Rancher; otherwise check the RKE2 tab for drift from what the node ran before")
		}
		if n := ls.ByName["rancher-probe-fail"]; n > 0 {
			add(SevWarn, "node", name, fmt.Sprintf("rancher-system-agent health probes failing (%d lines%s)", n, ago(ls.Last("rancher-probe-fail"))), "Rancher marks the machine unhealthy and holds plans; Logs tab for the probe name")
		}
	}

	// ---- API endpoint vs tls-san / serving certificate ----
	evalEndpoint(in, add)

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
			add(SevWarn, "workload", ref, "Pending for "+strutil.HumanDur(in.Now.Sub(p.CreationTimestamp.Time)), "kubectl describe pod (scheduling / PVC / image)")
		case p.Status.Phase == corev1.PodFailed && st != "Evicted" && p.Labels["job-name"] == "":
			add(SevWarn, "workload", ref, "Failed: "+st, "")
		case p.Status.Phase == corev1.PodUnknown:
			add(SevWarn, "workload", ref, "Unknown phase", "node may be unreachable")
		case st == "Terminating" && p.DeletionTimestamp != nil && in.Now.Sub(p.DeletionTimestamp.Time) > 10*time.Minute:
			add(SevWarn, "workload", ref, "Terminating for "+strutil.HumanDur(in.Now.Sub(p.DeletionTimestamp.Time)), "stuck finalizer or unreachable node")
		}
		if restarts >= thr.RestartWarn && !lastRestart.IsZero() && in.Now.Sub(lastRestart) < 24*time.Hour {
			add(SevWarn, "workload", ref, fmt.Sprintf("%d restarts (last %s ago)", restarts, strutil.HumanDur(in.Now.Sub(lastRestart))), "")
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

	// ---- dangling references ----
	for i := range s.Ingresses {
		ing := &s.Ingresses[i]
		for _, t := range ing.Spec.TLS {
			if t.SecretName == "" {
				continue
			}
			if exists, tracked := s.RefExists("Secret", ing.Namespace, t.SecretName); tracked && !exists {
				add(SevWarn, "workload", ing.Namespace+"/ingress/"+ing.Name, fmt.Sprintf("TLS secret %q does not exist (hosts %s): the ingress controller serves its default certificate", t.SecretName, strings.Join(t.Hosts, ",")), "create the secret (cert-manager Certificate?) or fix spec.tls[].secretName")
			}
		}
	}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		ref := p.Namespace + "/" + p.Name
		check := func(kind, name, via string) {
			if name == "" {
				return
			}
			if exists, tracked := s.RefExists(kind, p.Namespace, name); tracked && !exists {
				add(SevWarn, "workload", ref, fmt.Sprintf("references missing %s %q (%s)", kind, name, via), "the pod cannot start / will restart until it exists")
			}
		}
		for _, v := range p.Spec.Volumes {
			switch {
			case v.Secret != nil && (v.Secret.Optional == nil || !*v.Secret.Optional):
				check("Secret", v.Secret.SecretName, "volume "+v.Name)
			case v.ConfigMap != nil && (v.ConfigMap.Optional == nil || !*v.ConfigMap.Optional):
				check("ConfigMap", v.ConfigMap.Name, "volume "+v.Name)
			case v.PersistentVolumeClaim != nil:
				check("PersistentVolumeClaim", v.PersistentVolumeClaim.ClaimName, "volume "+v.Name)
			}
		}
		for _, c := range p.Spec.Containers {
			for _, e := range c.Env {
				if e.ValueFrom == nil {
					continue
				}
				if r := e.ValueFrom.SecretKeyRef; r != nil && (r.Optional == nil || !*r.Optional) {
					check("Secret", r.Name, "env "+e.Name)
				}
				if r := e.ValueFrom.ConfigMapKeyRef; r != nil && (r.Optional == nil || !*r.Optional) {
					check("ConfigMap", r.Name, "env "+e.Name)
				}
			}
		}
		if sa := p.Spec.ServiceAccountName; sa != "" && sa != "default" {
			check("ServiceAccount", sa, "serviceAccountName")
		}
	}

	// ---- storage ----
	for key, u := range MergePVCUsage(s, in.Nodes) {
		pct := u.UsedPct()
		switch {
		case pct >= float64(thr.DiskCritPct):
			add(SevCrit, "storage", "pvc/"+key, fmt.Sprintf("%.0f%% used (%s of %s) on %s", pct, strutil.HumanBytes(float64(u.Used)), strutil.HumanBytes(float64(u.Capacity)), u.Node), "expand the PVC (allowVolumeExpansion) or clean up data")
		case pct >= float64(thr.DiskWarnPct):
			add(SevWarn, "storage", "pvc/"+key, fmt.Sprintf("%.0f%% used (%s of %s)", pct, strutil.HumanBytes(float64(u.Used)), strutil.HumanBytes(float64(u.Capacity))), "")
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
			add(SevWarn, "helm", rel.Namespace+"/"+rel.Name, "release status "+rel.Status, helmReleaseFix(rel))
		}
		if l, ok := in.HelmLatest[rel.Namespace+"/"+rel.Name]; ok && l.Version != "" && helmcheck.CompareVersions(l.Version, rel.Version) > 0 {
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
				add(SevCrit, "etcd", who, "endpoint unhealthy: "+strutil.FirstLine(h.Error), "etcdctl endpoint health via "+x.EtcdctlVia)
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
			add(SevCrit, "etcd", name, "unhealthy: "+strutil.FirstLine(p.Health.Reason), "")
		}
		if m := p.Metrics; m != nil {
			if !m.HasLeader {
				add(SevCrit, "etcd", name, "member has no leader", "quorum lost or network partition")
			}
			if m.Quota > 0 && m.DBSize > 0 {
				pct := m.DBSize / m.Quota * 100
				switch {
				case pct >= 95:
					add(SevCrit, "etcd", name, fmt.Sprintf("db size %.0f%% of quota (%s / %s)", pct, strutil.HumanBytes(m.DBSize), strutil.HumanBytes(m.Quota)), "compact + defrag now (D on the etcd tab defrags member by member), raise quota-backend-bytes")
				case pct >= float64(thr.EtcdDBWarnPct):
					add(SevWarn, "etcd", name, fmt.Sprintf("db size %.0f%% of quota (%s / %s)", pct, strutil.HumanBytes(m.DBSize), strutil.HumanBytes(m.Quota)), "etcdctl defrag (D on the etcd tab)")
				}
			}
			if m.DBSize > 100e6 && m.DBSizeInUse > 0 {
				frag := (m.DBSize - m.DBSizeInUse) / m.DBSize * 100
				if frag >= float64(thr.EtcdFragWarnPct) {
					add(SevInfo, "etcd", name, fmt.Sprintf("db %.0f%% fragmented (%s allocated, %s in use)", frag, strutil.HumanBytes(m.DBSize), strutil.HumanBytes(m.DBSizeInUse)), "etcdctl defrag, one member at a time (D on the etcd tab)")
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
	for i := range s.RKE2Snapshots {
		r := &s.RKE2Snapshots[i]
		if r.Status == "failed" {
			failed++
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
		add(SevWarn, "etcd", "backups", "no etcd backup mechanism detected (no snapshots, timers, crons or CronJobs)", distro.For(s.Distribution).EtcdBackups+"; khealth looks for snapshot files, systemd timers, crons and CronJobs")
	default:
		latest := latestLocal
		src := "local on " + latestLocalNode
		if latestRec != nil && latestRec.Created.After(latest) {
			latest = latestRec.Created
			src = "cluster record " + latestRec.Name
		}
		if !latest.IsZero() && in.Now.Sub(latest) > in.Cfg.Etcd.MaxBackupAge {
			add(SevWarn, "etcd", "backups", fmt.Sprintf("latest etcd snapshot is %s old (%s)", strutil.HumanDur(in.Now.Sub(latest)), src), "check etcd-snapshot-schedule-cron / backup job")
		}
	}
	evalS3(in, add)
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

// helmReleaseFix is the remediation for a release whose latest revision is
// not deployed: back to the last revision that was, or a reinstall when
// nothing ever deployed.
func helmReleaseFix(rel k8s.HelmRelease) string {
	if g, ok := rel.LastGood(); ok {
		return fmt.Sprintf("B on the Helm tab rolls back to revision %d (last deployed); helm rollback %s %d -n %s", g.Revision, rel.Name, g.Revision, rel.Namespace)
	}
	return fmt.Sprintf("no revision ever deployed: helm history %s -n %s for the error, then helm uninstall and reinstall", rel.Name, rel.Namespace)
}
