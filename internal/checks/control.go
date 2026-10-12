package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// evalControl covers what stops a cluster while nodes and pods look fine:
// admission webhooks failing closed with no backend, aggregated APIs that
// do not answer, objects stuck in deletion, disruption budgets that block
// every drain, certificate requests nobody approves, controllers that
// cannot create their pods (and why), system Services with no endpoint,
// and add-on replicas that all sit on one node.
func evalControl(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	thr := in.Cfg.Thresholds
	now := in.Now
	system := func(ns string) bool { return ns != "default" && k8s.IsSystemNamespace(ns) }

	evalAPIMetrics(in, add)
	evalIngressNetpol(in, add)
	evalCertManager(in, add)

	// ---- admission webhooks ----
	if s.ServiceReady != nil {
		for _, w := range s.Webhooks {
			if w.ServiceName == "" {
				continue // URL webhook: nothing in the cluster to count
			}
			svc := w.ServiceNS + "/" + w.ServiceName
			ready, hasSlices := s.ServiceReady[svc]
			if hasSlices && ready > 0 {
				continue
			}
			kind := "validating"
			if w.Mutating {
				kind = "mutating"
			}
			obj := "webhook/" + w.Config
			scope := strutil.TruncList(w.Resources, 4)
			unblock := fmt.Sprintf("kubectl patch %swebhookconfiguration %s --type=json -p '[{\"op\":\"replace\",\"path\":\"/webhooks/<i>/failurePolicy\",\"value\":\"Ignore\"}]' (or delete the configuration; its operator recreates it)", kind, w.Config)
			fix := "kubectl -n " + w.ServiceNS + " get endpointslices -l kubernetes.io/service-name=" + w.ServiceName + "; get the backing pods running"
			if strings.HasPrefix(w.Config, "rancher.cattle.io") {
				fix += "; Rancher webhook: kubectl -n cattle-system delete secret cattle-webhook-tls; kubectl -n cattle-system rollout restart deploy/rancher-webhook"
			}
			if !w.FailClosed {
				add(SevInfo, "cluster", obj, fmt.Sprintf("%s webhook %s has no ready endpoint behind %s (failurePolicy Ignore): matching requests (%s) wait up to %ds each, then pass unchecked", kind, w.Name, svc, scope, w.TimeoutSeconds), fix)
				continue
			}
			sev := SevWarn
			if broadWebhook(w) {
				sev = SevCrit
			}
			add(sev, "cluster", obj, fmt.Sprintf("%s webhook %s fails closed and %s has no ready endpoint: every create/update of %s is refused (\"failed calling webhook\")", kind, w.Name, svc, scope), fix+"; to unblock now: "+unblock)
		}
	}
	for _, w := range s.Webhooks {
		if w.CAExpires.IsZero() {
			continue
		}
		left := w.CAExpires.Sub(now)
		switch {
		case left <= 0 && w.FailClosed:
			add(SevCrit, "cluster", "webhook/"+w.Config, fmt.Sprintf("the caBundle of webhook %s expired %s ago: the apiserver cannot verify it, so every matching request fails (failurePolicy Fail)", w.Name, strutil.HumanDur(-left)), "renew the webhook's CA/serving certificate (cert-manager CA injector, or the operator that owns "+w.Config+")")
		case left <= 0:
			add(SevWarn, "cluster", "webhook/"+w.Config, fmt.Sprintf("the caBundle of webhook %s expired %s ago: it is skipped on every call (failurePolicy Ignore)", w.Name, strutil.HumanDur(-left)), "renew the webhook's CA certificate")
		case left < 7*24*time.Hour:
			add(SevWarn, "cluster", "webhook/"+w.Config, fmt.Sprintf("the caBundle of webhook %s expires in %s", w.Name, strutil.HumanDur(left)), "renew the webhook's CA certificate before it expires")
		}
	}

	// ---- aggregated APIs ----
	brokenAPI := map[string]bool{}
	for _, a := range s.APIServices {
		if a.Local || a.Available {
			continue
		}
		brokenAPI[a.Name] = true
		add(SevWarn, "cluster", "apiservice/"+a.Name, fmt.Sprintf("aggregated API %s is unavailable (%s: %s): discovery fails for it, which stalls namespace deletion and the garbage collector and makes kubectl print errors", a.Name, a.Reason, strutil.TruncStr(strutil.FirstLine(a.Message), 120)), "fix the backing service "+a.Service+" (its pods / endpoints); if the add-on was uninstalled: kubectl delete apiservice "+a.Name)
	}

	// ---- objects stuck in deletion ----
	for i := range s.Namespaces {
		ns := &s.Namespaces[i]
		if ns.DeletionTimestamp == nil || now.Sub(ns.DeletionTimestamp.Time) < thr.StuckDeletion {
			continue
		}
		var why []string
		discovery := false
		for _, c := range ns.Status.Conditions {
			if c.Status != corev1.ConditionTrue {
				continue
			}
			switch c.Type {
			case corev1.NamespaceDeletionDiscoveryFailure:
				discovery = true
				why = append(why, strutil.FirstLine(c.Message))
			case corev1.NamespaceContentRemaining, corev1.NamespaceFinalizersRemaining, corev1.NamespaceDeletionContentFailure:
				why = append(why, strutil.FirstLine(c.Message))
			}
		}
		sev, hint := SevWarn, "kubectl get ns "+ns.Name+" -o yaml (status.conditions name what is left); remove the finalizers of the remaining objects once their controller is gone: kubectl patch <res> <name> -n "+ns.Name+" --type=merge -p '{\"metadata\":{\"finalizers\":null}}' (a CSI finalizer guards a backend volume)"
		if discovery && len(brokenAPI) > 0 {
			hint = "an aggregated API is unavailable (see its finding): fix or delete that APIService and the deletion continues"
		}
		add(sev, "cluster", "namespace/"+ns.Name, fmt.Sprintf("namespace %s has been Terminating for %s: %s", ns.Name, strutil.HumanDur(now.Sub(ns.DeletionTimestamp.Time)), strutil.FirstNonEmpty(strutil.TruncList(why, 2), "no condition says why")), hint)
	}
	claimPods := map[string][]string{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				k := p.Namespace + "/" + v.PersistentVolumeClaim.ClaimName
				claimPods[k] = append(claimPods[k], p.Name)
			}
		}
	}
	for i := range s.PVCs {
		c := &s.PVCs[i]
		if c.DeletionTimestamp == nil || now.Sub(c.DeletionTimestamp.Time) < thr.StuckDeletion {
			continue
		}
		key := c.Namespace + "/" + c.Name
		msg := fmt.Sprintf("PVC %s has been Terminating for %s (finalizers %s)", key, strutil.HumanDur(now.Sub(c.DeletionTimestamp.Time)), strings.Join(c.Finalizers, ","))
		hint := "kubectl describe pvc -n " + c.Namespace + " " + c.Name
		if pods := claimPods[key]; len(pods) > 0 {
			msg += ": still mounted by " + strutil.TruncList(pods, 3) + " (kubernetes.io/pvc-protection waits for them)"
			hint = "delete or scale down the pods using it; the claim goes once nothing mounts it"
		}
		add(SevWarn, "storage", "pvc/"+key, msg, hint)
	}
	for i := range s.PVs {
		v := &s.PVs[i]
		if v.DeletionTimestamp == nil || now.Sub(v.DeletionTimestamp.Time) < thr.StuckDeletion {
			continue
		}
		add(SevWarn, "storage", "pv/"+v.Name, fmt.Sprintf("PV %s has been Terminating for %s (finalizers %s)", v.Name, strutil.HumanDur(now.Sub(v.DeletionTimestamp.Time)), strings.Join(v.Finalizers, ",")), "kubernetes.io/pv-protection waits for its claim; an external-attacher/provisioner finalizer waits for the CSI driver - check it runs before removing the finalizer (that would leak the backend volume)")
	}

	// ---- disruption budgets that block every drain ----
	for i := range s.PDBs {
		p := &s.PDBs[i]
		st := p.Status
		if st.ExpectedPods == 0 || st.DisruptionsAllowed > 0 || st.CurrentHealthy < st.DesiredHealthy {
			continue // nothing to protect, drains possible, or simply unhealthy now
		}
		// an operator's own budget, which it lifts once the drain is safe:
		// owned objects (Rook) and Longhorn's per-node instance-manager
		// budgets (they hold a drain until the node's replicas are elsewhere)
		if len(p.OwnerReferences) > 0 || (p.Spec.Selector != nil && p.Spec.Selector.MatchLabels["longhorn.io/managed-by"] != "") {
			continue
		}
		add(SevWarn, "workload", p.Namespace+"/pdb/"+p.Name, fmt.Sprintf("PodDisruptionBudget allows no disruption even with all %d pod(s) healthy (desired healthy %d): kubectl drain, node upgrades and Rancher/SUC drains hang on its pods", st.ExpectedPods, st.DesiredHealthy), "scale the workload above minAvailable, or kubectl patch pdb "+p.Name+" -n "+p.Namespace+" --type=merge -p '{\"spec\":{\"maxUnavailable\":1}}'")
	}

	// ---- certificate requests nobody approves ----
	pending := map[string][]string{}
	for _, r := range s.CSRs {
		if r.Pending && now.Sub(r.Created) > thr.StuckDeletion {
			pending[r.Signer] = append(pending[r.Signer], r.Name)
		}
	}
	for _, signer := range strutil.SortedKeys(pending) {
		names := pending[signer]
		what := "nobody approves them"
		switch signer {
		case "kubernetes.io/kubelet-serving":
			what = "kubelet serving certificates are not issued: kubectl logs/exec and metrics-server fail with x509 errors against those nodes"
		case "kubernetes.io/kube-apiserver-client-kubelet":
			what = "a node cannot join or rotate its client certificate: it goes NotReady when the current one expires"
		}
		sev := SevWarn
		add(sev, "cluster", "csr/"+signer, fmt.Sprintf("%d CertificateSigningRequest(s) for %s pending for over %s (%s): %s", len(names), signer, strutil.HumanDur(thr.StuckDeletion), strutil.TruncList(names, 3), what), "kubectl get csr; check the requestor and SANs, then kubectl certificate approve <name>; for kubelet-serving deploy an approver (kubelet-csr-approver) or approve on join; rke2/k3s issue kubelet certs themselves, so a backlog there means something else creates them")
	}

	// ---- system Services with no ready endpoint ----
	if s.ServiceReady != nil {
		for i := range s.Services {
			sv := &s.Services[i]
			if !system(sv.Namespace) || len(sv.Spec.Selector) == 0 || sv.Spec.Type == corev1.ServiceTypeExternalName {
				continue
			}
			if ready, ok := s.ServiceReady[sv.Namespace+"/"+sv.Name]; ok && ready > 0 {
				continue
			}
			add(SevWarn, "cluster", sv.Namespace+"/svc/"+sv.Name, fmt.Sprintf("system Service %s/%s has no ready endpoint: whatever calls it times out", sv.Namespace, sv.Name), "kubectl -n "+sv.Namespace+" get endpointslices -l kubernetes.io/service-name="+sv.Name+"; compare the selector "+selectorText(sv.Spec.Selector)+" with the pods' labels and their readiness")
		}
	}

	// ---- add-on replicas all on one node ----
	byOwner := map[string]map[string]bool{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Status.Phase != corev1.PodRunning || p.Spec.NodeName == "" || !system(p.Namespace) {
			continue
		}
		for _, o := range p.OwnerReferences {
			if o.Kind == "ReplicaSet" {
				dep := p.Namespace + "/" + strings.TrimSuffix(o.Name, "-"+p.Labels["pod-template-hash"])
				if byOwner[dep] == nil {
					byOwner[dep] = map[string]bool{}
				}
				byOwner[dep][p.Spec.NodeName] = true
			}
		}
	}
	readyNodes := 0
	for i := range s.Nodes {
		if k8s.NodeReady(&s.Nodes[i]) {
			readyNodes++
		}
	}
	for i := range s.Deployments {
		d := &s.Deployments[i]
		key := d.Namespace + "/" + d.Name
		if readyNodes < 2 || d.Spec.Replicas == nil || *d.Spec.Replicas < 2 || d.Status.AvailableReplicas < 2 || len(byOwner[key]) != 1 {
			continue
		}
		var node string
		for n := range byOwner[key] {
			node = n
		}
		add(SevWarn, "workload", d.Namespace+"/deploy/"+d.Name, fmt.Sprintf("all %d replicas of %s run on %s: a reboot of that node takes the service down", d.Status.AvailableReplicas, key, node), "add topologySpreadConstraints or podAntiAffinity on kubernetes.io/hostname (rke2 add-ons: the chart's HelmChartConfig), then kubectl -n "+d.Namespace+" rollout restart deploy/"+d.Name)
	}
}

// broadWebhook: the rules reach pods or every resource, and kube-system is
// not excluded - when it fails closed nothing new starts anywhere,
// including the webhook's own replacement pod.
func broadWebhook(w k8s.Webhook) bool {
	if w.SkipsKubeSys {
		return false
	}
	for _, res := range w.Resources {
		if res == "*" || strings.HasPrefix(res, "*/") || res == "pods" || strings.HasPrefix(res, "pods/") || res == "deployments" || res == "replicasets" {
			return true
		}
	}
	return false
}

func selectorText(sel map[string]string) string {
	var p []string
	for _, k := range strutil.SortedKeys(sel) {
		p = append(p, k+"="+sel[k])
	}
	sort.Strings(p)
	return strings.Join(p, ",")
}

// replicaFailure explains why a Deployment cannot create pods, from its
// ReplicaFailure condition: Pod Security, quota, a webhook, a LimitRange or
// a missing service account. "" when the condition is not set.
func replicaFailure(d *appsv1.Deployment) (cause, hint string) {
	for _, c := range d.Status.Conditions {
		if c.Type != appsv1.DeploymentReplicaFailure || c.Status != corev1.ConditionTrue {
			continue
		}
		msg := strutil.TruncStr(strutil.FirstLine(c.Message), 200)
		switch {
		case strings.Contains(msg, "PodSecurity"):
			return "Pod Security rejects its pods: " + msg, "make the pod spec meet the namespace's level, or label the namespace (pod-security.kubernetes.io/enforce=privileged) / add it to the PSA exemptions (rke2: pod-security-admission-config-file; Rancher: the PSACT template)"
		case strings.Contains(msg, "exceeded quota"):
			return "ResourceQuota refuses its pods: " + msg, "kubectl describe quota -n " + d.Namespace + "; raise the quota or lower the requests"
		case strings.Contains(msg, "failed calling webhook") || strings.Contains(msg, "denied the request"):
			return "an admission webhook refuses its pods: " + msg, "see the webhook finding; kubectl get validatingwebhookconfiguration,mutatingwebhookconfiguration"
		case strings.Contains(msg, "LimitRange") || strings.Contains(msg, "maximum") && strings.Contains(msg, "limit"):
			return "a LimitRange refuses its pods: " + msg, "kubectl describe limitrange -n " + d.Namespace
		case strings.Contains(msg, "serviceaccount") || strings.Contains(msg, "service account"):
			return "its service account is missing: " + msg, "create the ServiceAccount or fix spec.template.spec.serviceAccountName"
		default:
			return "pods cannot be created: " + msg, "kubectl -n " + d.Namespace + " describe rs -l <deployment selector>; kubectl get events -n " + d.Namespace + " --field-selector reason=FailedCreate"
		}
	}
	return "", ""
}

// evalAPIMetrics: API Priority & Fairness rejections (clients get 429s,
// controllers lag) and what fills etcd, from the apiserver's /metrics.
func evalAPIMetrics(in Input, add func(Severity, string, string, string, string)) {
	m := in.Snap.APIMetrics
	if m == nil {
		return
	}
	fmtRej := func(r map[string]float64) (float64, string) {
		var total float64
		var parts []string
		for _, k := range strutil.SortedKeys(r) {
			total += r[k]
			pl, reason, _ := strings.Cut(k, "|")
			parts = append(parts, fmt.Sprintf("%s/%s %.0f", pl, reason, r[k]))
		}
		return total, strutil.TruncList(parts, 3)
	}
	hint := "find the noisy client: kubectl get --raw /metrics | grep apiserver_request_total, or the audit log by user agent; fix or throttle it; raise max-requests-inflight / max-mutating-requests-inflight or give it its own FlowSchema only as a last resort"
	if m.RejectedNew != nil {
		if n, which := fmtRej(m.RejectedNew); n > 0 {
			add(SevWarn, "cluster", "api-priority", fmt.Sprintf("the apiserver rejected %.0f requests (429, API Priority & Fairness) in the last %s: %s - controllers and kubelets retry and lag", n, strutil.HumanDur(m.Since), which), hint)
		}
	} else if n, which := fmtRej(m.Rejected); n > 0 {
		add(SevInfo, "cluster", "api-priority", fmt.Sprintf("the apiserver has rejected %.0f requests (429) since it started: %s", n, which), hint)
	}
	for _, r := range strutil.SortedKeys(m.Objects) {
		if n := m.Objects[r]; n > 50000 {
			add(SevWarn, "etcd", "objects/"+r, fmt.Sprintf("%.0f %s objects in storage: one resource is filling etcd (quota, slow lists, big snapshots)", n, r), "find who creates them (events: lower the controller's event rate or the apiserver event-ttl; Helm release secrets: --history-max; operator CRs: its retention); delete the excess, then compact and defrag")
		}
	}
}

// evalIngressNetpol: the rke2 CIS profile puts a same-namespace-only
// NetworkPolicy (default-network-policy, annotated np.rke2.io) in default,
// kube-public and kube-system. An Ingress whose backend lives in such a
// namespace is unreachable from an ingress controller in another one: the
// controller answers 502/504 (rke2 known issue "Ingress in CIS Mode").
func evalIngressNetpol(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	ctrlNS := map[string]bool{}
	for i := range s.Pods {
		p := &s.Pods[i]
		n := p.Labels["app.kubernetes.io/name"]
		if p.Status.Phase == corev1.PodRunning && (strings.Contains(n, "ingress-nginx") || strings.Contains(n, "traefik")) {
			ctrlNS[p.Namespace] = true
		}
	}
	if len(ctrlNS) == 0 {
		return
	}
	for i := range s.Ingresses {
		ing := &s.Ingresses[i]
		ns := ing.Namespace
		rke2Default, opensUp := false, false
		for j := range s.NetPols {
			np := &s.NetPols[j]
			if np.Namespace != ns {
				continue
			}
			if np.Name == "default-network-policy" && np.Annotations["np.rke2.io"] != "" {
				rke2Default = true
			}
			for _, r := range np.Spec.Ingress {
				if len(r.From) == 0 {
					opensUp = true // from anywhere
				}
				for _, f := range r.From {
					// rke2-flannel-host-networking admits the nodes' flannel
					// addresses as /32 ipBlocks: that is host traffic, not
					// the controller's pods; only a wide block opens it up
					if f.NamespaceSelector != nil || (f.IPBlock != nil && !strings.HasSuffix(f.IPBlock.CIDR, "/32") && !strings.HasSuffix(f.IPBlock.CIDR, "/128")) {
						opensUp = true
					}
				}
			}
		}
		if !rke2Default || opensUp || ctrlNS[ns] {
			continue
		}
		var ctrl []string
		for n := range ctrlNS {
			ctrl = append(ctrl, n)
		}
		sort.Strings(ctrl)
		add(SevWarn, "workload", ns+"/ingress/"+ing.Name, fmt.Sprintf("the ingress controller (namespace %s) cannot reach this Ingress's backends: rke2's CIS default-network-policy in %s only admits traffic from inside %s, so requests end in 502/504", strings.Join(ctrl, ","), ns, ns), "add a NetworkPolicy in "+ns+" allowing ingress from namespaceSelector kubernetes.io/metadata.name="+ctrl[0]+" (podSelector app.kubernetes.io/name of the controller) to the backend pods, or run the app in its own namespace (rke2 known issue: Ingress in CIS mode)")
	}
}

// evalCertManager: cert-manager Certificates that are not Ready, expiring
// without having been renewed, or expired; issuers that are not Ready.
func evalCertManager(in Input, add func(Severity, string, string, string, string)) {
	cm := in.Snap.CertManager
	if cm == nil {
		return
	}
	now := in.Now
	for _, c := range cm.Certificates {
		obj := c.Namespace + "/certificate/" + c.Name
		hint := "kubectl -n " + c.Namespace + " describe certificate " + c.Name + "; kubectl -n " + c.Namespace + " get certificaterequest,order,challenge; cmctl status certificate " + c.Name + " -n " + c.Namespace + " (cmctl renew to retry)"
		switch {
		case !c.NotAfter.IsZero() && !c.NotAfter.After(now):
			add(SevCrit, "security", obj, fmt.Sprintf("certificate %s expired %s ago (secret %s): whatever serves it (ingress, webhook, Rancher) presents an expired certificate", c.Name, strutil.HumanDur(now.Sub(c.NotAfter)), c.Secret), hint)
		case !c.NotAfter.IsZero() && c.NotAfter.Sub(now) < 7*24*time.Hour && !c.RenewalTime.IsZero() && c.RenewalTime.Before(now):
			add(SevWarn, "security", obj, fmt.Sprintf("certificate %s expires in %s and its renewal (due %s ago) has not happened", c.Name, strutil.HumanDur(c.NotAfter.Sub(now)), strutil.HumanDur(now.Sub(c.RenewalTime))), hint)
		case !c.Ready && now.Sub(c.Created) > in.Cfg.Thresholds.PendingPodAge: // a new one takes a moment to issue
			add(SevWarn, "security", obj, fmt.Sprintf("certificate %s is not Ready (%s): %s", c.Name, strutil.FirstNonEmpty(c.Reason, "no reason"), strutil.TruncStr(strutil.FirstLine(c.Message), 160)), hint)
		}
	}
	for _, is := range cm.Issuers {
		if is.Ready {
			continue
		}
		obj := strings.ToLower(is.Kind) + "/" + is.Name
		if is.Namespace != "" {
			obj = is.Namespace + "/" + obj
		}
		add(SevWarn, "security", obj, fmt.Sprintf("cert-manager %s %s is not Ready: %s - certificates it issues cannot be renewed", is.Kind, is.Name, strutil.TruncStr(strutil.FirstLine(is.Message), 160)), "kubectl describe "+strings.ToLower(is.Kind)+" "+is.Name+"; check the CA secret / ACME account and the solver's reachability")
	}
}
