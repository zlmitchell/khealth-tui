package checks

import (
	"fmt"

	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// evalACE: on a Rancher-managed cluster, whether the Authorized Cluster
// Endpoint is on and working. Without it every kubectl goes through the
// Rancher server, so a Rancher outage takes this cluster's API away from
// its operators (khealth included); with it, the webhook authenticator has
// to be there or every direct request is refused.
func evalACE(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	r := s.Rancher
	if r == nil || !r.Managed {
		return
	}
	ace := s.ACE()
	if len(ace.Servers)+len(ace.Without) == 0 {
		return // no apiserver pods visible: nothing to judge
	}
	// provisioned by Rancher (rancher-system-agent writes 50-rancher.yaml)
	// or imported: ACE is a provisioning feature, an imported cluster keeps
	// its own kubeconfig for direct access
	provisioned, probed := false, false
	for _, ni := range in.Nodes {
		if ni == nil || ni.Err != nil || !ni.ControlPlane {
			continue
		}
		probed = true
		if ni.Rancher.Provisioned {
			provisioned = true
		}
	}
	switch {
	case len(ace.Servers) == 0:
		if probed && !provisioned {
			return // imported: direct access is the cluster's own kubeconfig
		}
		add(SevInfo, "addons", "rancher", "Authorized Cluster Endpoint (ACE) is not enabled: every kubectl goes through Rancher at "+strutil.FirstNonEmpty(r.Server, "the management server")+", so while Rancher is down or unreachable nobody reaches this cluster's API",
			"Cluster Management > the cluster > Edit Config > Networking > Authorized Endpoint: enable it with the FQDN of a VIP / load balancer in front of the servers (an entry of tls-san, so the serving certificate covers it) and its CA; the kubeconfig Rancher hands out then carries a direct context that works without Rancher")
	case len(ace.Without) > 0:
		add(SevWarn, "addons", "rancher", fmt.Sprintf("ACE webhook configured on %s but not on %s: direct requests fail (401) whenever the endpoint lands on those servers", strutil.TruncList(ace.Servers, 3), strutil.TruncList(ace.Without, 3)),
			"the machine plan should carry authentication-token-webhook-config-file to every server: check rancher-system-agent and the plan state on the nodes without it")
	case !ace.AuthFound:
		add(SevCrit, "addons", "rancher", "ACE is enabled (webhook "+ace.Webhook+") but the kube-api-auth DaemonSet is missing: the authenticator on :6440 is that DaemonSet, so every direct request is refused (401)",
			"kubectl -n cattle-system get ds kube-api-auth; Rancher deploys it with the endpoint - re-save the cluster's ACE settings, or check the cluster-agent")
	case ace.AuthReady < ace.AuthDesired:
		add(SevCrit, "addons", "rancher", fmt.Sprintf("ACE is enabled but kube-api-auth is %d/%d ready in %s: direct requests are refused (401) on the servers without it", ace.AuthReady, ace.AuthDesired, ace.AuthNamespace),
			"kubectl -n "+ace.AuthNamespace+" describe ds kube-api-auth; the pods run on the control-plane nodes with hostNetwork")
	}
}
