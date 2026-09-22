package k8s

import (
	"sort"
	"strings"
)

// ACEStatus is what the cluster shows of Rancher's Authorized Cluster
// Endpoint: with ACE, Rancher makes every server's kube-apiserver
// authenticate tokens through a webhook (--authentication-token-webhook-
// config-file, the kube-api-authn-webhook.yaml file rancher-system-agent
// delivers) answered by the kube-api-auth DaemonSet on :6440, so kubectl
// can reach the cluster directly - and keep reaching it while Rancher is
// down. Without it every request goes through the Rancher server.
type ACEStatus struct {
	Servers []string // control-plane nodes whose apiserver has the webhook flag
	Without []string // control-plane nodes whose apiserver has not (mixed = the plan did not land everywhere)
	Webhook string   // the webhook config file path (from the flag)
	// the authenticator the webhook calls
	AuthFound     bool
	AuthReady     int32
	AuthDesired   int32
	AuthNamespace string
}

// Enabled reports whether every visible apiserver carries the webhook.
func (a ACEStatus) Enabled() bool { return len(a.Servers) > 0 && len(a.Without) == 0 }

// ACE reads the endpoint's state from the apiserver static pods' flags
// and the kube-api-auth DaemonSet.
func (s *Snapshot) ACE() ACEStatus {
	var st ACEStatus
	for node, f := range ComponentArgs(s.Pods, "kube-apiserver") {
		if v := f["authentication-token-webhook-config-file"]; v != "" {
			st.Servers = append(st.Servers, node)
			if st.Webhook == "" || strings.HasSuffix(v, "kube-api-authn-webhook.yaml") {
				st.Webhook = v
			}
		} else {
			st.Without = append(st.Without, node)
		}
	}
	sort.Strings(st.Servers)
	sort.Strings(st.Without)
	for i := range s.DaemonSets {
		d := &s.DaemonSets[i]
		if d.Name == "kube-api-auth" {
			st.AuthFound, st.AuthReady, st.AuthDesired, st.AuthNamespace = true, d.Status.NumberReady, d.Status.DesiredNumberScheduled, d.Namespace
		}
	}
	return st
}
