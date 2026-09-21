package stig

// DISA Rancher Government Solutions Multi-Cluster Manager STIG V2R2
// (Release 2, benchmark date 05 Jan 2026), from dl.dod.cyber.mil/wp-content/
// uploads/stigs/zip/U_RGS_MCM_V2R2_STIG.zip. Applies only to the cluster that
// runs Rancher itself (the "local" management cluster); downstream clusters
// get no rules from this file. Facts come from the rancher deployment and
// ingress, the release's helm values and the management.cattle.io objects
// (k8s/rancher.go).

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/strutil"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func (e *evaluator) rancherRules() {
	s := e.in.Snap
	ri := s.Rancher
	if ri == nil || !ri.Management {
		return
	}
	g := "rancher"
	unknown := func(id, title, cat, fix string) {
		e.add(Result{ID: id, Title: title, Cat: cat, Group: g, Status: Unknown, Detail: ri.MgmtErr, Fix: fix})
	}

	// V-252843 external auth provider enabled
	{
		r := Result{ID: "V-252843", Title: "Rancher uses a centralized authentication provider (not local accounts only)", Cat: "I", Group: g, Fix: "Users & Authentication > Auth Provider: configure and enable AD/LDAP/SAML/OIDC"}
		switch {
		case len(ri.AuthProviders) > 0:
			r.Status, r.Detail = Pass, strings.Join(ri.AuthProviders, ", ")
		case ri.MgmtErr != "" && strings.Contains(ri.MgmtErr, "authconfigs"):
			r.Status, r.Detail = Unknown, ri.MgmtErr
		default:
			r.Status, r.Detail = Fail, "no authconfig enabled (local auth only)"
		}
		e.add(r)
	}

	// V-252844 rancher AUDIT_LEVEL >= 2
	{
		r := Result{ID: "V-252844", Title: "Rancher API audit logging enabled (AUDIT_LEVEL >= 2)", Cat: "II", Group: g, Fix: "helm upgrade rancher ... --set auditLog.level=2 (or 3); ship /var/log/auditlog via the audit sidecar"}
		var rancher *corev1.Container
		for i := range s.Deployments {
			d := &s.Deployments[i]
			if d.Namespace == "cattle-system" && d.Name == "rancher" {
				for j := range d.Spec.Template.Spec.Containers {
					if d.Spec.Template.Spec.Containers[j].Name == "rancher" {
						rancher = &d.Spec.Template.Spec.Containers[j]
					}
				}
			}
		}
		switch {
		case rancher == nil:
			r.Status, r.Detail = Unknown, "rancher deployment not in snapshot"
		default:
			lvl := ""
			for _, env := range rancher.Env {
				if env.Name == "AUDIT_LEVEL" {
					lvl = env.Value
				}
			}
			n, err := strconv.Atoi(lvl)
			switch {
			case lvl == "":
				r.Status, r.Detail = Fail, "AUDIT_LEVEL not set"
			case err != nil:
				r.Status, r.Detail = Fail, "AUDIT_LEVEL="+lvl
			case n < 2:
				r.Status, r.Detail = Fail, fmt.Sprintf("AUDIT_LEVEL=%d", n)
			default:
				r.Status, r.Detail = Pass, fmt.Sprintf("AUDIT_LEVEL=%d", n)
			}
		}
		e.add(r)
	}

	// V-252845 new-user default role is user-base, not user
	{
		title := "New users default to the User-Base global role (not Standard User)"
		fix := "Users & Authentication > Roles: set New User Default = No on Standard User (user) and Yes on User-Base (user-base)"
		if ri.GlobalRoles == nil {
			unknown("V-252845", title, "II", fix)
		} else {
			r := Result{ID: "V-252845", Title: title, Cat: "II", Group: g, Status: Pass, Detail: "user-base is the only default", Fix: fix}
			var defaults []string
			for name, def := range ri.GlobalRoles {
				if def {
					defaults = append(defaults, name)
				}
			}
			sort.Strings(defaults)
			switch {
			case ri.GlobalRoles["user"]:
				r.Status, r.Detail = Fail, "Standard User (user) is a new-user default: "+strings.Join(defaults, ", ")
			case !ri.GlobalRoles["user-base"]:
				r.Status, r.Detail = Fail, "User-Base is not a new-user default: "+strings.Join(defaults, ", ")
			case len(defaults) > 1:
				r.Status, r.Detail = Manual, "additional defaults beyond user-base: "+strings.Join(defaults, ", ")
			}
			e.add(r)
		}
	}

	// V-252846 log aggregation: detect a shipper, otherwise manual
	{
		r := Result{ID: "V-252846", Title: "Cluster logs aggregated to a central logging solution", Cat: "II", Group: g, Status: Manual, Detail: "no log shipper detected; confirm logs are aggregated centrally", Fix: "install Rancher Logging (Cluster Tools) or another shipper (fluent-bit, vector, promtail) forwarding to the central log platform"}
		var found []string
		for i := range s.DaemonSets {
			d := &s.DaemonSets[i]
			n := strings.ToLower(d.Name)
			if d.Namespace == "cattle-logging-system" || strings.Contains(n, "fluent") || strings.Contains(n, "vector") || strings.Contains(n, "promtail") || strings.Contains(n, "filebeat") || strings.Contains(n, "logging") {
				found = append(found, d.Namespace+"/"+d.Name)
			}
		}
		if len(found) > 0 {
			r.Status, r.Detail = Manual, "shipper present: "+strutil.TruncList(strutil.Uniq(found), 4)+" - confirm the destination is the central log platform"
		}
		e.add(r)
	}

	// V-252847 exactly one local account, and it is an administrator
	{
		title := "Exactly one local account exists and it is an administrator (emergency account)"
		fix := "Users & Authentication > Users: keep a single local admin, remove other local accounts (external users keep their provider principals)"
		if ri.Users == nil {
			unknown("V-252847", title, "II", fix)
		} else {
			r := Result{ID: "V-252847", Title: title, Cat: "II", Group: g, Status: Pass, Fix: fix}
			local := ri.LocalUsers()
			var labels []string
			for _, u := range local {
				labels = append(labels, u.Label())
			}
			switch {
			case len(local) == 0:
				r.Status, r.Detail = Fail, "no local administrator account"
			case len(local) > 1:
				r.Status, r.Detail = Fail, fmt.Sprintf("%d local accounts: %s", len(local), strutil.TruncList(labels, 6))
			case !local[0].Admin:
				r.Status, r.Detail = Fail, local[0].Label()+" is not an administrator"
			case !local[0].Enabled:
				r.Status, r.Detail = Fail, local[0].Label()
			default:
				r.Detail = local[0].Label()
			}
			e.add(r)
		}
	}

	// V-252849 ingress on 443, network policies restricting rancher pods to 444
	{
		r := Result{ID: "V-252849", Title: "Rancher ingress on 443 and NetworkPolicies limit rancher pods to port 444", Cat: "I", Group: g, Fix: "ingress backend port 443; add rancher-allow-https (ingress to 444 only) and rancher-deny-ingress policies with podSelector app=rancher in cattle-system"}
		var probs []string
		switch {
		case !ri.IngressFound:
			probs = append(probs, "ingress cattle-system/rancher not found")
		default:
			for _, p := range ri.IngressPorts {
				if p != 443 {
					probs = append(probs, fmt.Sprintf("ingress backend port %d", p))
				}
			}
		}
		selecting, allow444, other := 0, false, []string{}
		for i := range s.NetPols {
			np := &s.NetPols[i]
			if np.Namespace != "cattle-system" || np.Spec.PodSelector.MatchLabels["app"] != "rancher" {
				continue
			}
			selecting++
			for _, rule := range np.Spec.Ingress {
				for _, port := range rule.Ports {
					if port.Port == nil {
						continue
					}
					if port.Port.IntValue() == 444 {
						allow444 = true
					} else {
						other = append(other, np.Name+":"+port.Port.String())
					}
				}
			}
		}
		switch {
		case selecting == 0:
			probs = append(probs, "no NetworkPolicy selects app=rancher in cattle-system")
		case !allow444:
			probs = append(probs, "no policy allows ingress to port 444")
		}
		if len(other) > 0 {
			probs = append(probs, "policies allow other ports: "+strutil.TruncList(other, 4))
		}
		if len(probs) > 0 {
			r.Status, r.Detail = Fail, strings.Join(probs, "; ")
		} else {
			r.Status, r.Detail = Pass, fmt.Sprintf("ingress 443, %d policies on app=rancher", selecting)
		}
		e.add(r)
	}

	// V-257292 helm values: privateCA true, ingress.tls.source secret
	{
		r := Result{ID: "V-257292", Title: "Rancher installed with privateCA=true and ingress.tls.source=secret", Cat: "II", Group: g, Fix: "helm upgrade rancher ... --set privateCA=true --set ingress.tls.source=secret with tls-rancher-ingress and tls-ca secrets from the organizational CA"}
		var vals map[string]any
		found := false
		for i := range s.HelmReleases {
			h := &s.HelmReleases[i]
			if h.Namespace == "cattle-system" && h.Name == "rancher" {
				found = true
				if err := yaml.Unmarshal([]byte(h.ValuesYAML), &vals); err != nil {
					r.Status, r.Detail = Unknown, "values: "+err.Error()
				}
			}
		}
		switch {
		case !found:
			r.Status, r.Detail = Unknown, "helm release cattle-system/rancher not readable"
		case r.Status == Unknown:
		default:
			var probs []string
			if pc, _ := vals["privateCA"].(bool); !pc {
				probs = append(probs, "privateCA not true")
			}
			src, _ := nested(vals, "ingress", "tls", "source")
			if src != "secret" {
				probs = append(probs, fmt.Sprintf("ingress.tls.source=%v", src))
			}
			if len(probs) > 0 {
				r.Status, r.Detail = Fail, strings.Join(probs, "; ")
			} else {
				r.Status, r.Detail = Pass, "privateCA=true, ingress.tls.source=secret"
				if len(ri.IngressTLS) > 0 {
					r.Detail += " (" + strings.Join(ri.IngressTLS, ", ") + ")"
				}
			}
		}
		e.add(r)
	}
}
