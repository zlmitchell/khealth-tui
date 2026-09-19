package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// RancherUser is one users.management.cattle.io object, reduced to what the
// Rancher MCM STIG asks about local (password) accounts.
type RancherUser struct {
	Name        string // object name (u-xxxxx)
	Username    string
	DisplayName string
	Local       bool // no external principal: a local password account
	Admin       bool // bound to the "admin" global role
	Enabled     bool
}

var (
	authConfigGVR         = schema.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "authconfigs"}
	globalRoleGVR         = schema.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalroles"}
	globalRoleBindingGVR  = schema.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalrolebindings"}
	rancherUserGVR        = schema.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "users"}
	rancherMgmtErrPrefix  = "management.cattle.io: "
	rancherIngressNS      = "cattle-system"
	rancherIngressName    = "rancher"
	rancherLocalPrincipal = "local://"
)

// rancherManagement fills the management-cluster facts of RancherInfo: the
// rancher ingress, the enabled auth providers, the global roles marked as
// new-user defaults and the local user accounts. Failures (RBAC, CRDs
// missing) are recorded in MgmtErr; the STIG rules then report Unknown.
func (c *Client) rancherManagement(ctx context.Context, info *RancherInfo) {
	info.Management = true
	fail := func(what string, err error) {
		if info.MgmtErr == "" {
			info.MgmtErr = rancherMgmtErrPrefix + what + ": " + err.Error()
		}
	}

	if ing, err := c.CS.NetworkingV1().Ingresses(rancherIngressNS).Get(ctx, rancherIngressName, metav1.GetOptions{}); err == nil {
		info.IngressFound = true
		for _, r := range ing.Spec.Rules {
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				if p.Backend.Service != nil {
					info.IngressPorts = append(info.IngressPorts, p.Backend.Service.Port.Number)
				}
			}
		}
		for _, t := range ing.Spec.TLS {
			info.IngressTLS = append(info.IngressTLS, t.SecretName)
		}
	} else {
		fail("ingress cattle-system/rancher", err)
	}

	if l, err := c.Dyn.Resource(authConfigGVR).List(ctx, c.listOpts()); err == nil {
		for i := range l.Items {
			u := &l.Items[i]
			enabled, _, _ := unstructured.NestedBool(u.Object, "enabled")
			if enabled && u.GetName() != "local" {
				typ, _, _ := unstructured.NestedString(u.Object, "type")
				info.AuthProviders = append(info.AuthProviders, u.GetName()+" ("+strings.TrimSuffix(typ, "Config")+")")
			}
		}
		sort.Strings(info.AuthProviders)
	} else {
		fail("authconfigs", err)
	}

	if l, err := c.Dyn.Resource(globalRoleGVR).List(ctx, c.listOpts()); err == nil {
		info.GlobalRoles = map[string]bool{}
		for i := range l.Items {
			u := &l.Items[i]
			def, _, _ := unstructured.NestedBool(u.Object, "newUserDefault")
			info.GlobalRoles[u.GetName()] = def
		}
	} else {
		fail("globalroles", err)
	}

	admins := map[string]bool{}
	if l, err := c.Dyn.Resource(globalRoleBindingGVR).List(ctx, c.listOpts()); err == nil {
		for i := range l.Items {
			u := &l.Items[i]
			role, _, _ := unstructured.NestedString(u.Object, "globalRoleName")
			user, _, _ := unstructured.NestedString(u.Object, "userName")
			if role == "admin" && user != "" {
				admins[user] = true
			}
		}
	} else {
		fail("globalrolebindings", err)
	}

	if l, err := c.Dyn.Resource(rancherUserGVR).List(ctx, c.listOpts()); err == nil {
		for i := range l.Items {
			u := &l.Items[i]
			principals, _, _ := unstructured.NestedStringSlice(u.Object, "principalIds")
			local := true
			for _, p := range principals {
				if !strings.HasPrefix(p, rancherLocalPrincipal) {
					local = false
				}
			}
			username, _, _ := unstructured.NestedString(u.Object, "username")
			display, _, _ := unstructured.NestedString(u.Object, "displayName")
			enabled := true
			if v, ok, _ := unstructured.NestedBool(u.Object, "enabled"); ok {
				enabled = v
			}
			info.Users = append(info.Users, RancherUser{Name: u.GetName(), Username: username, DisplayName: display, Local: local && username != "", Admin: admins[u.GetName()], Enabled: enabled})
		}
		sort.Slice(info.Users, func(i, j int) bool { return info.Users[i].Name < info.Users[j].Name })
	} else {
		fail("users", err)
	}
}

// LocalUsers returns the local password accounts (STIG: exactly one, an admin).
func (r *RancherInfo) LocalUsers() []RancherUser {
	var out []RancherUser
	for _, u := range r.Users {
		if u.Local {
			out = append(out, u)
		}
	}
	return out
}

// Label is a short user reference for rule detail text.
func (u RancherUser) Label() string {
	name := u.Username
	if name == "" {
		name = u.DisplayName
	}
	if name == "" {
		name = u.Name
	}
	switch {
	case u.Admin && !u.Enabled:
		return fmt.Sprintf("%s (admin, disabled)", name)
	case u.Admin:
		return name + " (admin)"
	case !u.Enabled:
		return name + " (disabled)"
	}
	return name
}
