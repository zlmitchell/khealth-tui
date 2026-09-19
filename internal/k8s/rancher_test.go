package k8s

import (
	"context"
	"net/http"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func deployment(ns, name string, replicas, ready int32, env ...corev1.EnvVar) appsv1.Deployment {
	return appsv1.Deployment{TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}, ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:   appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: name, Env: env}}}}},
		Status: appsv1.DeploymentStatus{Replicas: replicas, ReadyReplicas: ready}}
}

func TestRancherInfoManaged(t *testing.T) {
	f := newFakeAPI(t)
	f.set("/apis/apps/v1/namespaces/cattle-system/deployments/cattle-cluster-agent", deployment("cattle-system", "cattle-cluster-agent", 2, 2,
		corev1.EnvVar{Name: "CATTLE_SERVER", Value: "https://rancher.example.com"},
		corev1.EnvVar{Name: "CATTLE_TOKEN", Value: "supersecret"},
		corev1.EnvVar{Name: "CATTLE_CA_CHECKSUM", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "ca"}}}},
		corev1.EnvVar{Name: "CATTLE_CREDENTIAL_NAME", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "cred"}}}},
		corev1.EnvVar{Name: "CATTLE_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
		corev1.EnvVar{Name: "CATTLE_X", ValueFrom: &corev1.EnvVarSource{ResourceFieldRef: &corev1.ResourceFieldSelector{Resource: "limits.cpu"}}},
		corev1.EnvVar{Name: "OTHER", Value: "ignored"}))
	f.set("/apis/apps/v1/namespaces/cattle-fleet-system/deployments/fleet-agent", deployment("cattle-fleet-system", "fleet-agent", 1, 0))
	f.set("/apis/apps/v1/namespaces/cattle-system/deployments/system-upgrade-controller", deployment("cattle-system", "system-upgrade-controller", 1, 1))
	c := f.client(t, DefaultOptions())
	info := c.rancherInfo(context.Background())
	if info == nil || !info.Managed || info.Server != "https://rancher.example.com" || info.ClusterAgent != "2/2 ready" || !info.ClusterAgentOK {
		t.Fatalf("managed: %+v", info)
	}
	if info.Env["CATTLE_TOKEN"] != "<masked>" || info.Env["CATTLE_CA_CHECKSUM"] != "<from configmap ca>" || info.Env["CATTLE_CREDENTIAL_NAME"] != "<from secret cred>" || info.Env["CATTLE_NODE_NAME"] != "<from field spec.nodeName>" || info.Env["CATTLE_X"] != "<from ref>" {
		t.Errorf("env: %v", info.Env)
	}
	if _, ok := info.Env["OTHER"]; ok {
		t.Error("non-CATTLE env kept")
	}
	if info.FleetAgentOK == nil || *info.FleetAgentOK || info.FleetNamespace != "cattle-fleet-system" {
		t.Errorf("fleet: %+v", info.FleetAgentOK)
	}
	if info.SystemUpgradeOK == nil || !*info.SystemUpgradeOK {
		t.Errorf("system-upgrade: %+v", info.SystemUpgradeOK)
	}

	// fleet-agent as a StatefulSet (newer Rancher)
	f.denyWith("/apis/apps/v1/namespaces/cattle-fleet-system/deployments/fleet-agent", http.StatusNotFound)
	f.set("/apis/apps/v1/namespaces/cattle-fleet-system/statefulsets/fleet-agent", appsv1.StatefulSet{TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"}, Status: appsv1.StatefulSetStatus{Replicas: 1, ReadyReplicas: 1}})
	info = c.rancherInfo(context.Background())
	if info.FleetAgentOK == nil || !*info.FleetAgentOK {
		t.Errorf("fleet statefulset: %+v", info.FleetAgentOK)
	}
}

func TestRancherInfoDeniedAndAbsent(t *testing.T) {
	f := newFakeAPI(t)
	f.denyWith("/apis/apps/v1/namespaces/cattle-system/deployments/cattle-cluster-agent", http.StatusForbidden)
	c := f.client(t, DefaultOptions())
	if info := c.rancherInfo(context.Background()); info != nil {
		t.Errorf("403 must yield nil: %+v", info)
	}
	if _, ok := c.Denied("rancher"); !ok {
		t.Error("403 not remembered")
	}
	// Fetch then skips the Rancher probe entirely
	rke2Cluster(f)
	if s := c.Fetch(context.Background()); s.Rancher != nil {
		t.Errorf("rancher probed while denied: %+v", s.Rancher)
	}
	// a 500 is neither managed nor remembered
	c.ResetDenied()
	f.denyWith("/apis/apps/v1/namespaces/cattle-system/deployments/cattle-cluster-agent", http.StatusInternalServerError)
	if info := c.rancherInfo(context.Background()); info != nil {
		t.Errorf("500 must yield nil: %+v", info)
	}
	if len(c.DeniedList()) != 0 {
		t.Errorf("500 remembered: %v", c.DeniedList())
	}
}

func TestRancherManagementCluster(t *testing.T) {
	f := newFakeAPI(t)
	f.set("/apis/apps/v1/namespaces/cattle-system/deployments/rancher", deployment("cattle-system", "rancher", 3, 3))
	f.set("/apis/networking.k8s.io/v1/namespaces/cattle-system/ingresses/rancher", networkingv1.Ingress{TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{SecretName: "tls-rancher-ingress"}},
			Rules: []networkingv1.IngressRule{
				{Host: "rancher.example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{
					{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "rancher", Port: networkingv1.ServiceBackendPort{Number: 80}}}},
					{Backend: networkingv1.IngressBackend{Resource: &corev1.TypedLocalObjectReference{Name: "x"}}},
				}}}},
				{Host: "no-http"},
			}}})
	f.set("/apis/management.cattle.io/v3/authconfigs", ulist("management.cattle.io/v3", "AuthConfig",
		uobj("", "local", map[string]any{"enabled": true, "type": "localConfig"}),
		uobj("", "openldap", map[string]any{"enabled": true, "type": "openLdapConfig"}),
		uobj("", "github", map[string]any{"enabled": false, "type": "githubConfig"}),
		uobj("", "activedirectory", map[string]any{"enabled": true, "type": "activeDirectoryConfig"}),
	))
	f.set("/apis/management.cattle.io/v3/globalroles", ulist("management.cattle.io/v3", "GlobalRole",
		uobj("", "admin", map[string]any{"newUserDefault": false}),
		uobj("", "user", map[string]any{"newUserDefault": true}),
	))
	f.set("/apis/management.cattle.io/v3/globalrolebindings", ulist("management.cattle.io/v3", "GlobalRoleBinding",
		uobj("", "grb-1", map[string]any{"globalRoleName": "admin", "userName": "user-admin"}),
		uobj("", "grb-2", map[string]any{"globalRoleName": "user", "userName": "user-bob"}),
		uobj("", "grb-3", map[string]any{"globalRoleName": "admin", "groupPrincipalName": "openldap_group://admins"}),
	))
	f.set("/apis/management.cattle.io/v3/users", ulist("management.cattle.io/v3", "User",
		uobj("", "user-bob", map[string]any{"username": "bob", "displayName": "Bob", "principalIds": []any{"local://user-bob", "openldap_user://bob"}}),
		uobj("", "user-admin", map[string]any{"username": "admin", "displayName": "Default Admin", "principalIds": []any{"local://user-admin"}, "enabled": true}),
		uobj("", "user-old", map[string]any{"username": "old", "principalIds": []any{"local://user-old"}, "enabled": false}),
		uobj("", "user-svc", map[string]any{"displayName": "Service", "principalIds": []any{"local://user-svc"}}),
	))
	c := f.client(t, DefaultOptions())
	info := c.rancherInfo(context.Background())
	if info == nil || info.Managed || !info.Management || !strings.Contains(info.Provisioning, "management") || info.MgmtErr != "" {
		t.Fatalf("management: %+v", info)
	}
	if !info.IngressFound || len(info.IngressPorts) != 1 || info.IngressPorts[0] != 80 || len(info.IngressTLS) != 1 {
		t.Errorf("ingress: ports=%v tls=%v", info.IngressPorts, info.IngressTLS)
	}
	if strings.Join(info.AuthProviders, ";") != "activedirectory (activeDirectory);openldap (openLdap)" {
		t.Errorf("auth providers: %v", info.AuthProviders)
	}
	if !info.GlobalRoles["user"] || info.GlobalRoles["admin"] || len(info.GlobalRoles) != 2 {
		t.Errorf("global roles: %v", info.GlobalRoles)
	}
	if len(info.Users) != 4 || info.Users[0].Name != "user-admin" {
		t.Fatalf("users not sorted: %+v", info.Users)
	}
	byName := map[string]RancherUser{}
	for _, u := range info.Users {
		byName[u.Name] = u
	}
	if u := byName["user-admin"]; !u.Local || !u.Admin || !u.Enabled || u.Label() != "admin (admin)" {
		t.Errorf("admin: %+v label=%q", u, u.Label())
	}
	if u := byName["user-bob"]; u.Local || u.Admin || !u.Enabled || u.Label() != "bob" {
		t.Errorf("external user must not count as local: %+v", u)
	}
	if u := byName["user-old"]; !u.Local || u.Enabled || u.Label() != "old (disabled)" {
		t.Errorf("disabled: %+v label=%q", u, u.Label())
	}
	if u := byName["user-svc"]; u.Local || u.Label() != "Service" {
		t.Errorf("no username is not a local password account: %+v label=%q", u, u.Label())
	}
	if l := info.LocalUsers(); len(l) != 2 {
		t.Errorf("local users: %+v", l)
	}
	if (RancherUser{Name: "u-1", Admin: true}).Label() != "u-1 (admin, disabled)" {
		t.Error("label fallback to the object name")
	}

	// the first collection error is kept; the rest still fills in
	f.denyWith("/apis/networking.k8s.io/v1/namespaces/cattle-system/ingresses/rancher", http.StatusForbidden)
	f.denyWith("/apis/management.cattle.io/v3/users", http.StatusForbidden)
	c.ResetDenied()
	info = c.rancherInfo(context.Background())
	if !strings.HasPrefix(info.MgmtErr, "management.cattle.io: ingress cattle-system/rancher: ") || info.IngressFound || len(info.Users) != 0 || len(info.AuthProviders) != 2 {
		t.Errorf("partial failure: err=%q found=%v users=%d auth=%v", info.MgmtErr, info.IngressFound, len(info.Users), info.AuthProviders)
	}
	if _, ok := c.Denied("users.management.cattle.io"); !ok {
		t.Error("403 on users not remembered")
	}
}

func TestDescribeValueFrom(t *testing.T) {
	if describeValueFrom(&corev1.EnvVarSource{}) != "ref" {
		t.Error("empty source")
	}
	if (&RancherInfo{}).LocalUsers() != nil {
		t.Error("no users")
	}
}
