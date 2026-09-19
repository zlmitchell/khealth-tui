package stig

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
)

func find(rs []Result, id string) *Result {
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i]
		}
	}
	return nil
}

func TestEvaluate(t *testing.T) {
	snap := &k8s.Snapshot{
		Distribution: "rke2",
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-cp-1", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}},
				Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "kube-apiserver", Args: []string{"kube-apiserver", "--anonymous-auth=false", "--authorization-mode=Node,RBAC", "--audit-log-maxage=10", "--profiling=false"}}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
		},
		Namespaces:     []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}, {ObjectMeta: metav1.ObjectMeta{Name: "team-b", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}},
		KubeletConfigs: map[string]map[string]any{"cp-1": {"authentication": map[string]any{"anonymous": map[string]any{"enabled": false}}, "authorization": map[string]any{"mode": "Webhook"}, "readOnlyPort": float64(0), "protectKernelDefaults": true, "streamingConnectionIdleTimeout": "0s"}},
	}
	nodes := map[string]*nodeinfo.Info{"cp-1": {Node: "cp-1", Dist: "rke2", ControlPlane: true, EtcdUser: true, Settings: map[string]string{"profile": "cis"}, Sysctl: map[string]string{"vm.overcommit_memory": "0"},
		Perms: []nodeinfo.Perm{{Path: "/etc/rancher/rke2/config.yaml", Mode: "644", User: "root", Group: "root", Type: "regular file"}, {Path: "/var/lib/rancher/rke2/server/db/etcd", Mode: "700", User: "etcd", Group: "etcd", Type: "directory"}}, KubeletFlags: map[string]string{"hostname-override": "cp-1"}}}
	rs := Evaluate(Input{Snap: snap, Nodes: nodes})
	expect := map[string]Status{
		"V-242390": Pass, "V-242382": Pass, "V-242464": Fail, "V-242378": Fail, "CIS-1.2.15": Pass,
		"V-242391": Pass, "V-242392": Pass, "V-242387": Pass, "V-245541": Fail, "V-242434": Pass, "V-242404": NA,
		"V-254555": Pass, "CIS-sysctl": Fail, "V-242445": Pass, "RKE2-etcd-user": Pass, "V-254564": Fail,
		"V-242383": Fail, "V-254800-ns": Fail, "V-242395": Pass,
	}
	for id, want := range expect {
		r := find(rs, id)
		if r == nil {
			t.Errorf("missing rule %s", id)
			continue
		}
		if r.Status != want {
			t.Errorf("%s: got %s (%s) want %s", id, r.Status, r.Detail, want)
		}
	}
	if !modeAtMost("600", 0o600) || modeAtMost("644", 0o600) || !modeAtMost("400", 0o644) {
		t.Errorf("modeAtMost")
	}
}

func TestOSBenchmarkFor(t *testing.T) {
	cases := []struct {
		os   nodeinfo.OSRelease
		want string
	}{
		{nodeinfo.OSRelease{ID: "rhel", VersionID: "9.4"}, "DISA RHEL 9 STIG"},
		{nodeinfo.OSRelease{ID: "rocky", IDLike: "rhel centos fedora", VersionID: "8.10"}, "DISA RHEL 8 STIG"},
		{nodeinfo.OSRelease{ID: "almalinux", IDLike: "rhel centos fedora", VersionID: "10.0"}, "DISA RHEL 10 STIG"},
		{nodeinfo.OSRelease{ID: "ubuntu", IDLike: "debian", VersionID: "22.04"}, "DISA Ubuntu 22.04 LTS STIG"},
		{nodeinfo.OSRelease{ID: "ubuntu", IDLike: "debian", VersionID: "24.04"}, "DISA Ubuntu 24.04 LTS STIG"},
		{nodeinfo.OSRelease{ID: "ubuntu", IDLike: "debian", VersionID: "20.04"}, ""},
		{nodeinfo.OSRelease{ID: "sles", IDLike: "suse", VersionID: "15.5"}, ""},
		{nodeinfo.OSRelease{ID: "debian", VersionID: "12"}, ""},
		{nodeinfo.OSRelease{}, ""},
	}
	for _, c := range cases {
		got := ""
		if b := OSBenchmarkFor(c.os); b != nil {
			got = b.Name
		}
		if got != c.want {
			t.Errorf("%+v: got %q want %q", c.os, got, c.want)
		}
	}
	// every table key must be a known check
	known := map[string]bool{}
	for _, c := range osChecks {
		known[c.key] = true
	}
	for _, b := range OSBenchmarks {
		for k := range b.rules {
			if !known[k] {
				t.Errorf("%s: rule key %q has no osCheck", b.Name, k)
			}
		}
	}
}

func TestOSRulesPerBenchmark(t *testing.T) {
	snap := &k8s.Snapshot{Distribution: "rke2"}
	synced := true
	nodes := map[string]*nodeinfo.Info{
		"rhel-1": {Node: "rhel-1", Dist: "rke2", STIGProbed: true, OS: nodeinfo.OSRelease{ID: "rhel", VersionID: "9.4"}, NTPSynced: &synced,
			Hardening: map[string]string{"fips": "1", "fips_boot": "yes", "selinux": "Enforcing", "selinux_config": "enforcing", "svc_fapolicyd": "loaded active enabled", "svc_auditd": "loaded active enabled", "svc_firewalld": "loaded inactive disabled", "svc_usbguard": "loaded active enabled", "svc_chronyd": "loaded active enabled"},
			Sysctl:    map[string]string{"kernel.randomize_va_space": "2", "kernel.dmesg_restrict": "0", "kernel.core_pattern": "|/bin/false"}},
		"ubu-1": {Node: "ubu-1", Dist: "rke2", STIGProbed: true, OS: nodeinfo.OSRelease{ID: "ubuntu", IDLike: "debian", VersionID: "22.04"}, NTPSynced: &synced,
			Hardening: map[string]string{"fips": "0", "fips_boot": "no", "apparmor": "Y", "apparmor_enforced": "12", "svc_auditd": "loaded active enabled", "ufw": "active", "svc_chrony": "loaded active enabled"},
			Sysctl:    map[string]string{"kernel.randomize_va_space": "2", "kernel.dmesg_restrict": "1"}},
		"sles-1": {Node: "sles-1", Dist: "rke2", OS: nodeinfo.OSRelease{ID: "sles", IDLike: "suse", VersionID: "15.5"},
			Hardening: map[string]string{"fips": "1", "fips_boot": "yes", "selinux": "Enforcing"}},
	}
	rs := Evaluate(Input{Snap: snap, Nodes: nodes})
	expect := map[string]Status{
		"V-258230": Pass,   // RHEL 9 FIPS
		"V-258078": Pass,   // RHEL 9 SELinux
		"V-270180": Pass,   // RHEL 9 fapolicyd
		"V-257936": Fail,   // RHEL 9 firewalld inactive
		"V-258036": Pass,   // RHEL 9 usbguard
		"V-257944": Pass,   // RHEL 9 chrony
		"V-257797": Fail,   // RHEL 9 dmesg_restrict=0
		"V-257803": Pass,   // RHEL 9 core_pattern
		"V-257800": Manual, // RHEL 9 kptr_restrict not collected
		"V-260650": Fail,   // Ubuntu 22.04 FIPS off
		"V-260557": Pass,   // Ubuntu 22.04 AppArmor
		"V-260515": Pass,   // Ubuntu 22.04 ufw
		"V-260472": Pass,   // Ubuntu 22.04 dmesg
		"OS-fips":  Pass,   // SLES falls back to the generic ID
		"OS-mac":   Pass,
	}
	for id, want := range expect {
		r := find(rs, id)
		if r == nil {
			t.Errorf("missing rule %s", id)
			continue
		}
		if r.Status != want {
			t.Errorf("%s: got %s (%s) want %s", id, r.Status, r.Detail, want)
		}
		if r.Group != "os" {
			t.Errorf("%s: group %q", id, r.Group)
		}
	}
	for _, id := range []string{"V-244546", "V-281009"} {
		if find(rs, id) != nil {
			t.Errorf("%s should not be evaluated for these nodes", id)
		}
	}
	for _, id := range []string{"OS-fapolicyd", "OS-usbguard"} {
		if r := find(rs, id); r == nil || r.Status != NA {
			t.Errorf("%s should be N/A on the SLES node, got %+v", id, r)
		}
	}
	if r := find(rs, "V-258230"); r.Ref != "DISA RHEL 9 STIG V2R9 (01 Jul 2026)" || r.PerNode["rhel-1"] != Pass || len(r.PerNode) != 1 {
		t.Errorf("ref/per-node bookkeeping: %+v", r)
	}
	counts, ref := OSSummary(rs, "ubu-1")
	if counts[Pass] == 0 || counts[Fail] == 0 || ref == "" {
		t.Errorf("OSSummary ubu-1: %v %q", counts, ref)
	}
	if find(rs, "OS-fips").Ref != "" {
		t.Errorf("generic OS rules carry no Ref")
	}
	// facts not collected yet (S not pressed): no table rows for that node
	nodes["rhel-1"].STIGProbed = false
	rs = Evaluate(Input{Snap: snap, Nodes: nodes})
	if r := find(rs, "V-258230"); r != nil {
		t.Errorf("unprobed RHEL node must produce no OS STIG rows, got %+v", r)
	}
	if r := find(rs, "V-260650"); r == nil {
		t.Errorf("probed Ubuntu node must still produce its rows")
	}
}

func TestRancherRules(t *testing.T) {
	// downstream cluster: no rancher rules at all
	rs := Evaluate(Input{Snap: &k8s.Snapshot{Rancher: &k8s.RancherInfo{Managed: true}}})
	for _, r := range rs {
		if r.Group == "rancher" {
			t.Fatalf("rancher rule %s on a downstream cluster", r.ID)
		}
	}

	port444 := intstr.FromInt(444)
	port443 := intstr.FromInt(443)
	snap := &k8s.Snapshot{
		Rancher: &k8s.RancherInfo{Management: true, IngressFound: true, IngressPorts: []int32{443}, IngressTLS: []string{"tls-rancher-ingress"},
			AuthProviders: []string{"openldap (OpenLdap)"},
			GlobalRoles:   map[string]bool{"admin": false, "user": true, "user-base": true},
			Users: []k8s.RancherUser{
				{Name: "user-abc", Username: "admin", Local: true, Admin: true, Enabled: true},
				{Name: "u-x1", Username: "svc-break-glass", Local: true, Admin: false, Enabled: true},
				{Name: "u-x2", DisplayName: "Jane", Local: false, Enabled: true},
			}},
		Deployments: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "rancher", Namespace: "cattle-system"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "rancher", Env: []corev1.EnvVar{{Name: "AUDIT_LEVEL", Value: "1"}}}}}}}}},
		NetPols: []networkingv1.NetworkPolicy{
			{ObjectMeta: metav1.ObjectMeta{Name: "rancher-allow-https", Namespace: "cattle-system"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "rancher"}},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{{Port: &port444}}}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "rancher-deny-ingress", Namespace: "cattle-system"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "rancher"}}}},
		},
		HelmReleases: []k8s.HelmRelease{{Namespace: "cattle-system", Name: "rancher", ValuesYAML: "privateCA: true\ningress:\n  tls:\n    source: secret\n"}},
	}
	rs = Evaluate(Input{Snap: snap})
	expect := map[string]Status{"V-252843": Pass, "V-252844": Fail, "V-252845": Fail, "V-252846": Manual, "V-252847": Fail, "V-252849": Pass, "V-257292": Pass}
	for id, want := range expect {
		r := find(rs, id)
		if r == nil {
			t.Errorf("missing %s", id)
			continue
		}
		if r.Status != want {
			t.Errorf("%s: got %s (%s) want %s", id, r.Status, r.Detail, want)
		}
	}

	// fix the findings and open a port: audit level, defaults, single local admin, extra port, self-signed
	snap.Deployments[0].Spec.Template.Spec.Containers[0].Env[0].Value = "2"
	snap.Rancher.GlobalRoles["user"] = false
	snap.Rancher.Users = snap.Rancher.Users[:1]
	snap.NetPols[0].Spec.Ingress[0].Ports = append(snap.NetPols[0].Spec.Ingress[0].Ports, networkingv1.NetworkPolicyPort{Port: &port443})
	snap.HelmReleases[0].ValuesYAML = "ingress:\n  tls:\n    source: rancher\n"
	rs = Evaluate(Input{Snap: snap})
	expect = map[string]Status{"V-252844": Pass, "V-252845": Pass, "V-252847": Pass, "V-252849": Fail, "V-257292": Fail}
	for id, want := range expect {
		if r := find(rs, id); r == nil || r.Status != want {
			t.Errorf("%s: got %+v want %s", id, r, want)
		}
	}
	snap.Rancher.MgmtErr = "management.cattle.io: users: forbidden"
	snap.Rancher.Users, snap.Rancher.GlobalRoles = nil, nil
	rs = Evaluate(Input{Snap: snap})
	for _, id := range []string{"V-252845", "V-252847"} {
		if r := find(rs, id); r == nil || r.Status != Unknown {
			t.Errorf("%s without RBAC: got %+v want UNKNOWN", id, r)
		}
	}
}
