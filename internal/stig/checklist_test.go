package stig

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/stigdata"
)

func group(gs []ChecklistGroup, name string) *ChecklistGroup {
	for i := range gs {
		if gs[i].Name == name {
			return &gs[i]
		}
	}
	return nil
}

func TestChecklistMergesAndOrders(t *testing.T) {
	cfg := Target{Kind: TargetFile, Name: "/etc/rancher/rke2/config.yaml", Change: "kube-apiserver-arg: profiling=false"}
	rs := []Result{
		{ID: "CIS-1.2.15", Cat: "II", Status: Fail, Targets: []Target{cfg}, PerNode: map[string]Status{"cp-1": Fail, "cp-2": Pass}},
		{ID: "V-242409", Cat: "I", Status: Manual, Targets: []Target{cfg}, PerNode: map[string]Status{"cp-2": Manual}},
		{ID: "V-242390", Cat: "I", Status: Pass, Targets: []Target{cfg}},
		{ID: "V-242383", Cat: "I", Status: Fail, Targets: []Target{{Kind: TargetResource, Name: "Deployment default/web", Change: "move"}}},
		{ID: "V-242443", Cat: "II", Status: Manual, Group: "cluster", Fix: "upgrade"},
	}
	gs := Checklist(rs)
	if len(gs) != 3 || gs[0].Kind != TargetFile || gs[1].Kind != TargetResource || gs[2].Kind != TargetReview {
		t.Fatalf("groups: %+v", gs)
	}
	it := gs[0].Items
	if len(it) != 1 || strings.Join(it[0].IDs, ",") != "CIS-1.2.15,V-242409" || it[0].Cat != "I" || it[0].Status != Fail {
		t.Errorf("merged item: %+v", it)
	}
	if strings.Join(gs[0].Nodes, ",") != "cp-1,cp-2" {
		t.Errorf("nodes: %v", gs[0].Nodes)
	}
	if gs[2].Items[0].Change != "upgrade" {
		t.Errorf("review item falls back to the fix: %+v", gs[2].Items[0])
	}
}

func TestChecklistNarrowsToNamedFiles(t *testing.T) {
	r := Result{ID: "V-1", Status: Fail, Detail: "n1: /etc/shadow mode 0644 (want 0000 or stricter)", PerNode: map[string]Status{"n1": Fail},
		Targets: []Target{{Kind: TargetFile, Name: "/etc/shadow", Change: "chmod 0000"}, {Kind: TargetFile, Name: "/etc/gshadow", Change: "chmod 0000"}}}
	gs := Checklist([]Result{r})
	if len(gs) != 1 || gs[0].Name != "/etc/shadow" {
		t.Errorf("want only the failing file: %+v", gs)
	}
	// no path in a node-side detail: fall back to the path in the detail, else review
	gs = Checklist([]Result{{ID: "V-2", Group: "os", Status: Fail, Detail: "n1: 'x' not in /etc/issue"}})
	if len(gs) != 1 || gs[0].Name != "/etc/issue" {
		t.Errorf("detail path: %+v", gs)
	}
}

// sshd keeps the first value it reads and sshd_config includes the drop-ins
// at the top, so the fix goes to the drop-in that sets the wrong value.
func TestSSHDFixFollowsDropin(t *testing.T) {
	c := stigdata.Check{Template: "sshd_lineinfile", Params: map[string]any{"PARAMETER": "PermitRootLogin", "VALUE": "no"}}
	cf := func(p, s string) nodeinfo.ConfigFile { return nodeinfo.ConfigFile{Path: p, Content: s} }
	dropin := &nodeinfo.Info{SSHD: map[string][]string{"permitrootlogin": {"yes"}}, STIGFiles: []nodeinfo.ConfigFile{
		cf("/etc/ssh/sshd_config", "# comment\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n"),
		cf("/etc/ssh/sshd_config.d/10-other.conf", "Match User x\nPermitRootLogin no\n"),
		cf("/etc/ssh/sshd_config.d/50-redhat.conf", "PermitRootLogin yes\n"),
	}}
	main := &nodeinfo.Info{SSHD: map[string][]string{"permitrootlogin": {"yes"}}, STIGFiles: []nodeinfo.ConfigFile{
		cf("/etc/ssh/sshd_config", "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n"),
		cf("/etc/ssh/sshd_config.d/50-redhat.conf", "PermitRootLogin no\n"),
	}}
	st, d1 := evalSSHD(dropin, c, "")
	if st != Fail || !strings.HasSuffix(d1, " in /etc/ssh/sshd_config.d/50-redhat.conf") {
		t.Errorf("drop-in node: %v %q", st, d1)
	}
	_, d2 := evalSSHD(main, c, "")
	if !strings.HasSuffix(d2, " in /etc/ssh/sshd_config") {
		t.Errorf("main node: %q", d2)
	}
	r := Result{ID: "V-1", Status: Fail, Detail: "n1: " + d1 + "; n2: " + d2, PerNode: map[string]Status{"n1": Fail, "n2": Fail}, Targets: checkTargets(c)}
	var names []string
	for _, g := range Checklist([]Result{r}) {
		names = append(names, g.Name+"="+g.Items[0].Change)
	}
	if strings.Join(names, ",") != "/etc/ssh/sshd_config=PermitRootLogin no,/etc/ssh/sshd_config.d/50-redhat.conf=PermitRootLogin no" {
		t.Errorf("targets: %v", names)
	}
}

func TestComponentTarget(t *testing.T) {
	cases := []struct {
		dist  string
		r     Result
		file  string
		chg   string
		found bool
	}{
		{"rke2", Result{Group: "apiserver", Fix: "kube-apiserver-arg: anonymous-auth=false"}, "/etc/rancher/rke2/config.yaml", "kube-apiserver-arg: anonymous-auth=false", true},
		{"k3s", Result{Group: "rke2", Fix: "config.yaml: profile: cis"}, "/etc/rancher/k3s/config.yaml", "profile: cis", true},
		{"kubeadm", Result{Group: "apiserver", Fix: "kube-apiserver-arg: anonymous-auth=false"}, "/etc/kubernetes/manifests/kube-apiserver.yaml", "--anonymous-auth=false", true},
		{"kubeadm", Result{Group: "kubelet", Title: "kubelet anonymous authentication disabled", Fix: kubeletFix}, "/var/lib/kubelet/config.yaml", "kubelet anonymous authentication disabled", true},
		{"kubeadm", Result{Group: "apiserver", Fix: "rke2: secrets-encryption: true; kubeadm: --encryption-provider-config with aescbc"}, "/etc/kubernetes/manifests/kube-apiserver.yaml", "--encryption-provider-config with aescbc", true},
		{"kubeadm", Result{Group: "cluster", Fix: "upgrade"}, "", "", false},
		{"unknown", Result{Group: "apiserver", Fix: "kube-apiserver-arg: x=y"}, "", "", false},
	}
	for _, c := range cases {
		tg, ok := componentTarget(c.dist, c.r)
		if ok != c.found || tg.Name != c.file || tg.Change != c.chg {
			t.Errorf("%s %s: got %+v %v", c.dist, c.r.Fix, tg, ok)
		}
	}
}

func TestCheckTargets(t *testing.T) {
	cases := []struct {
		c    stigdata.Check
		name string
		chg  string
	}{
		{stigdata.Check{Template: "sysctl", Params: map[string]any{"SYSCTLVAR": "kernel.dmesg_restrict", "SYSCTLVAL": "1"}}, "/etc/sysctl.d/", "kernel.dmesg_restrict = 1"},
		{stigdata.Check{Template: "sshd_lineinfile", Params: map[string]any{"PARAMETER": "PermitRootLogin", "XCCDF_VARIABLE": "v"}, Resolved: map[string]string{"v": "no"}}, "/etc/ssh/sshd_config", "PermitRootLogin no"},
		{stigdata.Check{Template: "file_permissions", Params: map[string]any{"FILEPATH": "/etc/shadow", "FILEMODE": "0000"}}, "/etc/shadow", "chmod 0000"},
		{stigdata.Check{Template: "service_disabled", Params: map[string]any{"SERVICENAME": "kdump"}}, "systemd units", "systemctl mask --now kdump.service"},
		{stigdata.Check{Template: "kernel_module_disabled", Params: map[string]any{"KERNMODULE": "usb-storage"}}, "/etc/modprobe.d/", "install usb-storage /bin/false; blacklist usb-storage"},
	}
	for _, c := range cases {
		ts := checkTargets(c.c)
		if len(ts) != 1 || ts[0].Name != c.name || ts[0].Change != c.chg {
			t.Errorf("%s: %+v", c.c.Template, ts)
		}
	}
}

func TestEvaluateTargets(t *testing.T) {
	ctrl := true
	snap := &k8s.Snapshot{Distribution: "kubeadm", Pods: []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-cp-1", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}},
			Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "kube-apiserver", Args: []string{"kube-apiserver", "--profiling=true"}}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "web-7d9f-abcde", Namespace: "default", Labels: map[string]string{"pod-template-hash": "7d9f"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-7d9f", Controller: &ctrl}}}},
	}}
	gs := Checklist(Evaluate(Input{Snap: snap}))
	api := group(gs, "/etc/kubernetes/manifests/kube-apiserver.yaml")
	if api == nil || strings.Join(api.Nodes, ",") != "cp-1" {
		t.Fatalf("apiserver manifest group: %+v", gs)
	}
	var anon bool
	for _, it := range api.Items {
		if it.Change == "--anonymous-auth=false" {
			anon = true
		}
	}
	if !anon {
		t.Errorf("--anonymous-auth=false missing: %+v", api.Items)
	}
	if web := group(gs, "Deployment default/web"); web == nil || web.Kind != TargetResource {
		t.Errorf("pod in default should land on its Deployment: %+v", gs)
	}
}
