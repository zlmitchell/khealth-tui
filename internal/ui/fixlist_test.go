package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/stig"
)

// The Fix list sub-tab regroups the open rules by file / object: a node
// with no hardening facts fails most of the RHEL 9 STIG, which must land
// under the files the ComplianceAsCode templates name, and the kubeadm
// apiserver flags under its static pod manifest.
func TestFixListTab(t *testing.T) {
	a := testApp()
	a.secScanned = true
	snap := &k8s.Snapshot{Distribution: "kubeadm", Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-cp-1", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}},
		Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "kube-apiserver", Args: []string{"kube-apiserver", "--profiling=true"}}}}}}}
	nodes := map[string]*nodeinfo.Info{"cp-1": {Node: "cp-1", Dist: "kubeadm", OS: nodeinfo.OSRelease{ID: "rocky", VersionID: "9.6", IDLike: "rhel centos fedora"}, STIGProbed: true}}
	a.stigRes = stig.Evaluate(stig.Input{Snap: snap, Nodes: nodes})
	a.fixList = stig.Checklist(a.stigRes)
	a.tab = tabSecurity
	for i, s := range subTabs[tabSecurity] {
		if s == "Fix list" {
			a.sub[tabSecurity] = i
		}
	}
	c := a.securityContent()
	var text []string
	for _, r := range c.rows {
		text = append(text, ansi.Strip(r.text))
	}
	all := strings.Join(text, "\n")
	for _, want := range []string{"/etc/kubernetes/manifests/kube-apiserver.yaml", "--anonymous-auth=false", "/etc/ssh/sshd_config", "/etc/sysctl.d/", "then sysctl --system", "/etc/audit/rules.d/", "packages: install", "systemd units"} {
		if !strings.Contains(all, want) {
			t.Errorf("fix list lacks %q", want)
		}
	}
	// selectable rows open the rule they came from
	for _, r := range c.rows {
		if r.id == "" {
			continue
		}
		if id, lines := a.securityDetail(r.id); id == "" || len(lines) == 0 {
			t.Errorf("row %q has no detail", r.id)
		}
		break
	}
	a.hideManual = true
	if n := len(a.securityContent().rows); n >= len(c.rows) {
		t.Errorf("m should hide manual items: %d rows, was %d", n, len(c.rows))
	}
	if testing.Verbose() {
		t.Log("\n" + strings.Join(append(c.header, text...), "\n"))
	}
}
