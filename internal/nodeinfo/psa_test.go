package nodeinfo

import (
	"strings"
	"testing"
	"time"
)

const rke2PSS = `apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: "restricted"
        enforce-version: "latest"
        audit: "restricted"
        warn: "restricted"
      exemptions:
        usernames: []
        runtimeClasses: []
        namespaces:
          - kube-system
          - cis-operator-system
          - tigera-operator
          - my-app
`

func TestParsePSA(t *testing.T) {
	p := ParsePSA("/etc/rancher/rke2/rke2-pss.yaml", rke2PSS)
	if p == nil {
		t.Fatal("not parsed")
	}
	if p.Path != "/etc/rancher/rke2/rke2-pss.yaml" || p.EnforceLevel() != "restricted" || p.Audit != "restricted" || p.External != "" {
		t.Errorf("%+v", p)
	}
	if strings.Join(p.ExemptNamespaces, ",") != "kube-system,cis-operator-system,tigera-operator,my-app" || !p.Exempt("my-app") || p.Exempt("default") {
		t.Errorf("exemptions: %v", p.ExemptNamespaces)
	}
	// no defaults = upstream privileged; plugin config kept in another file
	ext := "kind: AdmissionConfiguration\nplugins:\n- name: PodSecurity\n  path: /etc/rancher/rke2/pss-plugin.yaml\n"
	if p := ParsePSA("/x", ext); p == nil || p.EnforceLevel() != "privileged" || p.External != "/etc/rancher/rke2/pss-plugin.yaml" {
		t.Errorf("external plugin config: %+v", p)
	}
	// other files in the extra dump are not admission configs
	if ParsePSA("/etc/rancher/rke2/audit-policy.yaml", "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: Metadata\n") != nil {
		t.Error("audit policy parsed as PSA")
	}
	if ParsePSA("/x", "kind: AdmissionConfiguration\nplugins:\n- name: EventRateLimit\n") != nil {
		t.Error("no PodSecurity plugin")
	}
}

func TestEffectivePSA(t *testing.T) {
	a := &PSAConfig{Path: "/etc/rancher/rke2/rke2-pss.yaml", Enforce: "restricted"}
	b := &PSAConfig{Path: "/etc/rancher/rke2/custom.yaml", Enforce: "baseline"}
	infos := map[string]*Info{
		"cp-1": {ControlPlane: true, PSA: []*PSAConfig{a, b}},
		"cp-2": {ControlPlane: true, PSA: []*PSAConfig{a, b}},
		"w-1":  {},
	}
	// the apiserver flag decides between the files on disk
	if got := EffectivePSA(infos, map[string]string{"cp-1": "/etc/rancher/rke2/custom.yaml", "cp-2": "/etc/rancher/rke2/custom.yaml"}); got != b {
		t.Errorf("by flag: %+v", got)
	}
	// two candidate files and no flag match: unknown
	if got := EffectivePSA(infos, nil); got != nil {
		t.Errorf("ambiguous: %+v", got)
	}
	// one file everywhere: that one, flag or not
	infos["cp-1"].PSA, infos["cp-2"].PSA = []*PSAConfig{a}, []*PSAConfig{a}
	if got := EffectivePSA(infos, map[string]string{"cp-1": "/etc/kubernetes/psa.yaml"}); got != a {
		t.Errorf("single file: %+v", got)
	}
	if EffectivePSA(map[string]*Info{"w-1": {}}, nil) != nil {
		t.Error("nothing read")
	}
}

func TestParseExtraFilesPSA(t *testing.T) {
	out := "===HARDENING\nconfig_probed=yes\n===RKE2EXTRA\n--- /etc/rancher/rke2/rke2-pss.yaml\n" + rke2PSS + "--- listing /etc/rancher/rke2\n-rw------- 1 root root 1 Jan 1 00:00 config.yaml\n===END\n"
	info := Parse("n", "h", out, time.Now())
	if len(info.PSA) != 1 || info.PSA[0].Path != "/etc/rancher/rke2/rke2-pss.yaml" || !info.PSA[0].Exempt("my-app") {
		t.Errorf("PSA from the extra dump: %+v", info.PSA)
	}
	// carried forward by the light cycles like the files themselves
	light := Parse("n", "h", "===HOST\nh\n===END\n", time.Now())
	light.MergeConfig(info)
	if len(light.PSA) != 1 {
		t.Error("PSA not carried forward")
	}
}
