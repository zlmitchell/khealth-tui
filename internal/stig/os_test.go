package stig

import (
	"strings"
	"testing"

	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
)

// TestOSGroupWaitsForCollection: before S (no OS STIG facts) the OS group is
// empty on every OS, matched to a benchmark or not; the generic reboot /
// secure-boot checks must not sneak in from the regular probe.
func TestOSGroupWaitsForCollection(t *testing.T) {
	for _, os := range []nodeinfo.OSRelease{{ID: "rocky", VersionID: "9.7", IDLike: "rhel centos fedora"}, {ID: "ubuntu", VersionID: "24.04"}, {ID: "sles", VersionID: "15.6", IDLike: "suse"}} {
		in := Input{Snap: &k8s.Snapshot{Distribution: "rke2"}, Nodes: map[string]*nodeinfo.Info{
			"n1": {Node: "n1", OS: os, Hardening: map[string]string{"reboot_required": "yes", "secureboot": "disabled"}},
		}}
		for _, r := range Evaluate(in) {
			if r.Group == "os" {
				t.Errorf("%s: OS row %s emitted before the facts were collected", os.ID, r.ID)
			}
		}
		in.Nodes["n1"].STIGProbed = true
		n := 0
		for _, r := range Evaluate(in) {
			if r.Group == "os" {
				n++
			}
		}
		if n == 0 {
			t.Errorf("%s: no OS rows after collection", os.ID)
		}
	}
}

// TestBenchmarksOnlyWhereTheyApply: a kubeadm cluster without Rancher gets
// no RKE2 STIG and no Rancher MCM STIG rows at all (not even N/A ones).
func TestBenchmarksOnlyWhereTheyApply(t *testing.T) {
	in := Input{Snap: &k8s.Snapshot{Distribution: "kubeadm"}, Nodes: map[string]*nodeinfo.Info{
		"n1": {Node: "n1", Dist: "kubeadm", OS: nodeinfo.OSRelease{ID: "ubuntu", VersionID: "24.04"}, STIGProbed: true},
	}}
	for _, r := range Evaluate(in) {
		for _, b := range Benchmarks {
			if b.Matches(r.ID) && (strings.Contains(b.Name, "RKE2") || strings.Contains(b.Name, "MCM")) {
				t.Errorf("%s rule %s emitted on a kubeadm cluster without Rancher", b.Name, r.ID)
			}
		}
	}
}
