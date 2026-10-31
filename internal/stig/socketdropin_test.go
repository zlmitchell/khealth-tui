package stig

import (
	"testing"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// V-258125: pcscd runs --auto-exit behind its socket, so the service is idle and inactive; the socket
// enabled and active passes, as the STIG's own check (systemctl is-active pcscd.socket) does
func TestServiceEnabledSocketActivated(t *testing.T) {
	n := probedNode()
	n.UnitFiles["pcscd.service"] = "indirect"
	n.UnitStates["pcscd.service"] = nodeinfo.UnitState{Load: "loaded", Active: "inactive", Sub: "dead"}
	c := chk("service_enabled", map[string]any{"SERVICENAME": "pcscd"}, nil)
	if st, msg := evalServiceEnabled(n, c, ""); st != Fail {
		t.Fatalf("socket not active yet: got %v %q, want Fail", st, msg)
	}
	n.UnitFiles["pcscd.socket"] = "enabled"
	n.UnitStates["pcscd.socket"] = nodeinfo.UnitState{Load: "loaded", Active: "active", Sub: "listening"}
	if st, msg := evalServiceEnabled(n, c, ""); st != Pass {
		t.Fatalf("socket enabled and active: got %v %q, want Pass", st, msg)
	}
	n.UnitFiles["pcscd.socket"] = "disabled"
	if st, _ := evalServiceEnabled(n, c, ""); st != Fail {
		t.Fatalf("socket disabled: got %v, want Fail", st)
	}
}

// V-257949: VALUE "none|default" is a regular expression in the CaC template, not a literal value
func TestSystemdDropinValueRegex(t *testing.T) {
	c := chk("systemd_dropin_configuration", map[string]any{"MASTER_CFG_FILE": "/etc/NetworkManager/NetworkManager.conf",
		"DROPIN_DIR": "/etc/NetworkManager/conf.d", "SECTION": "main", "PARAM": "dns", "VALUE": "none|default"}, nil)
	for _, tc := range []struct {
		val  string
		want Status
	}{{"default", Pass}, {"none", Pass}, {"dnsmasq", Fail}, {"defaults", Fail}} {
		n := probedNode()
		n.STIGFiles = append(n.STIGFiles,
			nodeinfo.ConfigFile{Path: "/etc/NetworkManager/NetworkManager.conf", Content: "[main]\n"},
			nodeinfo.ConfigFile{Path: "/etc/NetworkManager/conf.d/90-stig-dns.conf", Content: "[main]\ndns=" + tc.val + "\n"})
		if st, msg := evalSystemdDropin(n, c, ""); st != tc.want {
			t.Errorf("dns=%s: got %v %q, want %v", tc.val, st, msg, tc.want)
		}
	}
}
