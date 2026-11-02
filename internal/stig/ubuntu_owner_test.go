package stig

import (
	"strings"
	"testing"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/stigdata"
)

// ubuntuRule returns one rule of the embedded Ubuntu 24.04 table.
func ubuntuRule(t *testing.T, vid string) stigdata.Rule {
	t.Helper()
	tb, err := stigdata.Load("ubuntu2404")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range tb.Rules {
		if r.VID == vid {
			return r
		}
	}
	t.Fatalf("%s not in the ubuntu2404 table", vid)
	return stigdata.Rule{}
}

// hardenedUbuntu is an Ubuntu 24.04 node as the lab nodes are after the
// STIG chart: /var/log 0755 root:syslog, /var/log/syslog 0640 syslog:adm,
// /var/log/audit 0700 root:root with log_group = root.
func hardenedUbuntu() *nodeinfo.Info {
	return &nodeinfo.Info{
		Node: "u1", STIGProbed: true,
		OS: nodeinfo.OSRelease{ID: "ubuntu", VersionID: "24.04"},
		STIGStat: map[string]nodeinfo.Perm{
			"/var/log":        {Path: "/var/log", Mode: "755", User: "root", Group: "syslog", UID: "0", GID: "102", Type: "directory"},
			"/var/log/syslog": {Path: "/var/log/syslog", Mode: "640", User: "syslog", Group: "adm", UID: "102", GID: "4", Type: "regular file"},
		},
		STIGFiles: []nodeinfo.ConfigFile{{Path: "/etc/audit/auditd.conf", Content: "log_file = /var/log/audit/audit.log\nlog_group = root\n"}},
		STIGSweep: map[string][]string{"AUDITDIR": {"/var/log/audit|700|root|root"}},
	}
}

// V-270765 carries GID_OR_NAME "syslog" with GROUP_REPRESENTED_WITH_GID
// true; V-270768 / V-270769 carry the CAC alternations "adm|root" and
// "syslog|root". All three failed on every node that was right.
func TestUbuntuLogOwnershipRules(t *testing.T) {
	n := hardenedUbuntu()
	for _, vid := range []string{"V-270765", "V-270768", "V-270769"} {
		if st, d := evalTemplated(n, ubuntuRule(t, vid)); st != Pass {
			t.Errorf("%s on a compliant node: %s %s", vid, st, d)
		}
	}
	// still a finding when the owner is wrong
	n.STIGStat["/var/log"] = nodeinfo.Perm{Path: "/var/log", Mode: "755", User: "root", Group: "root", UID: "0", GID: "0"}
	n.STIGStat["/var/log/syslog"] = nodeinfo.Perm{Path: "/var/log/syslog", Mode: "640", User: "nobody", Group: "users", UID: "65534", GID: "100"}
	for _, vid := range []string{"V-270765", "V-270768", "V-270769"} {
		if st, d := evalTemplated(n, ubuntuRule(t, vid)); st != Fail {
			t.Errorf("%s on a wrong owner: %s %s", vid, st, d)
		}
	}
	// the CAC alternative (root) is accepted, as the CAC OVAL does
	n.STIGStat["/var/log/syslog"] = nodeinfo.Perm{Path: "/var/log/syslog", Mode: "640", User: "root", Group: "root", UID: "0", GID: "0"}
	for _, vid := range []string{"V-270768", "V-270769"} {
		if st, d := evalTemplated(n, ubuntuRule(t, vid)); st != Pass {
			t.Errorf("%s with the CAC alternative root: %s %s", vid, st, d)
		}
	}
}

func TestOwnerAlternativesAndIDs(t *testing.T) {
	n := probedNode() // /etc/shadow root:root 0:0
	cases := []struct {
		name string
		c    stigdata.Check
		want Status
	}{
		{"numeric gid flag, numeric value", chk("file_groupowner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "GID_OR_NAME": "0", "GROUP_REPRESENTED_WITH_GID": true}, nil), Pass},
		{"gid flag, name value", chk("file_groupowner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "GID_OR_NAME": "root", "GROUP_REPRESENTED_WITH_GID": true}, nil), Pass},
		{"name flag, numeric value", chk("file_groupowner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "GID_OR_NAME": "0"}, nil), Pass},
		{"group alternation hit", chk("file_groupowner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "GID_OR_NAME": "shadow|root"}, nil), Pass},
		{"group alternation miss", chk("file_groupowner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "GID_OR_NAME": "shadow|adm"}, nil), Fail},
		{"owner alternation", chk("file_owner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "UID_OR_NAME": "syslog|root"}, nil), Pass},
		{"owner uid flag, name value", chk("file_owner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "UID_OR_NAME": "root", "OWNER_REPRESENTED_WITH_UID": true}, nil), Pass},
		{"owner miss", chk("file_owner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "UID_OR_NAME": "syslog"}, nil), Fail},
	}
	for _, c := range cases {
		ev := templateEvals[c.c.Template]
		if st, d := ev(n, c.c, "V-x:0"); st != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, st, d, c.want)
		}
	}
}

// The recursive scans and the fix commands built from them must use the
// alternatives as alternatives and never fall back to a literal.
func TestOwnerScanAndFix(t *testing.T) {
	grp := chk("file_groupowner", map[string]any{"FILEPATH": []any{"/var/log/"}, "GID_OR_NAME": "adm|root", "RECURSIVE": true}, nil)
	s, ok := stigdata.FileScan(grp, 0)
	if !ok || !strings.Contains(s.Expr, "! -group adm ! -group root") {
		t.Errorf("group alternation scan: %+v %v", s, ok)
	}
	byName := chk("file_groupowner", map[string]any{"FILEPATH": []any{"/var/log/"}, "GID_OR_NAME": "syslog", "GROUP_REPRESENTED_WITH_GID": true, "RECURSIVE": true}, nil)
	if s, _ := stigdata.FileScan(byName, 0); !strings.Contains(s.Expr, "! -group syslog") || strings.Contains(s.Expr, "-gid") {
		t.Errorf("a name with the gid flag must scan by name: %q", s.Expr)
	}
	byID := chk("file_owner", map[string]any{"FILEPATH": []any{"/etc/"}, "UID_OR_NAME": "0", "RECURSIVE": true}, nil)
	if s, _ := stigdata.FileScan(byID, 0); !strings.Contains(s.Expr, "! -uid 0") {
		t.Errorf("a numeric owner must scan by uid: %q", s.Expr)
	}
	for vid, want := range map[string]string{"V-270768": "chgrp adm", "V-270769": "chown syslog", "V-270765": "chgrp syslog"} {
		tg := ruleTargets(ubuntuRule(t, vid))
		if len(tg) == 0 || tg[0].Change != want {
			t.Errorf("%s fix: %+v, want %q", vid, tg, want)
		}
	}
}

// V-270756: CAC's EXCLUDED_FILES (wtmp, btmp, lastlog: 0660/0664 by design)
// stay out of the /var/log scan and its fix; everything else (Calico's
// 0644 svlogd files) is still scanned.
func TestExcludedFilesHonoured(t *testing.T) {
	r := ubuntuRule(t, "V-270756")
	s, ok := stigdata.FileScan(r.Checks[0], 0)
	if !ok {
		t.Fatal("V-270756 must be a find scan")
	}
	for _, g := range []string{"[bw]tmp", "[bw]tmp.*", "[bw]tmp-*", "lastlog", "lastlog.*"} {
		if !strings.Contains(s.Expr, "! -name '"+g+"'") {
			t.Errorf("scan does not exclude %s: %q", g, s.Expr)
		}
	}
	if !strings.Contains(s.Expr, "-perm /7137") {
		t.Errorf("scan lost its mode test: %q", s.Expr)
	}
	if !strings.Contains(stigdata.ProbeScript(), s.Expr) {
		t.Errorf("the node probe does not run the excluding scan")
	}
	tg := ruleTargets(r)
	if len(tg) == 0 || !strings.Contains(tg[0].Change, "! -name 'lastlog'") {
		t.Errorf("fix would chmod the excluded files: %+v", tg)
	}
	// every table: an EXCLUDED_FILES parameter always reaches the scan
	for _, p := range stigdata.Products() {
		tb, _ := stigdata.Load(p)
		for _, rule := range tb.Rules {
			for _, c := range rule.Checks {
				ex := c.ExcludedFiles()
				if len(ex) == 0 {
					continue
				}
				for i := range c.List("FILEPATH") {
					if s, ok := stigdata.FileScan(c, i); ok && !strings.Contains(s.Expr, "! -name '"+ex[0]+"'") {
						t.Errorf("%s %s: excluded files not in the scan: %q", p, rule.VID, s.Expr)
					}
				}
			}
		}
	}
}

// V-270830: the Ubuntu STIG wants 0750 or less permissive (CAC's 0700 is
// its value for log_group = root); a missing sweep line is "not
// collected", never a FAIL.
func TestAuditLogDirMode(t *testing.T) {
	rule := ubuntuRule(t, "V-270830")
	n := hardenedUbuntu()
	for mode, want := range map[string]Status{"700": Pass, "750": Pass, "755": Fail, "770": Fail} {
		n.STIGSweep["AUDITDIR"] = []string{"/var/log/audit|" + mode + "|root|root"}
		if st, d := evalTemplated(n, rule); st != want {
			t.Errorf("ubuntu mode %s: %s %s, want %s", mode, st, d, want)
		}
	}
	delete(n.STIGSweep, "AUDITDIR")
	if st, _ := evalTemplated(n, rule); st == Fail || st == Pass {
		t.Errorf("no AUDITDIR line (sweep cut short) must not be scored, got %s", st)
	}
	n.STIGSweep["AUDITDIRNONE"] = []string{"/var/log/audit"}
	if st, _ := evalTemplated(n, rule); st != Fail {
		t.Errorf("a missing audit log directory is a finding, got %s", st)
	}
	// RHEL keeps 0700 while log_group is root, 0750 for another group
	rh := hardenedNode()
	ev := namedEvals["directory_permissions_var_log_audit"]
	rh.STIGSweep["AUDITDIR"] = []string{"/var/log/audit|750|root|root"}
	if st, _ := ev(rh); st != Fail {
		t.Errorf("rhel 0750 with log_group root: %s", st)
	}
	files := []nodeinfo.ConfigFile{cf("/etc/audit/auditd.conf", "log_file = /var/log/audit/audit.log\nlog_group = wheel\n")}
	for _, f := range rh.STIGFiles {
		if f.Path != "/etc/audit/auditd.conf" {
			files = append(files, f)
		}
	}
	rh.STIGFiles = files
	if st, _ := ev(rh); st != Pass {
		t.Errorf("rhel 0750 with log_group wheel: %s", st)
	}
}

// A node whose OS STIG collection failed is reported as not scanned on
// every OS rule; it never disappears and its rules never pass.
func TestUnscannedNodeVisible(t *testing.T) {
	snap := &k8s.Snapshot{Distribution: "kubeadm"}
	u := func(name string) *nodeinfo.Info {
		n := hardenedUbuntu()
		n.Node = name
		return n
	}
	failed := &nodeinfo.Info{Node: "u3", OS: nodeinfo.OSRelease{ID: "ubuntu", VersionID: "24.04"}, STIGErr: "sweep stage: context deadline exceeded"}
	rs := Evaluate(Input{Snap: snap, Nodes: map[string]*nodeinfo.Info{"u1": u("u1"), "u2": u("u2"), "u3": failed}})
	r := find(rs, "V-270765")
	if r == nil || r.PerNode["u3"] != Unknown || r.Status != Unknown || !strings.Contains(r.Detail, "not scanned") {
		t.Fatalf("partially scanned cluster: %+v", r)
	}
	// none answered: the benchmark is still there, every rule not scanned
	failed2 := &nodeinfo.Info{Node: "u1", OS: nodeinfo.OSRelease{ID: "ubuntu", VersionID: "24.04"}, STIGErr: "files stage: EOF"}
	rs = Evaluate(Input{Snap: snap, Nodes: map[string]*nodeinfo.Info{"u1": failed2}})
	if r := find(rs, "V-270765"); r == nil || r.Status != Unknown {
		t.Fatalf("no node scanned: the OS benchmark must still be reported, got %+v", r)
	}
	// the node probe failed too (OS unknown): its own row
	rs = Evaluate(Input{Snap: snap, Nodes: map[string]*nodeinfo.Info{"u1": {Node: "u1", Err: errString("dial tcp: i/o timeout"), STIGErr: "node unreachable"}}})
	if r := find(rs, "OS-scan"); r == nil || r.Status != Unknown {
		t.Fatalf("unreachable node: %+v", r)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
