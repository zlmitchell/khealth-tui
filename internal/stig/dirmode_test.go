package stig

import (
	"strings"
	"testing"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/stigdata"
)

// V-258171 as carried by the RHEL 9 table: FILE_REGEX is a list parallel to
// FILEPATH, and the targets are the audit config files, not the directories.
func auditConfCheck() stigdata.Check {
	return chk("file_permissions", map[string]any{
		"FILEPATH":     []any{"/etc/audit/", "/etc/audit/rules.d/"},
		"FILE_REGEX":   []any{`^.*audit(\.rules|d\.conf)$`, `^.*\.rules$`},
		"FILEMODE":     "0600",
		"IS_DIRECTORY": true,
		"RECURSIVE":    false,
	}, nil)
}

func TestFileRegexTargetsFilesNotDirectory(t *testing.T) {
	n := &nodeinfo.Info{Node: "n", STIGProbed: true,
		STIGStat: map[string]nodeinfo.Perm{
			"/etc/audit":             {Mode: "750", Type: "directory"},
			"/etc/audit/rules.d":     {Mode: "750", Type: "directory"},
			"/etc/ssh":               {Mode: "755", Type: "directory"},
			"/etc/ssh/sshd_config.d": {Mode: "700", Type: "directory"},
		},
		STIGViol: map[string][]string{},
	}
	c := auditConfCheck()
	if st, d := evalFilePermissions(n, c, "V-258171:0"); st != Pass {
		t.Errorf("0750 audit dirs with compliant files must pass, got %s (%s)", st, d)
	}
	n.STIGViol["V-258171:0"] = []string{"/etc/audit/rules.d/audit.rules"}
	if st, d := evalFilePermissions(n, c, "V-258171:0"); st != Fail || !strings.Contains(d, "audit.rules") {
		t.Errorf("violating rules file must fail, got %s (%s)", st, d)
	}
	// V-258001: .pub keys 0644 must not demand /etc/ssh itself at 0644
	pub := chk("file_permissions", map[string]any{"FILEPATH": []any{"/etc/ssh/"}, "FILE_REGEX": []any{`^.*\.pub$`}, "FILEMODE": "0644", "IS_DIRECTORY": true}, nil)
	if st, d := evalFilePermissions(n, pub, "V-258001:0"); st != Pass {
		t.Errorf("/etc/ssh 0755 must not fail the .pub check, got %s (%s)", st, d)
	}
	// the directory-itself rule (no FILE_REGEX) still stats the directory
	dir := chk("file_permissions", map[string]any{"FILEPATH": []any{"/etc/ssh/sshd_config.d/"}, "FILEMODE": "0700", "IS_DIRECTORY": true}, nil)
	if st, _ := evalFilePermissions(n, dir, "V-257999:1"); st != Pass {
		t.Errorf("sshd_config.d 0700 should pass")
	}
	n.STIGStat["/etc/ssh/sshd_config.d"] = nodeinfo.Perm{Mode: "755", Type: "directory"}
	if st, _ := evalFilePermissions(n, dir, "V-257999:1"); st != Fail {
		t.Errorf("sshd_config.d 0755 should fail the 0700 directory rule")
	}
}

func TestFileRegexScanAndFix(t *testing.T) {
	c := auditConfCheck()
	s, ok := stigdata.FileScan(c, 1)
	if !ok || s.Type != "f" || s.Dirs[0] != "/etc/audit/rules.d" ||
		!strings.Contains(s.Expr, `-regex '/etc/audit/rules.d/(.*\.rules)'`) || !strings.Contains(s.Expr, "-perm /7177") {
		t.Fatalf("scan: %+v", s)
	}
	ts := checkTargets(c)
	if len(ts) != 2 {
		t.Fatalf("targets: %+v", ts)
	}
	for _, tg := range ts {
		if !strings.HasPrefix(tg.Change, "find /etc/audit") || !strings.Contains(tg.Change, "-type f") ||
			!strings.HasSuffix(tg.Change, "-exec chmod u-xs,g-rwxs,o-rwxt {} +") {
			t.Errorf("%s: fix must chmod matching files only, got %q", tg.Name, tg.Change)
		}
	}
	// recursive directory rule: scans directories, never a numeric chmod -R
	lib := chk("file_permissions", map[string]any{"FILEPATH": []any{"/lib/"}, "FILEMODE": "7755", "IS_DIRECTORY": true, "RECURSIVE": true}, nil)
	if ts := checkTargets(lib); len(ts) != 1 || !strings.Contains(ts[0].Change, "-type d") || !strings.HasSuffix(ts[0].Change, "-exec chmod g-w,o-w {} +") {
		t.Errorf("lib dirs: %+v", ts)
	}
	// recursive + regex (Ubuntu /var/log 0640): files only, so dirs keep x
	vl := chk("file_permissions", map[string]any{"FILEPATH": []any{"/var/log/"}, "FILEMODE": "0640", "IS_DIRECTORY": true, "RECURSIVE": "true", "FILE_REGEX": []any{".*"}}, nil)
	if s, ok := stigdata.FileScan(vl, 0); !ok || s.Type != "f" || strings.Contains(s.Expr, "maxdepth") || strings.Contains(s.Expr, "-regex") {
		t.Errorf("var log scan: %+v", s)
	}
}

func TestStripModeBits(t *testing.T) {
	for in, want := range map[string]string{"0600": "u-xs,g-rwxs,o-rwxt", "0755": "u-s,g-ws,o-wt", "7755": "g-w,o-w", "0640": "u-xs,g-wxs,o-rwxt", "2750": "u-s,g-w,o-rwxt", "x": "x"} {
		if got := stripModeBits(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

// No embedded file_permissions rule may stat a directory against a mode
// without the owner execute bit.
func TestNoDirectoryGetsFileMode(t *testing.T) {
	for _, prod := range stigdata.Products() {
		tb, err := stigdata.Load(prod)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range tb.Rules {
			for _, c := range r.Checks {
				if c.Template != "file_permissions" {
					continue
				}
				m, ok := modeBits(c.Str("FILEMODE"))
				if !ok || m&0100 != 0 {
					continue
				}
				for i, fp := range c.List("FILEPATH") {
					if _, scanned := stigdata.FileScan(c, i); !scanned && (c.Bool("IS_DIRECTORY") || strings.HasSuffix(fp, "/")) {
						t.Errorf("%s %s %s: directory %s checked against %s", prod, r.VID, c.Rule, fp, c.Str("FILEMODE"))
					}
				}
			}
		}
	}
}
