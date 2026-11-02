package stigdata

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The node probe is one static POSIX script sent to every node, so the
// data-derived part is the union over all embedded products: a stat of every
// file the tables name, a find for violators under every directory checked
// recursively, and a dump of every config file a template reads. Output
// sections (see nodeinfo): STIGSTAT, STIGVIOL, STIGFILES.

var safeShellPath = regexp.MustCompile(`^/[A-Za-z0-9_./@:+-]*$`)

// FileDumps are config files read by evaluators regardless of template
// parameters (pwquality/faillock/pam for accounts_password and
// pam_account_password_faillock, auditd.conf, grub defaults).
var FileDumps = []string{
	"/etc/security/pwquality.conf",
	"/etc/security/pwquality.conf.d/*.conf",
	"/etc/security/faillock.conf",
	"/etc/security/limits.conf",
	"/etc/security/limits.d/*.conf",
	"/etc/pam.d/system-auth",
	"/etc/pam.d/password-auth",
	"/etc/pam.d/common-auth",
	"/etc/pam.d/common-password",
	"/etc/pam.d/common-account",
	"/etc/audit/auditd.conf",
	"/etc/default/grub",
	"/etc/selinux/config",
	// read by the named (custom OVAL) evaluators in internal/stig/osnamed.go
	"/etc/login.defs",
	"/etc/default/useradd",
	"/etc/libuser.conf",
	"/etc/profile",
	"/etc/profile.d/*.sh",
	"/etc/bashrc",
	"/etc/bash.bashrc",
	"/etc/csh.cshrc",
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/etc/rsyslog.conf",
	"/etc/rsyslog.d/*.conf",
	"/etc/chrony.conf",
	"/etc/chrony/chrony.conf",
	"/etc/chrony/conf.d/*.conf",
	"/etc/chrony/sources.d/*.sources",
	"/etc/dnf/dnf.conf",
	"/etc/yum.repos.d/*.repo",
	"/etc/apt/apt.conf.d/*",
	"/etc/systemd/system.conf",
	"/etc/systemd/system.conf.d/*.conf",
	"/etc/systemd/logind.conf",
	"/etc/systemd/logind.conf.d/*.conf",
	"/etc/issue",
	"/etc/issue.net",
	"/etc/gdm/custom.conf",
	"/etc/gdm3/custom.conf",
	"/etc/aide.conf",
	"/etc/aide/aide.conf",
	"/etc/crypto-policies/back-ends/opensshserver.config",
	"/etc/crypto-policies/back-ends/openssh.config",
	"/etc/crypto-policies/state/CURRENT.pol",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*.conf",
	"/etc/ssh/ssh_config",
	"/etc/ssh/ssh_config.d/*.conf",
	"/etc/resolv.conf",
	"/etc/postfix/main.cf",
	"/etc/aliases",
	"/etc/pam_pkcs11/pam_pkcs11.conf",
	"/etc/fapolicyd/fapolicyd.conf",
	"/etc/tmpfiles.d/*.conf",
}

// FindScan is one recursive violation scan.
type FindScan struct {
	ID   string // CheckID
	Expr string // find expression after the path
	Type string // f or d
	Dirs []string
}

// Derived is the union of probe targets over the embedded tables.
type Derived struct {
	Stat  []string   // files/dirs to stat individually
	Scans []FindScan // recursive scans
	Dumps []string   // files (or globs) to dump
}

// Derive computes the probe targets from every embedded product.
func Derive() Derived {
	stat, dumps := map[string]bool{}, map[string]bool{}
	for _, d := range FileDumps {
		dumps[d] = true
	}
	var scans []FindScan
	for _, p := range Products() {
		t, err := Load(p)
		if err != nil {
			continue
		}
		for _, r := range t.Rules {
			for i, c := range r.Checks {
				id := CheckID(r.VID, i)
				switch c.Template {
				case "file_permissions", "file_owner", "file_groupowner", "file_existence":
					for j, fp := range c.List("FILEPATH") {
						if !safeShellPath.MatchString(fp) {
							continue
						}
						if scan, ok := FileScan(c, j); ok {
							scan.ID = id
							scans = append(scans, scan)
						} else {
							stat[fp] = true
						}
					}
				case "key_value_pair_in_file", "lineinfile", "shell_lineinfile", "pam_options":
					dumps[c.Str("PATH")] = true
				case "systemd_dropin_configuration":
					dumps[c.Str("MASTER_CFG_FILE")] = true
					if d := c.Str("DROPIN_DIR"); d != "" {
						dumps[strings.TrimRight(d, "/")+"/*.conf"] = true
					}
				case "dconf_ini_file":
					if d := c.Str("PATH"); d != "" {
						dumps[strings.TrimRight(d, "/")+"/*"] = true
					}
					if d := c.Str("LOCK_PATH"); d != "" {
						dumps[strings.TrimRight(d, "/")+"/*"] = true
					}
				}
			}
		}
	}
	out := Derived{Scans: scans}
	for p := range stat {
		out.Stat = append(out.Stat, p)
	}
	for p := range dumps {
		if p != "" && safeShellPath.MatchString(strings.ReplaceAll(p, "*", "x")) {
			out.Dumps = append(out.Dumps, p)
		}
	}
	sort.Strings(out.Stat)
	sort.Strings(out.Dumps)
	sort.Slice(out.Scans, func(i, j int) bool { return out.Scans[i].ID < out.Scans[j].ID })
	return out
}

// FileScan turns the i-th FILEPATH of a recursive or regex-in-directory file
// check into a find expression that prints only violators (ID left empty).
// Returns false when a plain stat of the path is enough.
//
// CAC semantics: with FILE_REGEX the targets are the regular files in the
// directory whose names match (never the directory itself); with RECURSIVE
// and no FILE_REGEX the targets are the directory and its subdirectories.
func FileScan(c Check, i int) (FindScan, bool) {
	fps := c.List("FILEPATH")
	if i < 0 || i >= len(fps) {
		return FindScan{}, false
	}
	recursive := c.Bool("RECURSIVE")
	regex := c.FileRegex(i)
	if !recursive && regex == "" {
		return FindScan{}, false
	}
	dir := strings.TrimRight(fps[i], "/")
	scan := FindScan{Dirs: []string{dir}, Type: "f"}
	if regex == "" && c.Bool("IS_DIRECTORY") {
		scan.Type = "d"
	}
	var expr []string
	if !recursive {
		expr = append(expr, "-maxdepth 1")
	}
	expr = append(expr, "-type "+scan.Type)
	if re := strings.TrimSuffix(strings.TrimPrefix(regex, "^"), "$"); re != "" && re != ".*" {
		// CAC regexes are Python-style over the file name, anchored with ^...$;
		// find -regex matches the whole path, so anchor on "<dir>/" instead.
		// POSIX extended is close enough for the expressions the tables use.
		expr = append(expr, "-regextype posix-extended -regex '"+strings.ReplaceAll(dir, "'", "")+"/("+strings.ReplaceAll(re, "'", "")+")'")
	}
	// EXCLUDED_FILES are name globs the CAC check skips (wtmp/btmp/lastlog
	// under /var/log, written 0660/0664 by login accounting by design)
	for _, g := range c.ExcludedFiles() {
		if globRe.MatchString(g) {
			expr = append(expr, "! -name '"+g+"'")
		}
	}
	// owner alternatives ("adm|root"): a violator matches none of them
	owners := func(key, byID, byName string) bool {
		n := 0
		for _, w := range c.Owners(key) {
			switch {
			case IsID(w):
				expr = append(expr, "! "+byID+" "+w)
			case wordRe.MatchString(w):
				expr = append(expr, "! "+byName+" "+w)
			default:
				continue
			}
			n++
		}
		return n > 0
	}
	switch c.Template {
	case "file_permissions":
		mode, err := strconv.ParseInt(c.Str("FILEMODE"), 8, 32)
		if err != nil {
			return FindScan{}, false
		}
		// any bit set outside the allowed mode is a violation
		expr = append(expr, fmt.Sprintf("-perm /%04o", 07777&^mode))
	case "file_owner":
		if !owners("UID_OR_NAME", "-uid", "-user") {
			return FindScan{}, false
		}
	case "file_groupowner":
		if !owners("GID_OR_NAME", "-gid", "-group") {
			return FindScan{}, false
		}
	default:
		return FindScan{}, false
	}
	scan.Expr = strings.Join(expr, " ")
	return scan, true
}

var (
	wordRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	globRe = regexp.MustCompile(`^[A-Za-z0-9_.*?\[\]-]+$`)
)

// ProbeScript renders the data-derived probe sections. `mask` and `sec` are
// defined by the surrounding node script.
func ProbeScript() string {
	d := Derive()
	var b strings.Builder
	b.WriteString("sec STIGSTAT\n")
	if len(d.Stat) > 0 {
		b.WriteString("for f in " + strings.Join(d.Stat, " ") + "; do\n")
		b.WriteString("  [ -e \"$f\" ] && stat -c '%a|%U|%G|%u|%g|%F|%n' \"$f\" 2>/dev/null\n")
		b.WriteString("done\n")
	}
	b.WriteString("sec STIGVIOL\n")
	// The RHEL 8/9/10 and Ubuntu rule sets ask for the same scans under
	// different rule ids; run each (dir, expression) once and print a VIOL
	// line per id that shares it. Cuts the find calls by ~4x.
	type key struct{ dir, expr string }
	ids := map[key][]string{}
	var order []key
	for _, s := range d.Scans {
		for _, dir := range s.Dirs {
			k := key{dir, s.Expr}
			if _, ok := ids[k]; !ok {
				order = append(order, k)
			}
			ids[k] = append(ids[k], s.ID)
		}
	}
	for _, k := range order {
		var awk []string
		for _, id := range ids[k] {
			awk = append(awk, fmt.Sprintf(`print "VIOL|%s|"$0`, id))
		}
		fmt.Fprintf(&b, "[ -d '%s' ] && timeout 20 find '%s' -xdev %s 2>/dev/null | head -20 | awk '{%s}'\n", k.dir, k.dir, k.expr, strings.Join(awk, "; "))
	}
	b.WriteString("sec STIGFILES\n")
	b.WriteString("for f in " + strings.Join(d.Dumps, " ") + "; do\n")
	b.WriteString("  [ -f \"$f\" ] || continue\n")
	b.WriteString("  echo \"--- $f\"\n")
	b.WriteString("  head -c 65536 \"$f\" 2>/dev/null | mask /dev/stdin\n")
	b.WriteString("done\n")
	return b.String()
}
