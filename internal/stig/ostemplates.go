package stig

// Evaluators for the ComplianceAsCode template kinds carried by the embedded
// OS STIG tables (internal/stigdata). Each takes the node facts the probe
// collected and the preprocessed template parameters and returns a status.
// Semantics follow the CAC OVAL for the template; where the OVAL needs
// something the probe cannot see, the check returns Manual with a reason.

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/stigdata"
	"k8s-health-tui/internal/strutil"
)

type templateEval func(info *nodeinfo.Info, c stigdata.Check, id string) (Status, string)

var templateEvals = map[string]templateEval{
	"sysctl":                                     evalSysctl,
	"package_installed":                          evalPackageInstalled,
	"package_installed_guard_var":                evalPackageInstalled,
	"package_removed":                            evalPackageRemoved,
	"package_removed_guard_var":                  evalPackageRemoved,
	"service_enabled":                            evalServiceEnabled,
	"service_enabled_guard_var":                  evalServiceEnabled,
	"service_disabled":                           evalServiceDisabled,
	"service_disabled_guard_var":                 evalServiceDisabled,
	"socket_enabled":                             evalSocketEnabled,
	"socket_disabled":                            evalSocketDisabled,
	"timer_enabled":                              evalTimerEnabled,
	"mount":                                      evalMount,
	"mount_option":                               evalMountOption,
	"mount_option_home":                          evalMountOption,
	"mount_option_remote_filesystems":            evalMountOptionRemote,
	"mount_option_removable_partitions":          evalMountOptionRemovable,
	"sshd_lineinfile":                            evalSSHD,
	"file_permissions":                           evalFilePermissions,
	"file_owner":                                 evalFileOwner,
	"file_groupowner":                            evalFileGroupOwner,
	"file_existence":                             evalFileExistence,
	"audit_rules_watch":                          evalAuditWatch,
	"audit_rules_privileged_commands":            evalAuditPrivileged,
	"audit_rules_dac_modification":               evalAuditSyscall,
	"audit_rules_file_deletion_events":           evalAuditSyscall,
	"audit_rules_kernel_module_loading":          evalAuditSyscall,
	"audit_rules_unsuccessful_file_modification": evalAuditUnsuccessful,
	"kernel_module_disabled":                     evalKernelModule,
	"grub2_bootloader_argument":                  evalGrubArg,
	"auditd_lineinfile":                          evalAuditdConf,
	"key_value_pair_in_file":                     evalKeyValue,
	"shell_lineinfile":                           evalShellLine,
	"lineinfile":                                 evalLineInFile,
	"systemd_dropin_configuration":               evalSystemdDropin,
	"dconf_ini_file":                             evalDconf,
	"accounts_password":                          evalPwquality,
	"pam_account_password_faillock":              evalFaillock,
	"pam_options":                                evalPamOptions,
}

// guardApplies handles the *_guard_var templates: the rule applies only when
// the XCCDF variable has the given value.
func guardApplies(c stigdata.Check) bool {
	vn := c.Str("VARIABLE")
	if vn == "" {
		return true
	}
	want := c.Str("VALUE")
	got := c.Resolved[vn]
	if strings.Contains(c.Str("OPERATION"), "not equal") {
		return got != want
	}
	return got == want
}

// compareOp applies a CAC OVAL operation to two values (numeric when both parse).
func compareOp(op, got, want string) bool {
	g, err1 := strconv.ParseInt(strings.TrimSpace(got), 10, 64)
	w, err2 := strconv.ParseInt(strings.TrimSpace(want), 10, 64)
	numeric := err1 == nil && err2 == nil
	switch strings.TrimSpace(strings.ToLower(op)) {
	case "", "equals":
		if numeric {
			return g == w
		}
		return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want))
	case "not equal":
		if numeric {
			return g != w
		}
		return !strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want))
	case "greater than":
		return numeric && g > w
	case "greater than or equal":
		return numeric && g >= w
	case "less than":
		return numeric && g < w
	case "less than or equal":
		return numeric && g <= w
	case "pattern match":
		re, err := regexp.Compile(want)
		return err == nil && re.MatchString(got)
	}
	return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want))
}

// ---------- sysctl ----------

func evalSysctl(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	param := c.Str("SYSCTLVAR")
	want := c.Str("SYSCTLVAL")
	if want == "" {
		return Manual, param + ": expected value not resolved"
	}
	v, ok := info.SysctlAll[param]
	if !ok {
		if v2, ok2 := info.Sysctl[param]; ok2 && v2 != "" {
			v, ok = v2, true
		}
	}
	if !ok {
		if c.Bool("IPV6") {
			return NA, param + " not present (IPv6 disabled)"
		}
		return Manual, param + " not present on this kernel"
	}
	if compareOp(c.Str("OPERATION"), v, want) {
		return Pass, ""
	}
	return Fail, param + "=" + v + " (want " + want + ")"
}

// ---------- packages ----------

func evalPackageInstalled(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	if !guardApplies(c) {
		return NA, ""
	}
	pkg := c.Str("PKGNAME")
	if info.Packages[pkg] {
		return Pass, ""
	}
	return Fail, pkg + " not installed"
}

func evalPackageRemoved(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	if !guardApplies(c) {
		return NA, ""
	}
	pkgs := c.List("PACKAGES")
	if len(pkgs) == 0 {
		pkgs = []string{c.Str("PKGNAME")}
	}
	var present []string
	for _, p := range pkgs {
		if info.Packages[p] {
			present = append(present, p)
		}
	}
	if len(present) > 0 {
		return Fail, strings.Join(present, ", ") + " installed"
	}
	return Pass, ""
}

// ---------- systemd units ----------

func unitEnabled(state string) bool {
	switch state {
	case "enabled", "enabled-runtime", "static", "alias", "indirect", "generated", "linked":
		return true
	}
	return false
}

func evalUnitEnabled(info *nodeinfo.Info, unit string) (Status, string) {
	fs, known := info.UnitFiles[unit]
	st, running := info.UnitStates[unit]
	if !known && !running {
		return Fail, unit + " not installed"
	}
	var probs []string
	if !unitEnabled(fs) {
		probs = append(probs, "unit file "+strutil.FirstNonEmpty(fs, "-"))
	}
	if st.Active != "active" {
		probs = append(probs, strutil.FirstNonEmpty(st.Active, "-"))
	}
	if len(probs) > 0 {
		return Fail, unit + ": " + strings.Join(probs, ", ")
	}
	return Pass, ""
}

func evalUnitDisabled(info *nodeinfo.Info, unit string) (Status, string) {
	fs, known := info.UnitFiles[unit]
	st, running := info.UnitStates[unit]
	if !known && !running {
		return Pass, ""
	}
	var probs []string
	if unitEnabled(fs) {
		probs = append(probs, "unit file "+fs)
	}
	if st.Active == "active" || st.Active == "activating" {
		probs = append(probs, st.Active)
	}
	if len(probs) > 0 {
		return Fail, unit + ": " + strings.Join(probs, ", ")
	}
	return Pass, ""
}

func evalServiceEnabled(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	if !guardApplies(c) {
		return NA, ""
	}
	return evalUnitEnabled(info, c.Str("SERVICENAME")+".service")
}

func evalServiceDisabled(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	if !guardApplies(c) {
		return NA, ""
	}
	return evalUnitDisabled(info, c.Str("SERVICENAME")+".service")
}

func evalSocketEnabled(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	return evalUnitEnabled(info, c.Str("SOCKETNAME")+".socket")
}

func evalSocketDisabled(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	return evalUnitDisabled(info, c.Str("SOCKETNAME")+".socket")
}

func evalTimerEnabled(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	return evalUnitEnabled(info, c.Str("TIMERNAME")+".timer")
}

// ---------- mounts ----------

func findMount(info *nodeinfo.Info, target string) *nodeinfo.MountEntry {
	for i := range info.Findmnt {
		if info.Findmnt[i].Target == target {
			return &info.Findmnt[i]
		}
	}
	return nil
}

func fstabOptions(info *nodeinfo.Info, target string) ([]string, bool) {
	for _, l := range info.Fstab {
		f := strings.Fields(l)
		if len(f) >= 4 && f[1] == target {
			return strings.Split(f[3], ","), true
		}
	}
	return nil, false
}

func evalMount(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	mp := c.Str("MOUNTPOINT")
	if findMount(info, mp) != nil {
		return Pass, ""
	}
	return Fail, mp + " is not a separate mount"
}

func evalMountOption(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	mp := c.Str("MOUNTPOINT")
	opt := c.Str("MOUNTOPTION")
	m := findMount(info, mp)
	if m == nil {
		if c.Bool("MOUNT_HAS_TO_EXIST") {
			return Fail, mp + " is not a separate mount"
		}
		return Pass, ""
	}
	var probs []string
	if !slices.Contains(m.Options, opt) {
		probs = append(probs, "mounted without "+opt)
	}
	if fo, ok := fstabOptions(info, mp); ok && !slices.Contains(fo, opt) {
		probs = append(probs, "fstab entry lacks "+opt)
	}
	if len(probs) > 0 {
		return Fail, mp + ": " + strings.Join(probs, ", ")
	}
	return Pass, ""
}

func evalMountOptionRemote(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	opt := c.Str("MOUNTOPTION")
	var probs []string
	for _, m := range info.Findmnt {
		switch m.FSType {
		case "nfs", "nfs4", "cifs", "smb3":
			if !slices.Contains(m.Options, opt) {
				probs = append(probs, m.Target)
			}
		}
	}
	if len(probs) > 0 {
		return Fail, "remote mounts without " + opt + ": " + strutil.TruncList(probs, 5)
	}
	return Pass, ""
}

func evalMountOptionRemovable(_ *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	return Manual, "removable media cannot be identified remotely; verify fstab entries for removable partitions carry " + c.Str("MOUNTOPTION")
}

// ---------- sshd ----------

func evalSSHD(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	param := c.Str("PARAMETER")
	want := c.Value("VALUE", "XCCDF_VARIABLE")
	if len(info.SSHD) == 0 {
		if !info.Packages["openssh-server"] && info.UnitFiles["sshd.service"] == "" && info.UnitFiles["ssh.service"] == "" {
			return NA, "sshd not installed"
		}
		return Manual, "sshd -T output unavailable (needs root)"
	}
	vals := info.SSHD[strings.ToLower(param)]
	if len(vals) == 0 {
		if c.Bool("MISSING_PARAMETER_PASS") {
			return Pass, ""
		}
		return Fail, param + " not reported by sshd -T"
	}
	if want == "" {
		return Manual, param + ": expected value not resolved (" + strings.Join(vals, " ") + ")"
	}
	got := strings.Join(vals, " ")
	if c.Str("DATATYPE") == "int" {
		if compareOp("equals", got, want) {
			return Pass, ""
		}
	} else if strings.EqualFold(got, want) {
		return Pass, ""
	}
	return Fail, param + " " + got + " (want " + want + ")"
}

// ---------- files ----------

func modeBits(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 8, 32)
	return n, err == nil
}

// fileCheck applies one predicate to every FILEPATH, using the probe's find
// scan results for recursive/regex checks and stat lines otherwise.
func fileCheck(info *nodeinfo.Info, c stigdata.Check, id string, pred func(p nodeinfo.Perm) string) (Status, string) {
	if !info.STIGProbed {
		return Manual, "node probe predates the OS STIG facts"
	}
	scanned := c.Bool("RECURSIVE") || c.Str("FILE_REGEX") != ""
	if viol := info.STIGViol[id]; scanned && len(viol) > 0 {
		return Fail, strutil.TruncList(viol, 5)
	}
	var probs []string
	for _, fp := range c.List("FILEPATH") {
		if scanned {
			continue // covered by the find scan (no violators)
		}
		p, ok := info.STIGStat[strings.TrimRight(fp, "/")]
		if !ok {
			p, ok = info.STIGStat[fp]
		}
		if !ok {
			continue // absent files pass, as in the CAC OVAL
		}
		if d := pred(p); d != "" {
			probs = append(probs, fp+" "+d)
		}
	}
	if len(probs) > 0 {
		return Fail, strings.Join(probs, "; ")
	}
	return Pass, ""
}

func evalFilePermissions(info *nodeinfo.Info, c stigdata.Check, id string) (Status, string) {
	want, ok := modeBits(c.Str("FILEMODE"))
	if !ok {
		return Manual, "mode " + c.Str("FILEMODE") + " not parseable"
	}
	return fileCheck(info, c, id, func(p nodeinfo.Perm) string {
		got, ok := modeBits(p.Mode)
		if !ok {
			return "mode " + p.Mode
		}
		if got&^want != 0 {
			return fmt.Sprintf("mode %s (want %04o or stricter)", p.Mode, want)
		}
		return ""
	})
}

func evalFileOwner(info *nodeinfo.Info, c stigdata.Check, id string) (Status, string) {
	want := c.Str("UID_OR_NAME")
	byUID := c.Bool("OWNER_REPRESENTED_WITH_UID")
	return fileCheck(info, c, id, func(p nodeinfo.Perm) string {
		if byUID && p.UID == want || !byUID && p.User == want {
			return ""
		}
		return "owner " + p.User + " (want " + want + ")"
	})
}

func evalFileGroupOwner(info *nodeinfo.Info, c stigdata.Check, id string) (Status, string) {
	want := c.Str("GID_OR_NAME")
	byGID := c.Bool("GROUP_REPRESENTED_WITH_GID")
	return fileCheck(info, c, id, func(p nodeinfo.Perm) string {
		if byGID && p.GID == want || !byGID && p.Group == want {
			return ""
		}
		return "group " + p.Group + " (want " + want + ")"
	})
}

func evalFileExistence(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	if !info.STIGProbed {
		return Manual, "node probe predates the OS STIG facts"
	}
	fp := c.Str("FILEPATH")
	_, exists := info.STIGStat[fp]
	if exists == c.Bool("EXISTS") {
		return Pass, ""
	}
	if exists {
		return Fail, fp + " exists"
	}
	return Fail, fp + " missing"
}

// ---------- audit rules ----------

type auditRule struct {
	watch, perms string
	path         string // -F path=
	arch         string
	syscalls     map[string]bool
	fields       []string
	raw          string
}

func parseAuditRules(lines []string) []auditRule {
	var out []auditRule
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		r := auditRule{syscalls: map[string]bool{}, raw: l}
		for i := 0; i < len(f); i++ {
			switch f[i] {
			case "-w":
				if i+1 < len(f) {
					r.watch = f[i+1]
					i++
				}
			case "-p":
				if i+1 < len(f) {
					r.perms = f[i+1]
					i++
				}
			case "-S":
				if i+1 < len(f) {
					for _, s := range strings.Split(f[i+1], ",") {
						r.syscalls[s] = true
					}
					i++
				}
			case "-F":
				if i+1 < len(f) {
					fld := f[i+1]
					r.fields = append(r.fields, fld)
					if strings.HasPrefix(fld, "arch=") {
						r.arch = strings.TrimPrefix(fld, "arch=")
					}
					if strings.HasPrefix(fld, "path=") {
						r.path = strings.TrimPrefix(fld, "path=")
					}
					if strings.HasPrefix(fld, "perm=") {
						r.perms = strings.TrimPrefix(fld, "perm=")
					}
					i++
				}
			}
		}
		out = append(out, r)
	}
	return out
}

func auditRulesOf(info *nodeinfo.Info) ([]auditRule, string) {
	if len(info.AuditRules) > 0 && !(len(info.AuditRules) == 1 && strings.Contains(info.AuditRules[0], "No rules")) {
		return parseAuditRules(info.AuditRules), "loaded"
	}
	if len(info.AuditRuleFiles) > 0 {
		return parseAuditRules(info.AuditRuleFiles), "rules.d (auditctl -l unavailable)"
	}
	return nil, ""
}

func (r auditRule) hasField(prefix string) bool {
	for _, f := range r.fields {
		if strings.HasPrefix(f, prefix) {
			return true
		}
	}
	return false
}

func permsCover(got, want string) bool {
	for _, ch := range want {
		if !strings.ContainsRune(got, ch) {
			return false
		}
	}
	return true
}

func evalAuditWatch(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	rules, src := auditRulesOf(info)
	if src == "" {
		return Fail, "no audit rules loaded or configured"
	}
	path := strings.TrimRight(c.Str("PATH"), "/")
	for _, r := range rules {
		if (strings.TrimRight(r.watch, "/") == path || r.path == path) && permsCover(r.perms, "wa") {
			return Pass, ""
		}
	}
	return Fail, "no -w " + path + " -p wa rule (" + src + ")"
}

func evalAuditPrivileged(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	path := strings.ReplaceAll(c.Str("PATH"), `\/`, "/")
	if info.STIGProbed {
		if _, ok := info.STIGStat[path]; !ok {
			return NA, path + " not present"
		}
	}
	rules, src := auditRulesOf(info)
	if src == "" {
		return Fail, "no audit rules loaded or configured"
	}
	for _, r := range rules {
		if r.path == path && strings.Contains(r.perms, "x") {
			return Pass, ""
		}
	}
	return Fail, "no -F path=" + path + " -F perm=x rule (" + src + ")"
}

// syscallCovered reports whether a syscall is audited for the architectures
// the node needs (b32 and b64 on x86_64, b64 elsewhere).
func syscallCovered(info *nodeinfo.Info, rules []auditRule, syscall string, extra func(auditRule) bool) (bool, string) {
	need := []string{"b64"}
	if info.Arch == "x86_64" {
		need = []string{"b32", "b64"}
	}
	var missing []string
	for _, arch := range need {
		found := false
		for _, r := range rules {
			if r.syscalls[syscall] && (r.arch == arch || r.arch == "") && (extra == nil || extra(r)) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, arch)
		}
	}
	if len(missing) > 0 {
		return false, syscall + " not audited for " + strings.Join(missing, "/")
	}
	return true, ""
}

func evalAuditSyscall(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	rules, src := auditRulesOf(info)
	if src == "" {
		return Fail, "no audit rules loaded or configured"
	}
	sc := c.Str("ATTR")
	if sc == "" {
		sc = c.Str("NAME")
	}
	if ok, why := syscallCovered(info, rules, sc, nil); !ok {
		return Fail, why + " (" + src + ")"
	}
	return Pass, ""
}

func evalAuditUnsuccessful(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	rules, src := auditRulesOf(info)
	if src == "" {
		return Fail, "no audit rules loaded or configured"
	}
	sc := c.Str("NAME")
	var probs []string
	for _, exit := range []string{"-EACCES", "-EPERM"} {
		if ok, _ := syscallCovered(info, rules, sc, func(r auditRule) bool { return r.hasField("exit=" + exit) }); !ok {
			probs = append(probs, exit)
		}
	}
	if len(probs) > 0 {
		return Fail, sc + " not audited with exit=" + strings.Join(probs, "/") + " (" + src + ")"
	}
	return Pass, ""
}

// ---------- kernel modules ----------

func evalKernelModule(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	mod := c.Str("KERNMODULE")
	install, blacklist := false, false
	for _, l := range info.Modprobe {
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == mod {
			switch f[0] {
			case "install":
				if len(f) >= 3 && (f[2] == "/bin/false" || f[2] == "/bin/true") {
					install = true
				}
			case "blacklist":
				blacklist = true
			}
		}
	}
	var probs []string
	if !install {
		probs = append(probs, "no 'install "+mod+" /bin/false' in modprobe.d")
	}
	if !blacklist {
		probs = append(probs, "not blacklisted")
	}
	if info.LoadedModules[mod] {
		probs = append(probs, "currently loaded")
	}
	if len(probs) > 0 {
		return Fail, strings.Join(probs, ", ")
	}
	return Pass, ""
}

// ---------- grub ----------

func cmdlineHas(cmdline, name, value, op string) bool {
	for _, tok := range strings.Fields(cmdline) {
		k, v, has := strings.Cut(tok, "=")
		if k != name {
			continue
		}
		if value == "" {
			return true
		}
		if has && compareOp(op, v, value) {
			return true
		}
	}
	return false
}

func evalGrubArg(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	name := c.Str("ARG_NAME")
	value := c.Value("ARG_VALUE", "ARG_VARIABLE")
	op := c.Str("OPERATION")
	shown := name
	if value != "" {
		shown += "=" + value
	}
	runtime := cmdlineHas(info.Hardening["cmdline"], name, value, op)
	cfg := false
	for _, l := range info.GrubArgs {
		_, args, _ := strings.Cut(l, "=")
		if cmdlineHas(strings.Trim(args, `"`), name, value, op) {
			cfg = true
		}
	}
	switch {
	case runtime && (cfg || len(info.GrubArgs) == 0):
		return Pass, ""
	case runtime:
		return Fail, shown + " active but missing from the boot loader config (lost on reboot)"
	case cfg:
		return Fail, shown + " configured but not on the running kernel command line (reboot pending?)"
	}
	return Fail, shown + " not set"
}

// ---------- config-file line checks ----------

func evalAuditdConf(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	content, ok := info.STIGFile("/etc/audit/auditd.conf")
	if !ok {
		if info.Packages["audit"] || info.Packages["auditd"] {
			return Fail, "/etc/audit/auditd.conf not readable"
		}
		return Fail, "auditd not installed"
	}
	param := c.Str("PARAMETER")
	want := c.Value("VALUE", "XCCDF_VARIABLE")
	got, found := iniValue(content, "", param, "=")
	switch {
	case !found && c.Bool("MISSING_PARAMETER_PASS"):
		return Pass, ""
	case !found:
		return Fail, param + " not set"
	case want == "":
		return Manual, param + " = " + got + " (expected value not resolved)"
	case compareOp("equals", got, want):
		return Pass, ""
	}
	return Fail, param + " = " + got + " (want " + want + ")"
}

// iniValue returns the last value of key in section (section "" = whole
// file, ignoring headers) using sep as the separator.
func iniValue(content, section, key, sep string) (string, bool) {
	inSection := section == ""
	val, found := "", false
	for _, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			inSection = section == "" || strings.EqualFold(strings.Trim(t, "[]"), section)
			continue
		}
		if !inSection {
			continue
		}
		k, v, ok := strings.Cut(t, sep)
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), key) {
			val, found = strings.Trim(strings.TrimSpace(v), `"'`), true
		}
	}
	return val, found
}

func evalKeyValue(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	path := c.Str("PATH")
	content, ok := info.STIGFile(path)
	if !ok {
		return Fail, path + " missing"
	}
	key := c.Str("KEY")
	want := c.Value("VALUE", "XCCDF_VARIABLE")
	sep := c.Str("SEP")
	if sep == "" {
		sep = "="
	}
	got, found := iniValue(content, "", key, strings.TrimSpace(sep))
	switch {
	case !found:
		return Fail, key + " not set in " + path
	case want == "":
		return Manual, key + " = " + got + " (expected value not resolved)"
	case compareOp("equals", got, want):
		return Pass, ""
	}
	return Fail, key + " = " + got + " in " + path + " (want " + want + ")"
}

func evalShellLine(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	path := c.Str("PATH")
	content, ok := info.STIGFile(path)
	if !ok {
		return Fail, path + " missing"
	}
	param := c.Str("PARAMETER")
	want := c.Value("VALUE", "XCCDF_VARIABLE")
	got, found := iniValue(content, "", param, "=")
	switch {
	case !found && c.Bool("MISSING_PARAMETER_PASS"):
		return Pass, ""
	case !found:
		return Fail, param + " not set in " + path
	case compareOp("equals", got, want):
		return Pass, ""
	}
	return Fail, param + "=" + got + " in " + path + " (want " + want + ")"
}

func evalLineInFile(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	path := c.Str("PATH")
	content, ok := info.STIGFile(path)
	if !ok {
		return Fail, path + " missing"
	}
	text := strings.TrimSpace(c.Str("TEXT"))
	for _, l := range strings.Split(content, "\n") {
		if strings.TrimSpace(l) == text {
			return Pass, ""
		}
	}
	return Fail, "'" + text + "' not in " + path
}

func evalSystemdDropin(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	master := c.Str("MASTER_CFG_FILE")
	dropin := c.Str("DROPIN_DIR")
	section, param, want := c.Str("SECTION"), c.Str("PARAM"), c.Str("VALUE")
	got, found := "", false
	if content, ok := info.STIGFile(master); ok {
		got, found = iniValue(content, section, param, "=")
	} else if c.Bool("MISSING_CONFIG_FILE_FAIL") {
		return Fail, master + " missing"
	}
	files := info.STIGFilesGlob(dropin)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for _, f := range files {
		if v, ok := iniValue(f.Content, section, param, "="); ok {
			got, found = v, true
		}
	}
	switch {
	case !found && c.Bool("MISSING_PARAMETER_PASS"):
		return Pass, ""
	case !found:
		return Fail, param + " not set in " + master + " or " + dropin
	case compareOp("equals", got, want):
		return Pass, ""
	}
	return Fail, param + "=" + got + " (want " + want + ")"
}

func evalDconf(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	if !info.Packages["gdm"] && !info.Packages["gdm3"] && !info.Packages["dconf"] {
		return NA, "no GNOME desktop (gdm/dconf not installed)"
	}
	dir, section, param, want := c.Str("PATH"), c.Str("SECTION"), c.Str("PARAMETER"), c.Str("VALUE")
	got, found := "", false
	for _, f := range info.STIGFilesGlob(dir) {
		if strings.Contains(f.Path, "/locks/") {
			continue
		}
		if v, ok := iniValue(f.Content, section, param, "="); ok {
			got, found = v, true
		}
	}
	if !found {
		return Fail, param + " not set under " + dir
	}
	if strings.Trim(got, `'"`) != strings.Trim(want, `'"`) {
		return Fail, param + "=" + got + " (want " + want + ")"
	}
	lockKey := "/" + strings.Trim(section, "/") + "/" + param
	locked := false
	for _, f := range info.STIGFilesGlob(c.Str("LOCK_PATH")) {
		for _, l := range strings.Split(f.Content, "\n") {
			if strings.TrimSpace(l) == lockKey {
				locked = true
			}
		}
	}
	if !locked {
		return Fail, lockKey + " not locked under " + c.Str("LOCK_PATH")
	}
	return Pass, ""
}

// ---------- pam / pwquality ----------

func pwqualityValue(info *nodeinfo.Info, key string) (string, bool) {
	val, found := "", false
	if content, ok := info.STIGFile("/etc/security/pwquality.conf"); ok {
		val, found = iniValue(content, "", key, "=")
	}
	files := info.STIGFilesGlob("/etc/security/pwquality.conf.d")
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for _, f := range files {
		if v, ok := iniValue(f.Content, "", key, "="); ok {
			val, found = v, true
		}
	}
	return val, found
}

func evalPwquality(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	key := c.Str("VARIABLE")
	want := c.Resolved["var_password_pam_"+key]
	if want == "" {
		return Manual, key + ": expected value not resolved"
	}
	got, found := pwqualityValue(info, key)
	if !found {
		return Fail, key + " not set in pwquality.conf"
	}
	if !compareOp(c.Str("OPERATION"), got, want) {
		return Fail, fmt.Sprintf("%s = %s (want %s %s)", key, got, c.Str("OPERATION"), want)
	}
	if z := c.Str("ZERO_COMPARISON_OPERATION"); z != "" && !compareOp(z, got, "0") {
		return Fail, fmt.Sprintf("%s = %s (must be %s 0)", key, got, z)
	}
	return Pass, ""
}

func evalFaillock(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	name := c.Str("PRM_NAME")
	want := c.Resolved[c.Str("EXT_VARIABLE")]
	reConf, err1 := regexp.Compile("(?m)" + c.Str("PRM_REGEX_CONF"))
	rePam, err2 := regexp.Compile("(?m)" + c.Str("PRM_REGEX_PAMD"))
	if err1 != nil || err2 != nil {
		return Manual, name + ": pattern not supported"
	}
	var got string
	if content, ok := info.STIGFile("/etc/security/faillock.conf"); ok {
		if m := reConf.FindStringSubmatch(content); len(m) > 1 {
			got = m[1]
		}
	}
	if got == "" {
		for _, f := range []string{"/etc/pam.d/system-auth", "/etc/pam.d/password-auth", "/etc/pam.d/common-auth"} {
			if content, ok := info.STIGFile(f); ok {
				if m := rePam.FindStringSubmatch(content); len(m) > 1 {
					got = m[1]
				}
			}
		}
	}
	if got == "" {
		return Fail, "faillock " + name + " not configured"
	}
	lo, hi := c.Str("VARIABLE_LOWER_BOUND"), c.Str("VARIABLE_UPPER_BOUND")
	if lo == "use_ext_variable" {
		lo = want
	}
	if hi == "use_ext_variable" {
		hi = want
	}
	if lo != "" && !compareOp("greater than or equal", got, lo) || hi != "" && !compareOp("less than or equal", got, hi) {
		return Fail, fmt.Sprintf("%s = %s (want %s..%s)", name, got, strutil.FirstNonEmpty(lo, "-"), strutil.FirstNonEmpty(hi, "-"))
	}
	return Pass, ""
}

func evalPamOptions(info *nodeinfo.Info, c stigdata.Check, _ string) (Status, string) {
	path := c.Str("PATH")
	content, ok := info.STIGFile(path)
	if !ok {
		return Fail, path + " missing"
	}
	typ, flag, module := c.Str("TYPE"), c.Str("CONTROL_FLAG"), c.Str("MODULE")
	var args []string
	if l, ok := c.Params["ARGUMENTS"].([]any); ok {
		for _, a := range l {
			if m, ok := a.(map[string]any); ok {
				if s, _ := m["argument"].(string); s != "" {
					args = append(args, s)
				}
			}
		}
	}
	for _, l := range strings.Split(content, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != typ || f[2] != module {
			continue
		}
		if flag != "" && f[1] != flag {
			continue
		}
		missing := []string{}
		for _, a := range args {
			found := false
			for _, tok := range f[3:] {
				if tok == a || strings.HasPrefix(tok, a+"=") {
					found = true
				}
			}
			if !found {
				missing = append(missing, a)
			}
		}
		if len(missing) == 0 {
			return Pass, ""
		}
		return Fail, typ + " " + module + " in " + path + " lacks " + strings.Join(missing, ", ")
	}
	return Fail, "no '" + typ + " " + flag + " " + module + "' line in " + path
}
