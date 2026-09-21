package stig

// Evaluators for the OS STIG rules that ComplianceAsCode checks with
// hand-written OVAL rather than a template. They are keyed by the CAC rule
// name carried in the embedded tables, so one evaluator serves every product
// that maps a STIG rule to that CAC rule. Facts come from
// nodeinfo/scripts/os_stig_facts.sh (STIGCmd, STIGSweep, Passwd, ShadowMeta,
// ...) and the config-file dumps listed in stigdata.FileDumps.
//
// Where the STIG's own check needs an organizational decision (authorized
// user lists, PPSM CLSA, documented exceptions) the evaluator returns Manual
// with the evidence an assessor would ask for.
//
// This file: helpers, accounts, PAM, sudo, umask/session, GNOME, packages.
// osnamed_system.go: audit, rsyslog, chrony, crypto/SSH, firewall, files,
// AIDE, boot, miscellany.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

type namedEval func(info *nodeinfo.Info) (Status, string)

// namedEvals is filled by init() from the per-area tables below.
var namedEvals = map[string]namedEval{}

func register(m map[string]namedEval) {
	for k, v := range m {
		namedEvals[k] = v
	}
}

// ---------- helpers ----------

var commentRe = rx(`^\s*[#;]`)

// lines returns the non-comment, non-empty lines of a dumped file.
func lines(info *nodeinfo.Info, path string) ([]string, bool) {
	c, ok := info.STIGFile(path)
	if !ok {
		return nil, false
	}
	var out []string
	for _, l := range strings.Split(c, "\n") {
		if t := strings.TrimSpace(l); t != "" && !commentRe.MatchString(l) {
			out = append(out, l)
		}
	}
	return out, true
}

// linesOf returns the non-comment lines of every dumped file at the given
// paths (exact) or under the given directories (trailing slash), with the
// file path prefixed, and whether any file was present.
func linesOf(info *nodeinfo.Info, paths ...string) ([]string, bool) {
	var out []string
	found := false
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			for _, f := range info.STIGFilesGlob(p) {
				found = true
				for _, l := range strings.Split(f.Content, "\n") {
					if t := strings.TrimSpace(l); t != "" && !commentRe.MatchString(l) {
						out = append(out, f.Path+": "+l)
					}
				}
			}
			continue
		}
		if ls, ok := lines(info, p); ok {
			found = true
			for _, l := range ls {
				out = append(out, p+": "+l)
			}
		}
	}
	return out, found
}

// grep returns the lines (path-prefixed) matching re.
func grep(info *nodeinfo.Info, re *regexp.Regexp, paths ...string) ([]string, bool) {
	ls, found := linesOf(info, paths...)
	var out []string
	for _, l := range ls {
		if re.MatchString(l) {
			out = append(out, l)
		}
	}
	return out, found
}

// keyValue returns the last "KEY value" / "KEY = value" setting of key in
// the dumped files (case-insensitive key), and whether it was found.
func keyValue(info *nodeinfo.Info, key string, paths ...string) (string, bool) {
	re := rx(`(?i)^(?:[^:]*: )?\s*` + regexp.QuoteMeta(key) + `\s*[= \t]\s*(.*?)\s*$`)
	ls, _ := linesOf(info, paths...)
	val, found := "", false
	for _, l := range ls {
		if m := re.FindStringSubmatch(l); m != nil {
			val, found = strings.Trim(m[1], `"'`), true
		}
	}
	return val, found
}

func cmd(info *nodeinfo.Info, key string) string { return info.STIGCmd[key] }

func sweep(info *nodeinfo.Info, kind string) []string { return info.STIGSweep[kind] }

func pkgAny(info *nodeinfo.Info, names ...string) bool {
	for _, n := range names {
		if info.Packages[n] {
			return true
		}
	}
	return false
}

func isUbuntu(info *nodeinfo.Info) bool { return info.OS.ID == "ubuntu" }

func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil
}

func failIf(items []string, what string) (Status, string) {
	if len(items) > 0 {
		return Fail, fmt.Sprintf("%d %s: %s", len(items), what, strutil.TruncList(items, 5))
	}
	return Pass, ""
}

// interactive users: uid >= 1000 with a login shell
func interactiveUsers(info *nodeinfo.Info) []nodeinfo.PasswdEntry {
	var out []nodeinfo.PasswdEntry
	for _, u := range info.Passwd {
		if u.UID >= 1000 && u.Name != "nobody" && !strings.HasSuffix(u.Shell, "nologin") && !strings.HasSuffix(u.Shell, "/false") {
			out = append(out, u)
		}
	}
	return out
}

// pamFiles returns the PAM stack files for the family (RHEL: system-auth /
// password-auth; Debian: common-*).
func pamAuthFiles(info *nodeinfo.Info) []string {
	if isUbuntu(info) {
		return []string{"/etc/pam.d/common-auth", "/etc/pam.d/common-account"}
	}
	return []string{"/etc/pam.d/system-auth", "/etc/pam.d/password-auth"}
}

func pamPasswordFile(info *nodeinfo.Info, rhelFile string) string {
	if isUbuntu(info) {
		return "/etc/pam.d/common-password"
	}
	return rhelFile
}

// umaskOK reports whether every uncommented umask in the file is 077.
func umaskFile(info *nodeinfo.Info, path string, naWhenMissing bool) (Status, string) {
	ls, ok := lines(info, path)
	if !ok {
		if naWhenMissing {
			return NA, path + " not present"
		}
		return Fail, path + " missing"
	}
	re := rx(`(?i)\bumask\s+(\d{3,4})`)
	found := false
	for _, l := range ls {
		for _, m := range re.FindAllStringSubmatch(l, -1) {
			found = true
			if v := strings.TrimLeft(m[1], "0"); v != "77" {
				return Fail, path + ": umask " + m[1]
			}
		}
	}
	if !found {
		return Fail, path + ": no umask 077"
	}
	return Pass, ""
}

func loginDefsInt(info *nodeinfo.Info, key string, ok func(int) bool, want string) (Status, string) {
	v, found := keyValue(info, key, "/etc/login.defs")
	if !found {
		return Fail, key + " not set in /etc/login.defs"
	}
	n, isNum := atoi(v)
	if !isNum || !ok(n) {
		return Fail, key + " " + v + " (want " + want + ")"
	}
	return Pass, ""
}

// ---------- accounts ----------

func init() {
	register(map[string]namedEval{
		"accounts_maximum_age_login_defs": func(i *nodeinfo.Info) (Status, string) {
			return loginDefsInt(i, "PASS_MAX_DAYS", func(n int) bool { return n > 0 && n <= 60 }, "1..60")
		},
		"accounts_minimum_age_login_defs": func(i *nodeinfo.Info) (Status, string) {
			return loginDefsInt(i, "PASS_MIN_DAYS", func(n int) bool { return n >= 1 }, ">= 1")
		},
		"accounts_password_minlen_login_defs": func(i *nodeinfo.Info) (Status, string) {
			return loginDefsInt(i, "PASS_MIN_LEN", func(n int) bool { return n >= 15 }, ">= 15")
		},
		"accounts_logon_fail_delay": func(i *nodeinfo.Info) (Status, string) {
			return loginDefsInt(i, "FAIL_DELAY", func(n int) bool { return n >= 4 }, ">= 4")
		},
		"accounts_have_homedir_login_defs": func(i *nodeinfo.Info) (Status, string) {
			if v, ok := keyValue(i, "CREATE_HOME", "/etc/login.defs"); ok && strings.EqualFold(v, "yes") {
				return Pass, ""
			}
			return Fail, "CREATE_HOME not yes in /etc/login.defs"
		},
		"accounts_umask_etc_login_defs": func(i *nodeinfo.Info) (Status, string) {
			v, ok := keyValue(i, "UMASK", "/etc/login.defs")
			if ok && strings.TrimLeft(v, "0") == "77" {
				return Pass, ""
			}
			return Fail, "UMASK " + strutil.FirstNonEmpty(v, "-") + " in /etc/login.defs (want 077)"
		},
		"set_password_hashing_algorithm_logindefs": func(i *nodeinfo.Info) (Status, string) {
			if v, ok := keyValue(i, "ENCRYPT_METHOD", "/etc/login.defs"); ok && strings.EqualFold(v, "SHA512") {
				return Pass, ""
			}
			return Fail, "ENCRYPT_METHOD not SHA512 in /etc/login.defs"
		},
		"set_password_hashing_min_rounds_logindefs": func(i *nodeinfo.Info) (Status, string) {
			mn, okMin := keyValue(i, "SHA_CRYPT_MIN_ROUNDS", "/etc/login.defs")
			mx, okMax := keyValue(i, "SHA_CRYPT_MAX_ROUNDS", "/etc/login.defs")
			if !okMin && !okMax {
				return Fail, "SHA_CRYPT_MIN_ROUNDS / SHA_CRYPT_MAX_ROUNDS not set"
			}
			best := 0
			for _, v := range []string{mn, mx} {
				if n, ok := atoi(v); ok && n > best {
					best = n
				}
			}
			if best < 100000 {
				return Fail, fmt.Sprintf("SHA_CRYPT rounds %d (want >= 100000)", best)
			}
			return Pass, ""
		},
		"set_password_hashing_algorithm_libuserconf": func(i *nodeinfo.Info) (Status, string) {
			if _, ok := i.STIGFile("/etc/libuser.conf"); !ok {
				if !i.Packages["libuser"] {
					return NA, "libuser not installed"
				}
				return Fail, "/etc/libuser.conf missing"
			}
			if v, ok := keyValue(i, "crypt_style", "/etc/libuser.conf"); ok && strings.EqualFold(v, "sha512") {
				return Pass, ""
			}
			return Fail, "crypt_style not sha512 in /etc/libuser.conf"
		},
		"account_disable_post_pw_expiration": func(i *nodeinfo.Info) (Status, string) {
			v, ok := keyValue(i, "INACTIVE", "/etc/default/useradd")
			n, isNum := atoi(v)
			if !ok || !isNum || n < 0 || n > 35 {
				return Fail, "INACTIVE=" + strutil.FirstNonEmpty(v, "-") + " in /etc/default/useradd (want 0..35)"
			}
			return Pass, ""
		},
		"accounts_password_set_max_life_existing": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, u := range interactiveUsers(i) {
				m, ok := i.ShadowMeta[u.Name]
				if !ok || m.Hash == "locked" || m.Hash == "empty" {
					continue
				}
				if n, isNum := atoi(m.MaxDays); !isNum || n <= 0 || n > 60 {
					bad = append(bad, u.Name+" max "+strutil.FirstNonEmpty(m.MaxDays, "-"))
				}
			}
			return failIf(bad, "accounts with max password age outside 1..60")
		},
		"accounts_password_set_min_life_existing": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, u := range interactiveUsers(i) {
				m, ok := i.ShadowMeta[u.Name]
				if !ok || m.Hash == "locked" || m.Hash == "empty" {
					continue
				}
				if n, isNum := atoi(m.MinDays); !isNum || n < 1 {
					bad = append(bad, u.Name+" min "+strutil.FirstNonEmpty(m.MinDays, "-"))
				}
			}
			return failIf(bad, "accounts with min password age < 1")
		},
		"accounts_password_all_shadowed_sha512": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for name, m := range i.ShadowMeta {
				if m.Hash == "locked" || m.Hash == "empty" || m.Hash == "$6$" {
					continue
				}
				bad = append(bad, name+" ("+m.Hash+")")
			}
			sort.Strings(bad)
			return failIf(bad, "password hashes not SHA-512 ($6$)")
		},
		"no_empty_passwords_etc_shadow": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for name, m := range i.ShadowMeta {
				if m.Hash == "empty" {
					bad = append(bad, name)
				}
			}
			sort.Strings(bad)
			return failIf(bad, "accounts with an empty password")
		},
		"no_empty_passwords": func(i *nodeinfo.Info) (Status, string) {
			hits, _ := grep(i, rx(`\bnullok\b`), append(pamAuthFiles(i), pamPasswordFile(i, "/etc/pam.d/system-auth"))...)
			return failIf(hits, "nullok in PAM")
		},
		"account_unique_id": evalDuplicateUIDs,
		"no_duplicate_uids": evalDuplicateUIDs,
		"group_unique_id": func(i *nodeinfo.Info) (Status, string) {
			seen := map[int]string{}
			var dup []string
			for _, g := range i.Groups {
				if prev, ok := seen[g.GID]; ok {
					dup = append(dup, fmt.Sprintf("%d (%s, %s)", g.GID, prev, g.Name))
				}
				seen[g.GID] = g.Name
			}
			return failIf(dup, "duplicate GIDs")
		},
		"gid_passwd_group_same": func(i *nodeinfo.Info) (Status, string) {
			gids := map[int]bool{}
			for _, g := range i.Groups {
				gids[g.GID] = true
			}
			var bad []string
			for _, u := range interactiveUsers(i) {
				if !gids[u.GID] {
					bad = append(bad, fmt.Sprintf("%s gid %d", u.Name, u.GID))
				}
			}
			return failIf(bad, "users whose primary group does not exist")
		},
		"accounts_no_uid_except_zero": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, u := range i.Passwd {
				if u.UID == 0 && u.Name != "root" {
					bad = append(bad, u.Name)
				}
			}
			return failIf(bad, "accounts with UID 0")
		},
		"no_shelllogin_for_systemaccounts": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, u := range i.Passwd {
				if u.UID >= 1000 || u.Name == "root" {
					continue
				}
				switch {
				case strings.HasSuffix(u.Shell, "nologin"), strings.HasSuffix(u.Shell, "/false"), strings.HasSuffix(u.Shell, "/sync"), strings.HasSuffix(u.Shell, "/shutdown"), strings.HasSuffix(u.Shell, "/halt"), u.Shell == "":
				default:
					bad = append(bad, u.Name+" "+u.Shell)
				}
			}
			return failIf(bad, "system accounts with a login shell (must be documented)")
		},
		"accounts_user_interactive_home_directory_defined": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, u := range interactiveUsers(i) {
				if u.Home == "" || u.Home == "/" {
					bad = append(bad, u.Name)
				}
			}
			return failIf(bad, "interactive users without a home directory")
		},
		"accounts_user_interactive_home_directory_exists": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "HOMEMISSING"), "home directories missing")
		},
		"file_permissions_home_directories": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, h := range sweep(i, "HOME") { // user|mode|gid|path
				f := strings.Split(h, "|")
				if len(f) < 4 {
					continue
				}
				if m, ok := modeBits(f[1]); ok && m&^0o750 != 0 {
					bad = append(bad, f[3]+" "+f[1])
				}
			}
			return failIf(bad, "home directories more permissive than 0750")
		},
		"file_groupownership_home_directories": func(i *nodeinfo.Info) (Status, string) {
			gid := map[string]int{}
			for _, u := range i.Passwd {
				gid[u.Name] = u.GID
			}
			var bad []string
			for _, h := range sweep(i, "HOME") {
				f := strings.Split(h, "|")
				if len(f) < 4 {
					continue
				}
				if g, ok := atoi(f[2]); ok && g != gid[f[0]] {
					bad = append(bad, fmt.Sprintf("%s gid %d (user's primary gid %d)", f[3], g, gid[f[0]]))
				}
			}
			return failIf(bad, "home directories not group-owned by the user's primary group")
		},
		"file_permission_user_init_files_root": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "INITPERM"), "initialization files more permissive than 0740")
		},
		"file_permission_user_init_files": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "INITPERM"), "initialization files more permissive than 0740")
		},
		"accounts_user_dot_no_world_writable_programs": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "INITWW"), "world-writable initialization files")
		},
		"accounts_users_home_files_permissions": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "HOMEPERM"), "home directory files more permissive than 0750")
		},
		"accounts_users_home_files_groupownership": func(i *nodeinfo.Info) (Status, string) {
			member := map[string]map[string]bool{}
			for _, g := range i.Groups {
				for _, m := range g.Members {
					if member[m] == nil {
						member[m] = map[string]bool{}
					}
					member[m][g.Name] = true
				}
			}
			var bad []string
			for _, h := range sweep(i, "HOMEGROUP") { // user|path|group
				f := strings.Split(h, "|")
				if len(f) < 3 || member[f[0]][f[2]] {
					continue
				}
				bad = append(bad, f[1]+" group "+f[2])
			}
			return failIf(bad, "home files group-owned by a group the user is not in")
		},
		"accounts_umask_interactive_users": func(i *nodeinfo.Info) (Status, string) {
			re := rx(`(?i)umask\s+(\d{3,4})`)
			var bad []string
			for _, l := range sweep(i, "UMASK") {
				if m := re.FindStringSubmatch(l); m != nil && strings.TrimLeft(m[1], "0") != "77" {
					bad = append(bad, l)
				}
			}
			return failIf(bad, "user init files with a umask looser than 077")
		},
		"accounts_user_home_paths_only": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, l := range sweep(i, "PATHLINE") { // user|file:line
				_, rest, _ := strings.Cut(l, "|")
				_, line, _ := strings.Cut(rest, ":")
				_, val, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				val = strings.Trim(strings.TrimSpace(val), `"'`)
				for _, el := range strings.Split(val, ":") {
					el = strings.TrimSpace(el)
					switch {
					case el == "", strings.HasPrefix(el, "$PATH"), strings.HasPrefix(el, "${PATH"), strings.HasPrefix(el, "$HOME"), strings.HasPrefix(el, "${HOME"), strings.HasPrefix(el, "~"), strings.HasPrefix(el, "/home/"), strings.HasPrefix(el, "/root"):
					default:
						bad = append(bad, rest)
					}
				}
			}
			return failIf(strutil.Uniq(bad), "user init files with PATH entries outside the home directory")
		},
		"rootfiles_configured": func(i *nodeinfo.Info) (Status, string) {
			// systemd-tmpfiles provisioning of /root dotfiles exists from RHEL 10;
			// on older releases the STIG check is only the find in
			// file_permission_user_init_files_root
			if major, _, _ := strings.Cut(i.OS.VersionID, "."); isUbuntu(i) || len(major) < 2 {
				return NA, "not applicable before RHEL 10"
			}
			v := cmd(i, "tmpfiles_rootfiles")
			if v == "" {
				return Fail, "no /usr/share/rootfiles entries in /etc/tmpfiles.d"
			}
			for _, e := range strings.Split(v, ";") {
				if f := strings.Fields(e); len(f) >= 3 && f[2] != "600" && f[2] != "0600" {
					return Fail, "tmpfiles entry not 600: " + e
				}
			}
			return Pass, ""
		},
		"accounts_authorized_local_users": func(i *nodeinfo.Info) (Status, string) {
			var names []string
			for _, u := range interactiveUsers(i) {
				names = append(names, u.Name)
			}
			return Manual, "compare against the authorized user list: " + strutil.FirstNonEmpty(strutil.TruncList(names, 8), "-")
		},
		"account_temp_expire_date": func(i *nodeinfo.Info) (Status, string) {
			var exp []string
			for _, u := range interactiveUsers(i) {
				if m, ok := i.ShadowMeta[u.Name]; ok && m.Expire != "" {
					exp = append(exp, u.Name+" expires day "+m.Expire)
				}
			}
			if len(exp) == 0 {
				return Manual, "no interactive account has an expiry date; confirm no temporary accounts exist"
			}
			return Manual, "accounts with expiry: " + strutil.TruncList(exp, 5) + " - confirm temporary ones expire within 72h"
		},
		"ensure_sudo_group_restricted": func(i *nodeinfo.Info) (Status, string) {
			return Manual, "sudo group members: " + strutil.FirstNonEmpty(cmd(i, "sudo_group"), "-") + " - confirm each needs security-function access"
		},
	})
}

func evalDuplicateUIDs(i *nodeinfo.Info) (Status, string) {
	seen := map[int]string{}
	var dup []string
	for _, u := range i.Passwd {
		if prev, ok := seen[u.UID]; ok {
			dup = append(dup, fmt.Sprintf("%d (%s, %s)", u.UID, prev, u.Name))
		}
		seen[u.UID] = u.Name
	}
	return failIf(dup, "duplicate UIDs")
}

// ---------- PAM / faillock / pwquality ----------

func init() {
	pamFaillock := func(path string) namedEval {
		return func(i *nodeinfo.Info) (Status, string) {
			ls, ok := lines(i, path)
			if !ok {
				return Fail, path + " missing"
			}
			preauth, authfail, account, unixIdx, preIdx := false, false, false, -1, -1
			for idx, l := range ls {
				f := strings.Fields(l)
				if len(f) < 3 {
					continue
				}
				switch {
				case f[0] == "auth" && strings.Contains(l, "pam_faillock.so") && strings.Contains(l, "preauth"):
					preauth, preIdx = true, idx
				case f[0] == "auth" && strings.Contains(l, "pam_faillock.so") && strings.Contains(l, "authfail"):
					authfail = true
				case f[0] == "account" && strings.Contains(l, "pam_faillock.so"):
					account = true
				case f[0] == "auth" && strings.Contains(l, "pam_unix.so") && unixIdx < 0:
					unixIdx = idx
				}
			}
			var probs []string
			if !preauth {
				probs = append(probs, "no preauth line")
			} else if unixIdx >= 0 && preIdx > unixIdx {
				probs = append(probs, "preauth after pam_unix.so")
			}
			if !authfail {
				probs = append(probs, "no authfail line")
			}
			if !account {
				probs = append(probs, "no account line")
			}
			if len(probs) > 0 {
				return Fail, path + ": pam_faillock.so " + strings.Join(probs, ", ")
			}
			return Pass, ""
		}
	}
	pamHas := func(rhelFile, module string) namedEval {
		return func(i *nodeinfo.Info) (Status, string) {
			path := pamPasswordFile(i, rhelFile)
			hits, ok := grep(i, rx(`^[^:]*:\s*password\s+\S+.*`+regexp.QuoteMeta(module)), path)
			if !ok {
				return Fail, path + " missing"
			}
			if len(hits) == 0 {
				return Fail, module + " not in " + path
			}
			return Pass, ""
		}
	}
	pamUnixRounds := func(rhelFile string) namedEval {
		return func(i *nodeinfo.Info) (Status, string) {
			path := pamPasswordFile(i, rhelFile)
			hits, ok := grep(i, rx(`^[^:]*:\s*password\s+\S+.*pam_unix\.so`), path)
			if !ok {
				return Fail, path + " missing"
			}
			re := rx(`rounds=(\d+)`)
			for _, h := range hits {
				if m := re.FindStringSubmatch(h); m != nil {
					if n, _ := atoi(m[1]); n >= 100000 {
						return Pass, ""
					}
					return Fail, "pam_unix.so rounds=" + m[1] + " in " + path + " (want >= 100000)"
				}
			}
			return Fail, "pam_unix.so has no rounds= in " + path
		}
	}
	pamUnixSHA512 := func(rhelFile string) namedEval {
		return func(i *nodeinfo.Info) (Status, string) {
			path := pamPasswordFile(i, rhelFile)
			hits, ok := grep(i, rx(`^[^:]*:\s*password\s+\S+.*pam_unix\.so.*\bsha512\b`), path)
			if !ok {
				return Fail, path + " missing"
			}
			if len(hits) == 0 {
				return Fail, "pam_unix.so without sha512 in " + path
			}
			return Pass, ""
		}
	}
	faillockOpt := func(opt, want string) namedEval {
		return func(i *nodeinfo.Info) (Status, string) {
			ls, ok := lines(i, "/etc/security/faillock.conf")
			if !ok {
				// pre-faillock.conf systems carry the options on the preauth line
				hits, _ := grep(i, rx(`pam_faillock\.so.*preauth.*\b`+regexp.QuoteMeta(opt)+`\b`), pamAuthFiles(i)...)
				if len(hits) > 0 {
					return Pass, ""
				}
				return Fail, "/etc/security/faillock.conf missing and " + opt + " not on the preauth line"
			}
			re := rx(`^\s*` + regexp.QuoteMeta(opt) + `\b\s*(?:=\s*(\S+))?`)
			for _, l := range ls {
				if m := re.FindStringSubmatch(l); m != nil {
					if want == "" || m[1] == want {
						return Pass, ""
					}
					if want == "nondefault" && m[1] != "" && m[1] != "/var/run/faillock" {
						return Pass, ""
					}
					return Fail, opt + " = " + m[1] + " in faillock.conf"
				}
			}
			return Fail, opt + " not set in /etc/security/faillock.conf"
		}
	}
	register(map[string]namedEval{
		"account_password_pam_faillock_system_auth":       pamFaillock("/etc/pam.d/system-auth"),
		"account_password_pam_faillock_password_auth":     pamFaillock("/etc/pam.d/password-auth"),
		"accounts_password_pam_pwquality_system_auth":     pamHas("/etc/pam.d/system-auth", "pam_pwquality.so"),
		"accounts_password_pam_pwquality_password_auth":   pamHas("/etc/pam.d/password-auth", "pam_pwquality.so"),
		"accounts_password_pam_unix_rounds_system_auth":   pamUnixRounds("/etc/pam.d/system-auth"),
		"accounts_password_pam_unix_rounds_password_auth": pamUnixRounds("/etc/pam.d/password-auth"),
		"set_password_hashing_algorithm_systemauth":       pamUnixSHA512("/etc/pam.d/system-auth"),
		"set_password_hashing_algorithm_passwordauth":     pamUnixSHA512("/etc/pam.d/password-auth"),
		"set_password_hashing_algorithm_auth_stig":        pamUnixSHA512("/etc/pam.d/password-auth"),
		"accounts_passwords_pam_faillock_audit":           faillockOpt("audit", ""),
		"accounts_passwords_pam_faillock_deny_root":       faillockOpt("even_deny_root", ""),
		"accounts_passwords_pam_faillock_silent":          faillockOpt("silent", ""),
		"accounts_passwords_pam_faillock_dir":             faillockOpt("dir", "nondefault"),
		"account_password_selinux_faillock_dir": func(i *nodeinfo.Info) (Status, string) {
			if !strings.EqualFold(i.Hardening["selinux"], "Enforcing") {
				return NA, "SELinux not enforcing"
			}
			ctx := cmd(i, "faillock_ctx")
			switch {
			case ctx == "":
				return Fail, "/var/log/faillock missing"
			case strings.Contains(ctx, "faillog_t"):
				return Pass, ""
			}
			return Fail, "/var/log/faillock context " + ctx + " (want faillog_t)"
		},
		"accounts_password_pam_retry": func(i *nodeinfo.Info) (Status, string) {
			v, ok := pwqualityValue(i, "retry")
			n, isNum := atoi(v)
			if !ok || !isNum || n < 1 || n > 3 {
				return Fail, "pwquality retry = " + strutil.FirstNonEmpty(v, "-") + " (want 1..3)"
			}
			return Pass, ""
		},
		"disallow_bypass_password_sudo": func(i *nodeinfo.Info) (Status, string) {
			if v := cmd(i, "pam_sudo_succeed"); v != "" {
				return Fail, "/etc/pam.d/sudo: " + v
			}
			return Pass, ""
		},
		"smartcard_pam_enabled": func(i *nodeinfo.Info) (Status, string) {
			hits, ok := grep(i, rx(`pam_pkcs11\.so`), "/etc/pam.d/common-auth")
			if !ok || len(hits) == 0 {
				return Fail, "pam_pkcs11.so not in /etc/pam.d/common-auth (NA only with an approved alternate MFA)"
			}
			return Pass, ""
		},
		"smartcard_configure_cert_checking": pkcs11Policy("ocsp_on"),
		"smartcard_configure_ca":            pkcs11Policy("ca"),
		"smartcard_configure_crl":           pkcs11Policy("crl_auto|crl_offline"),
	})
}

func pkcs11Policy(want string) namedEval {
	re := rx(`\b(` + want + `)\b`)
	return func(i *nodeinfo.Info) (Status, string) {
		hits, ok := grep(i, rx(`cert_policy`), "/etc/pam_pkcs11/pam_pkcs11.conf")
		if !ok {
			if !pkgAny(i, "libpam-pkcs11", "pam_pkcs11") {
				return Fail, "pam_pkcs11 not installed (NA only when smart card authentication is not used)"
			}
			return Fail, "/etc/pam_pkcs11/pam_pkcs11.conf missing"
		}
		if len(hits) == 0 {
			return Fail, "no cert_policy in pam_pkcs11.conf"
		}
		for _, h := range hits {
			if !re.MatchString(h) {
				return Fail, "cert_policy without " + want + ": " + strings.TrimSpace(h)
			}
		}
		return Pass, ""
	}
}

// ---------- sudo ----------

func init() {
	sudoers := []string{"/etc/sudoers", "/etc/sudoers.d/"}
	register(map[string]namedEval{
		"sudo_remove_nopasswd": func(i *nodeinfo.Info) (Status, string) {
			hits, _ := grep(i, rx(`\bNOPASSWD\b`), sudoers...)
			if len(hits) > 0 {
				return Fail, "NOPASSWD in " + strutil.TruncList(hits, 3) + " (must be documented as an MFA admin group)"
			}
			return Pass, ""
		},
		"sudo_remove_no_authenticate": sudoNoAuthenticate,
		"sudo_require_authentication": sudoNoAuthenticate,
		"sudo_require_reauthentication": func(i *nodeinfo.Info) (Status, string) {
			hits, _ := grep(i, rx(`(?i)timestamp_timeout\s*=\s*(-?\d+)`), sudoers...)
			if len(hits) == 0 {
				return Fail, "timestamp_timeout not set in sudoers"
			}
			files := map[string]bool{}
			re := rx(`(?i)timestamp_timeout\s*=\s*(-?\d+)`)
			for _, h := range hits {
				f, _, _ := strings.Cut(h, ": ")
				files[f] = true
				if m := re.FindStringSubmatch(h); m != nil {
					if n, _ := atoi(m[1]); n < 0 {
						return Fail, "timestamp_timeout negative: " + h
					}
				}
			}
			if len(files) > 1 {
				return Fail, "timestamp_timeout set in more than one file"
			}
			return Pass, ""
		},
		"sudoers_validate_passwd": func(i *nodeinfo.Info) (Status, string) {
			var missing []string
			files := map[string]bool{}
			for _, opt := range []string{"!targetpw", "!rootpw", "!runaspw"} {
				hits, _ := grep(i, rx(`(?i)^[^:]*:\s*Defaults\b.*`+regexp.QuoteMeta(opt)), sudoers...)
				if len(hits) == 0 {
					missing = append(missing, opt)
				}
				for _, h := range hits {
					f, _, _ := strings.Cut(h, ": ")
					files[f] = true
				}
			}
			if len(missing) > 0 {
				return Fail, "Defaults " + strings.Join(missing, ", ") + " not set"
			}
			if len(files) > 1 {
				return Fail, "set in more than one sudoers file"
			}
			return Pass, ""
		},
		"sudo_restrict_privilege_elevation_to_authorized": func(i *nodeinfo.Info) (Status, string) {
			hits, _ := grep(i, rx(`^[^:]*:\s*ALL\s+ALL\s*=\s*\(ALL(:ALL)?\)\s+ALL`), sudoers...)
			return failIf(hits, "sudoers entries granting ALL to everyone")
		},
		"sudoers_default_includedir": func(i *nodeinfo.Info) (Status, string) {
			c, ok := i.STIGFile("/etc/sudoers")
			if !ok {
				return Fail, "/etc/sudoers missing"
			}
			re := rx(`(?m)^\s*[#@]include(dir)?\s+(\S+)`)
			ms := re.FindAllStringSubmatch(c, -1)
			if len(ms) == 0 {
				return NA, "no include directives"
			}
			for _, m := range ms {
				if m[2] != "/etc/sudoers.d" {
					return Fail, "include of " + m[2]
				}
			}
			nested, _ := grep(i, rx(`^[^:]*:\s*[#@]include`), "/etc/sudoers.d/")
			return failIf(nested, "nested includes in /etc/sudoers.d")
		},
		"selinux_context_elevation_for_sudo": func(i *nodeinfo.Info) (Status, string) {
			hits, _ := grep(i, rx(`sysadm_r`), sudoers...)
			if len(hits) == 0 {
				return Fail, "no sudoers entry elevating to TYPE=sysadm_t ROLE=sysadm_r"
			}
			return Pass, ""
		},
		"selinux_user_login_roles": func(i *nodeinfo.Info) (Status, string) {
			if len(i.SELinuxLogins) == 0 {
				return Manual, "semanage login -l unavailable"
			}
			for _, l := range i.SELinuxLogins {
				f := strings.Fields(l)
				if len(f) >= 2 && f[0] == "__default__" {
					if f[1] == "user_u" {
						return Pass, ""
					}
					return Fail, "__default__ mapped to " + f[1] + " (want user_u; admins to sysadm_u/staff_u)"
				}
			}
			return Fail, "no __default__ login mapping"
		},
	})
}

func sudoNoAuthenticate(i *nodeinfo.Info) (Status, string) {
	hits, _ := grep(i, rx(`!authenticate`), "/etc/sudoers", "/etc/sudoers.d/")
	return failIf(hits, "!authenticate in sudoers")
}

// ---------- umask / sessions / limits / systemd ----------

func init() {
	register(map[string]namedEval{
		"accounts_umask_etc_bashrc": func(i *nodeinfo.Info) (Status, string) {
			if isUbuntu(i) {
				return umaskFile(i, "/etc/bash.bashrc", false)
			}
			return umaskFile(i, "/etc/bashrc", false)
		},
		"accounts_umask_etc_profile":   func(i *nodeinfo.Info) (Status, string) { return umaskFile(i, "/etc/profile", false) },
		"accounts_umask_etc_csh_cshrc": func(i *nodeinfo.Info) (Status, string) { return umaskFile(i, "/etc/csh.cshrc", true) },
		"accounts_tmout": func(i *nodeinfo.Info) (Status, string) {
			hits, _ := grep(i, rx(`\bTMOUT\s*=\s*(\d+)`), "/etc/profile", "/etc/profile.d/")
			re := rx(`\bTMOUT\s*=\s*(\d+)`)
			for _, h := range hits {
				if m := re.FindStringSubmatch(h); m != nil {
					if n, _ := atoi(m[1]); n > 0 && n <= 600 {
						return Pass, ""
					}
					return Fail, "TMOUT=" + m[1] + " (want 1..600)"
				}
			}
			return Fail, "TMOUT not set in /etc/profile.d"
		},
		"accounts_max_concurrent_login_sessions": func(i *nodeinfo.Info) (Status, string) {
			re := rx(`^[^:]*:\s*\S+\s+(?:hard|-)\s+maxlogins\s+(\d+)`)
			hits, _ := grep(i, re, "/etc/security/limits.conf", "/etc/security/limits.d/")
			if len(hits) == 0 {
				return Fail, "no hard maxlogins in limits.conf"
			}
			for _, h := range hits {
				if m := re.FindStringSubmatch(h); m != nil {
					if n, _ := atoi(m[1]); n > 10 {
						return Fail, "maxlogins " + m[1] + " (want <= 10)"
					}
				}
			}
			return Pass, ""
		},
		"disable_users_coredumps": func(i *nodeinfo.Info) (Status, string) {
			re := rx(`^[^:]*:\s*(\S+)\s+(?:hard|-)\s+core\s+(\d+)`)
			hits, _ := grep(i, re, "/etc/security/limits.conf", "/etc/security/limits.d/")
			global := false
			for _, h := range hits {
				m := re.FindStringSubmatch(h)
				if m == nil {
					continue
				}
				if m[2] != "0" {
					return Fail, "core limit " + m[2] + " for " + m[1]
				}
				if m[1] == "*" {
					global = true
				}
			}
			if !global {
				return Fail, "no '* hard core 0' in limits.conf"
			}
			return Pass, ""
		},
		"logind_session_timeout": func(i *nodeinfo.Info) (Status, string) {
			v, ok := keyValue(i, "StopIdleSessionSec", "/etc/systemd/logind.conf", "/etc/systemd/logind.conf.d/")
			n, isNum := atoi(v)
			if !ok || !isNum || n < 1 || n > 600 {
				return Fail, "StopIdleSessionSec=" + strutil.FirstNonEmpty(v, "-") + " (want 1..600)"
			}
			return Pass, ""
		},
		"disable_ctrlaltdel_burstaction": func(i *nodeinfo.Info) (Status, string) {
			v, ok := keyValue(i, "CtrlAltDelBurstAction", "/etc/systemd/system.conf", "/etc/systemd/system.conf.d/")
			if ok && strings.EqualFold(v, "none") {
				return Pass, ""
			}
			return Fail, "CtrlAltDelBurstAction=" + strutil.FirstNonEmpty(v, "-") + " (want none)"
		},
		"disable_ctrlaltdel_reboot": func(i *nodeinfo.Info) (Status, string) {
			if st := i.UnitFiles["ctrl-alt-del.target"]; st == "masked" || st == "masked-runtime" {
				return Pass, ""
			}
			return Fail, "ctrl-alt-del.target not masked (" + strutil.FirstNonEmpty(i.UnitFiles["ctrl-alt-del.target"], "-") + ")"
		},
		"xwindows_runlevel_target": func(i *nodeinfo.Info) (Status, string) {
			t := cmd(i, "default_target")
			if t == "multi-user.target" {
				return Pass, ""
			}
			return Fail, "default target " + strutil.FirstNonEmpty(t, "-") + " (graphical needs ISSO documentation)"
		},
		"xwindows_remove_packages": func(i *nodeinfo.Info) (Status, string) {
			if pkgAny(i, "xorg-x11-server-common", "xorg-x11-server-Xorg", "xserver-xorg-core") {
				return Fail, "X server installed (needs ISSO documentation)"
			}
			return Pass, ""
		},
		"require_emergency_target_auth": sulogin("emergency_sulogin", "emergency.service"),
		"require_singleuser_auth":       sulogin("rescue_sulogin", "rescue.service"),
	})
}

func sulogin(key, unit string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		if strings.Contains(cmd(i, key), "sulogin") {
			return Pass, ""
		}
		return Fail, unit + " ExecStart does not use systemd-sulogin-shell"
	}
}

// ---------- GNOME (N/A without a desktop) ----------

func noGUI(i *nodeinfo.Info) bool {
	return !pkgAny(i, "gdm", "gdm3", "gnome-shell", "gnome-session")
}

// dconfKey finds "key=value" under the section in the dumped dconf keyfiles.
func dconfKey(i *nodeinfo.Info, section, key string) (string, bool) {
	val, found := "", false
	for _, f := range i.STIGFilesGlob("/etc/dconf/db/") {
		if strings.Contains(f.Path, "/locks/") {
			continue
		}
		if v, ok := iniValue(f.Content, section, key, "="); ok {
			val, found = v, true
		}
	}
	return val, found
}

func dconfLocked(i *nodeinfo.Info, path string) bool {
	for _, f := range i.STIGFilesGlob("/etc/dconf/db/") {
		if !strings.Contains(f.Path, "/locks/") {
			continue
		}
		for _, l := range strings.Split(f.Content, "\n") {
			if strings.TrimSpace(l) == path {
				return true
			}
		}
	}
	return false
}

func gnomeSetting(section, key, want string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		if noGUI(i) {
			return NA, "no GNOME desktop installed"
		}
		v, ok := dconfKey(i, section, key)
		if !ok {
			return Fail, key + " not set under /etc/dconf/db"
		}
		if strings.Trim(v, `'"`) == strings.Trim(want, `'"`) {
			return Pass, ""
		}
		return Fail, key + "=" + v + " (want " + want + ")"
	}
}

func gnomeLock(path string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		if noGUI(i) {
			return NA, "no GNOME desktop installed"
		}
		if dconfLocked(i, path) {
			return Pass, ""
		}
		return Fail, path + " not locked under /etc/dconf/db/*/locks"
	}
}

func gnomeUint(section, key string, ok func(int) bool, want string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		if noGUI(i) {
			return NA, "no GNOME desktop installed"
		}
		v, found := dconfKey(i, section, key)
		if !found {
			return Fail, key + " not set under /etc/dconf/db"
		}
		n, isNum := atoi(strings.TrimPrefix(strings.TrimSpace(v), "uint32 "))
		if !isNum || !ok(n) {
			return Fail, key + "=" + v + " (want " + want + ")"
		}
		return Pass, ""
	}
}

func init() {
	register(map[string]namedEval{
		"dconf_gnome_banner_enabled":            gnomeSetting("org/gnome/login-screen", "banner-message-enable", "true"),
		"dconf_gnome_disable_automount_open":    gnomeSetting("org/gnome/desktop/media-handling", "automount-open", "false"),
		"dconf_gnome_disable_autorun":           gnomeSetting("org/gnome/desktop/media-handling", "autorun-never", "true"),
		"dconf_gnome_screensaver_lock_enabled":  gnomeSetting("org/gnome/desktop/screensaver", "lock-enabled", "true"),
		"dconf_gnome_disable_restart_shutdown":  gnomeSetting("org/gnome/login-screen", "disable-restart-buttons", "true"),
		"dconf_gnome_disable_user_list":         gnomeSetting("org/gnome/login-screen", "disable-user-list", "true"),
		"dconf_gnome_disable_ctrlaltdel_reboot": gnomeSetting("org/gnome/settings-daemon/plugins/media-keys", "logout", "['']"),
		"dconf_gnome_screensaver_idle_delay":    gnomeUint("org/gnome/desktop/session", "idle-delay", func(n int) bool { return n > 0 && n <= 600 }, "1..600"),
		"dconf_gnome_screensaver_lock_delay":    gnomeUint("org/gnome/desktop/screensaver", "lock-delay", func(n int) bool { return n <= 5 }, "<= 5"),
		"dconf_gnome_session_idle_user_locks":   gnomeLock("/org/gnome/desktop/session/idle-delay"),
		"dconf_gnome_screensaver_user_locks":    gnomeLock("/org/gnome/desktop/screensaver/lock-delay"),
		"dconf_gnome_screensaver_lock_locked":   gnomeLock("/org/gnome/desktop/screensaver/lock-enabled"),
		"dconf_gnome_screensaver_mode_blank":    gnomeLock("/org/gnome/desktop/screensaver/picture-uri"),
		"dconf_gnome_login_banner_text": func(i *nodeinfo.Info) (Status, string) {
			if noGUI(i) {
				return NA, "no GNOME desktop installed"
			}
			v, ok := dconfKey(i, "org/gnome/login-screen", "banner-message-text")
			if ok && strings.Contains(v, "You are accessing a U.S. Government (USG) Information System (IS)") {
				return Pass, ""
			}
			return Fail, "banner-message-text is not the DoD banner"
		},
		"dconf_db_up_to_date": func(i *nodeinfo.Info) (Status, string) {
			if noGUI(i) {
				return NA, "no GNOME desktop installed"
			}
			if v := cmd(i, "dconf_stale"); v != "" {
				return Fail, "dconf databases older than their keyfiles: " + v + " (run dconf update)"
			}
			return Pass, ""
		},
		"gnome_gdm_disable_automatic_login": func(i *nodeinfo.Info) (Status, string) {
			if noGUI(i) {
				return NA, "no GNOME desktop installed"
			}
			v, ok := keyValue(i, "AutomaticLoginEnable", "/etc/gdm/custom.conf", "/etc/gdm3/custom.conf")
			if ok && strings.EqualFold(v, "false") {
				return Pass, ""
			}
			return Fail, "AutomaticLoginEnable=" + strutil.FirstNonEmpty(v, "-") + " in gdm custom.conf (want false)"
		},
	})
}

// ---------- packages / repositories / vendor support ----------

// endOfSupport is the vendor end of standard support per product.
var endOfSupport = map[string]time.Time{
	"rhel8":      time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC),
	"rhel9":      time.Date(2032, 5, 31, 0, 0, 0, 0, time.UTC),
	"rhel10":     time.Date(2035, 5, 31, 0, 0, 0, 0, time.UTC),
	"ubuntu2204": time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
	"ubuntu2404": time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC),
}

func init() {
	register(map[string]namedEval{
		"installed_OS_is_vendor_supported": func(i *nodeinfo.Info) (Status, string) {
			b := OSBenchmarkFor(i.OS)
			if b == nil {
				return Manual, "unknown product"
			}
			eol, ok := endOfSupport[b.product]
			if !ok {
				return Manual, "no support window recorded for " + b.product
			}
			if time.Now().Before(eol) {
				return Pass, ""
			}
			if pro := strings.ToLower(i.Hardening["ubuntu_pro"]); strings.Contains(pro, "esm-infra") && strings.Contains(pro, "enabled") {
				return Pass, ""
			}
			return Fail, i.OS.Pretty + " left vendor standard support on " + eol.Format("2006-01-02")
		},
		"security_patches_up_to_date": func(i *nodeinfo.Info) (Status, string) {
			d := "verify against the organizational patching policy"
			if i.Hardening["reboot_required"] == "yes" {
				d += "; a reboot is pending (updates applied but not active)"
			}
			return Manual, d
		},
		"ensure_gpgcheck_globally_activated": dnfConf("gpgcheck", "1"),
		"ensure_gpgcheck_local_packages":     dnfConf("localpkg_gpgcheck", "1"),
		"clean_components_post_updating": func(i *nodeinfo.Info) (Status, string) {
			if isUbuntu(i) {
				hits, _ := grep(i, rx(`(?i)Remove-Unused-Dependencies\s+"true"`), "/etc/apt/apt.conf.d/")
				if len(hits) == 0 {
					return Fail, `Unattended-Upgrade::Remove-Unused-Dependencies "true" not set in /etc/apt/apt.conf.d`
				}
				return Pass, ""
			}
			return dnfConf("clean_requirements_on_remove", "True")(i)
		},
		"ensure_gpgcheck_never_disabled":       repoGpgcheck,
		"enable_gpgcheck_for_all_repositories": repoGpgcheck,
		"ensure_redhat_gpgkey_installed": func(i *nodeinfo.Info) (Status, string) {
			keys := cmd(i, "gpg_keys")
			switch {
			case strings.Contains(keys, "release key 2") && strings.Contains(keys, "auxiliary key 3"):
				return Pass, ""
			case strings.Contains(keys, "release key 2"):
				return Fail, "Red Hat auxiliary key 3 not imported"
			case strings.Contains(strings.ToLower(keys), "rocky"), strings.Contains(strings.ToLower(keys), "almalinux"), strings.Contains(strings.ToLower(keys), "oracle"), strings.Contains(strings.ToLower(keys), "centos"):
				return Pass, "vendor key: " + firstField(keys)
			}
			return Fail, "no vendor package-signing key imported"
		},
		"ensure_epel_repos_disabled": func(i *nodeinfo.Info) (Status, string) {
			var epel []string
			for _, r := range strings.Fields(cmd(i, "repos")) {
				if strings.Contains(strings.ToLower(r), "epel") {
					epel = append(epel, r)
				}
			}
			return failIf(epel, "EPEL repositories enabled")
		},
		"apt_conf_disallow_unauthenticated": func(i *nodeinfo.Info) (Status, string) {
			hits, _ := grep(i, rx(`(?i)AllowUnauthenticated\s+"?true`), "/etc/apt/apt.conf.d/")
			return failIf(hits, "AllowUnauthenticated true")
		},
		"kerberos_disable_no_keytab": func(i *nodeinfo.Info) (Status, string) {
			if v := cmd(i, "keytabs"); v != "" {
				if pkgAny(i, "krb5-server", "krb5-workstation") {
					return NA, "krb5 packages installed (keytabs expected): " + v
				}
				return Fail, "keytabs present: " + v
			}
			return Pass, ""
		},
		"tftp_uses_secure_mode_systemd": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "tftp-server", "tftpd-hpa") {
				return NA, "tftp server not installed"
			}
			if strings.Contains(cmd(i, "tftp_execstart"), " -s ") {
				return Pass, ""
			}
			return Fail, "tftp.service ExecStart lacks -s (secure mode)"
		},
	})
}

func dnfConf(key, want string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		v, ok := keyValue(i, key, "/etc/dnf/dnf.conf")
		if ok && strings.EqualFold(v, want) {
			return Pass, ""
		}
		return Fail, key + "=" + strutil.FirstNonEmpty(v, "-") + " in /etc/dnf/dnf.conf (want " + want + ")"
	}
}

func repoGpgcheck(i *nodeinfo.Info) (Status, string) {
	hits, found := grep(i, rx(`(?i)^[^:]*:\s*gpgcheck\s*=\s*0`), "/etc/yum.repos.d/")
	if !found {
		return Manual, "no repo files dumped"
	}
	return failIf(hits, "repositories with gpgcheck=0")
}

func firstField(s string) string {
	s, _, _ = strings.Cut(s, ";")
	return strings.TrimSpace(s)
}

// rxCache holds every pattern the named evaluators use. They are built at
// evaluation time (some from the rule's key), and a recompute evaluates
// ~450 rules per node, so compiling per call was a quarter of Evaluate.
var rxCache sync.Map

// rx returns the compiled pattern, compiling it once.
func rx(pattern string) *regexp.Regexp {
	if v, ok := rxCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	v, _ := rxCache.LoadOrStore(pattern, re)
	return v.(*regexp.Regexp)
}
