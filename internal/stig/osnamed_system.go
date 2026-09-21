package stig

// Named evaluators, part 2: audit, rsyslog, chrony, crypto policy and SSH,
// firewall, filesystem sweep, AIDE, boot loader, SSSD/PKI and miscellany.
// See osnamed.go for the registry and helpers.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// ---------- auditd.conf / audit rules ----------

func auditdConf(key string, ok func(v string) bool, want string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		v, found := keyValue(i, key, "/etc/audit/auditd.conf")
		if !found {
			if !pkgAny(i, "audit", "auditd") {
				return Fail, "auditd not installed"
			}
			return Fail, key + " not set in /etc/audit/auditd.conf"
		}
		if ok(strings.ToLower(v)) {
			return Pass, ""
		}
		return Fail, key + " = " + v + " (want " + want + ")"
	}
}

func oneOf(vals ...string) func(string) bool {
	return func(v string) bool {
		for _, w := range vals {
			if v == strings.ToLower(w) {
				return true
			}
		}
		return false
	}
}

func auditRuleFileHas(re *regexp.Regexp) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		src := i.AuditRuleFiles
		if len(src) == 0 {
			return Fail, "no audit rules configured"
		}
		for _, l := range src {
			if re.MatchString(l) {
				return Pass, ""
			}
		}
		return Fail, "no rule matching " + re.String() + " in /etc/audit/rules.d"
	}
}

func init() {
	register(map[string]namedEval{
		"auditd_data_disk_error_action":                  auditdConf("disk_error_action", oneOf("syslog", "single", "halt"), "SYSLOG|SINGLE|HALT"),
		"auditd_data_disk_error_action_stig":             auditdConf("disk_error_action", oneOf("syslog", "single", "halt"), "SYSLOG|SINGLE|HALT"),
		"auditd_data_disk_full_action":                   auditdConf("disk_full_action", oneOf("syslog", "single", "halt"), "SYSLOG|SINGLE|HALT"),
		"auditd_data_disk_full_action_stig":              auditdConf("disk_full_action", oneOf("syslog", "single", "halt"), "SYSLOG|SINGLE|HALT"),
		"auditd_data_retention_action_mail_acct":         auditdConf("action_mail_acct", func(v string) bool { return v != "" }, "root or the SA/ISSO address"),
		"auditd_data_retention_admin_space_left_action":  auditdConf("admin_space_left_action", oneOf("single"), "single"),
		"auditd_data_retention_max_log_file_action_stig": auditdConf("max_log_file_action", oneOf("rotate", "single"), "ROTATE|SINGLE"),
		"auditd_name_format":                             auditdConf("name_format", oneOf("hostname", "fqd", "numeric"), "hostname|fqd|numeric"),
		"auditd_overflow_action":                         auditdConf("overflow_action", oneOf("syslog", "single", "halt"), "syslog|single|halt"),
		"auditd_data_retention_admin_space_left_percentage": auditdConf("admin_space_left", func(v string) bool {
			return v == "5%" || v == "5 %"
		}, "5%"),
		"auditd_data_retention_space_left_action": func(i *nodeinfo.Info) (Status, string) {
			if isUbuntu(i) {
				return auditdConf("space_left_action", func(v string) bool { return v != "" && v != "ignore" }, "email|exec|syslog")(i)
			}
			return auditdConf("space_left_action", oneOf("email"), "email")(i)
		},
		"auditd_data_retention_space_left_percentage": func(i *nodeinfo.Info) (Status, string) {
			v, ok := keyValue(i, "space_left", "/etc/audit/auditd.conf")
			if !ok {
				return Fail, "space_left not set"
			}
			if strings.HasSuffix(v, "%") {
				if n, isNum := atoi(strings.TrimSuffix(v, "%")); isNum && n >= 25 {
					return Pass, ""
				}
				return Fail, "space_left = " + v + " (want >= 25%)"
			}
			return Manual, "space_left = " + v + " (absolute; confirm it is >= 25% of the audit partition)"
		},
		"auditd_audispd_configure_sufficiently_large_partition": func(i *nodeinfo.Info) (Status, string) {
			dir := "/var/log/audit"
			if lf := cmd(i, "audit_log_file"); lf != "" {
				if idx := strings.LastIndex(lf, "/"); idx > 0 {
					dir = lf[:idx]
				}
			}
			var best *nodeinfo.Mount
			for idx := range i.Mounts {
				m := &i.Mounts[idx]
				if strings.HasPrefix(dir+"/", strings.TrimRight(m.Mountpoint, "/")+"/") && (best == nil || len(m.Mountpoint) > len(best.Mountpoint)) {
					best = m
				}
			}
			if best == nil {
				return Manual, "audit partition size unknown"
			}
			gb := float64(best.SizeKB) / 1024 / 1024
			if best.Mountpoint == "/" {
				return Manual, fmt.Sprintf("%s is on the root filesystem (%.0f GB); a dedicated partition sized for one week of records is expected", dir, gb)
			}
			if gb >= 10 {
				return Pass, fmt.Sprintf("%s on %s (%.0f GB)", dir, best.Mountpoint, gb)
			}
			return Manual, fmt.Sprintf("%s on %s is %.1f GB; confirm it holds one week of records", dir, best.Mountpoint, gb)
		},
		"audit_rules_immutable":            auditRuleFileHas(rx(`^\s*-e\s+2\b`)),
		"audit_rules_immutable_login_uids": auditRuleFileHas(rx(`^\s*--loginuid-immutable\b`)),
		"audit_rules_system_shutdown":      auditRuleFileHas(rx(`^\s*-f\s+2\b`)),
		"audit_rules_suid_privilege_function": func(i *nodeinfo.Info) (Status, string) {
			rules, src := auditRulesOf(i)
			if src == "" {
				return Fail, "no audit rules loaded or configured"
			}
			var missing []string
			for _, f := range []string{"uid!=euid", "gid!=egid"} {
				ok, why := syscallCovered(i, rules, "execve", func(r auditRule) bool { return strings.Contains(r.raw, f) })
				if !ok {
					missing = append(missing, f+": "+why)
				}
			}
			return failIf(missing, "execve setuid/setgid audit rules missing")
		},
		"audit_rules_cron_execution": func(i *nodeinfo.Info) (Status, string) {
			rules, src := auditRulesOf(i)
			if src == "" {
				return Fail, "no audit rules loaded or configured"
			}
			ok, why := syscallCovered(i, rules, "execve", func(r auditRule) bool { return r.hasField("subj_type=crond_t") })
			if !ok {
				return Fail, why + " with subj_type=crond_t (" + src + ")"
			}
			return Pass, ""
		},
		"audit_rules_dac_modification_umount": func(i *nodeinfo.Info) (Status, string) {
			rules, src := auditRulesOf(i)
			if src == "" {
				return Fail, "no audit rules loaded or configured"
			}
			for _, r := range rules {
				if r.syscalls["umount"] && (r.arch == "b32" || r.arch == "") {
					return Pass, ""
				}
			}
			return Fail, "no b32 rule auditing umount (" + src + ")"
		},
		"audit_rules_privileged_commands_modprobe": auditWatchExec("/sbin/modprobe", "/usr/sbin/modprobe"),
		"audit_rules_privileged_commands_fdisk":    auditWatchExec("/sbin/fdisk", "/usr/sbin/fdisk"),
		"auditd_offload_logs": func(i *nodeinfo.Info) (Status, string) {
			return Manual, "standalone systems need a weekly audit off-load script in /etc/cron.weekly; interconnected systems: NA"
		},
		"directory_ownership_var_log_audit": auditDir(func(f []string) string {
			if f[2] != "root" {
				return "owner " + f[2]
			}
			return ""
		}),
		"directory_group_ownership_var_log_audit": func(i *nodeinfo.Info) (Status, string) {
			group := "root"
			if v, ok := keyValue(i, "log_group", "/etc/audit/auditd.conf"); ok && v != "" {
				group = v
			}
			var bad []string
			for _, l := range sweep(i, "AUDITLOGGROUP") {
				if f := strings.Split(l, "|"); len(f) == 2 && f[1] != group {
					bad = append(bad, l)
				}
			}
			return failIf(bad, "audit logs not group-owned by "+group)
		},
		"directory_permissions_var_log_audit": auditDir(func(f []string) string {
			if m, ok := modeBits(f[1]); ok && m&^0o700 != 0 {
				return "mode " + f[1]
			}
			return ""
		}),
		"file_permissions_var_log_audit": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "AUDITLOGPERM"), "audit logs more permissive than 0600")
		},
		"file_permissions_var_log_audit_stig": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "AUDITLOGPERM"), "audit logs more permissive than 0600")
		},
		"file_ownership_var_log_audit_stig": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "AUDITLOGOWNER"), "audit logs not owned by root")
		},
		"file_group_ownership_var_log_audit": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "AUDITLOGGROUP"), "audit logs not group-owned by root")
		},
		"file_group_ownership_var_log_audit_stig": func(i *nodeinfo.Info) (Status, string) {
			return failIf(sweep(i, "AUDITLOGGROUP"), "audit logs not group-owned by root")
		},
	})
}

func auditWatchExec(paths ...string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		rules, src := auditRulesOf(i)
		if src == "" {
			return Fail, "no audit rules loaded or configured"
		}
		for _, r := range rules {
			for _, p := range paths {
				if (r.watch == p || r.path == p) && strings.Contains(r.perms, "x") {
					return Pass, ""
				}
			}
		}
		return Fail, "no audit rule for execution of " + paths[0] + " (" + src + ")"
	}
}

// auditDir checks the AUDITDIR sweep line: path|mode|owner|group.
func auditDir(pred func(f []string) string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		for _, l := range sweep(i, "AUDITDIR") {
			f := strings.Split(l, "|")
			if len(f) < 4 {
				continue
			}
			if d := pred(f); d != "" {
				return Fail, f[0] + " " + d
			}
			return Pass, ""
		}
		return Fail, "/var/log/audit not present"
	}
}

// ---------- rsyslog ----------

func rsyslogGrep(re *regexp.Regexp, missing string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		hits, found := grep(i, re, "/etc/rsyslog.conf", "/etc/rsyslog.d/")
		if !found {
			if !pkgAny(i, "rsyslog") {
				return Manual, "rsyslog not installed; confirm the alternative log shipper covers this"
			}
			return Fail, "rsyslog configuration not readable"
		}
		if len(hits) == 0 {
			return Fail, missing
		}
		return Pass, ""
	}
}

func init() {
	register(map[string]namedEval{
		"rsyslog_nolisten": func(i *nodeinfo.Info) (Status, string) {
			hits, _ := grep(i, rx(`(?i)InputTCPServerRun|UDPServerRun|RELPServerRun|imtcp|imudp|imrelp`), "/etc/rsyslog.conf", "/etc/rsyslog.d/")
			if len(hits) > 0 {
				return Fail, "rsyslog listens for remote logs (only a log aggregation server may): " + strutil.TruncList(hits, 2)
			}
			return Pass, ""
		},
		"rsyslog_remote_access_monitoring":                       rsyslogGrep(rx(`(auth\.\*|authpriv\.\*|daemon\.\*)`), "auth.*, authpriv.* or daemon.* not logged"),
		"rsyslog_remote_loghost":                                 rsyslogGrep(rx(`@@|type="omfwd"`), "no remote log host (@@host or omfwd)"),
		"rsyslog_cron_logging":                                   rsyslogGrep(rx(`(?i)(^|[;:\s])cron\.\*|^[^:]*:\s*\*\.\*\s`), "cron facility not logged"),
		"rsyslog_encrypt_offload_defaultnetstreamdriver":         rsyslogGrep(rx(`(?i)\$DefaultNetstreamDriver\s+gtls|StreamDriver(\.Name)?\s*=\s*"?(gtls|ossl)`), "$DefaultNetstreamDriver gtls not set"),
		"rsyslog_omfwd_streamdriver":                             rsyslogGrep(rx(`(?i)StreamDriver\s*=\s*"(gtls|ossl)"`), `no StreamDriver="gtls"/"ossl" in an omfwd action`),
		"rsyslog_encrypt_offload_actionsendstreamdrivermode":     rsyslogGrep(rx(`(?i)\$ActionSendStreamDriverMode\s+1|StreamDriver\.?Mode\s*=\s*"?1`), "$ActionSendStreamDriverMode 1 not set"),
		"rsyslog_omfwd_tls":                                      rsyslogGrep(rx(`(?i)tls="on"|StreamDriver\.Mode\s*=\s*"1"`), `no tls="on" / StreamDriver.Mode="1" in an omfwd action`),
		"rsyslog_encrypt_offload_actionsendstreamdriverauthmode": rsyslogGrep(rx(`(?i)StreamDriver\.?AuthMode\s*=?\s*"?x509/name`), "$ActionSendStreamDriverAuthMode x509/name not set"),
		"rsyslog_omfwd_authmode":                                 rsyslogGrep(rx(`(?i)(streamdriver|tls)\.authmode\s*=\s*"x509/name"`), `no streamdriver.authmode="x509/name" in an omfwd action`),
	})
}

// ---------- chrony ----------

var chronyFiles = []string{"/etc/chrony.conf", "/etc/chrony/chrony.conf", "/etc/chrony/conf.d/", "/etc/chrony/sources.d/"}

func chronyGrep(re *regexp.Regexp, missing string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		hits, found := grep(i, re, chronyFiles...)
		if !found {
			return Fail, "chrony not configured"
		}
		if len(hits) == 0 {
			return Fail, missing
		}
		return Pass, ""
	}
}

func init() {
	servers := rx(`^[^:]*:\s*(server|pool|peer)\s+\S+`)
	register(map[string]namedEval{
		"chronyd_server_directive":       chronyGrep(servers, "no server/pool directive"),
		"chronyd_specify_remote_server":  chronyGrep(servers, "no server/pool directive"),
		"chronyd_client_only":            chronyGrep(rx(`^[^:]*:\s*port\s+0\b`), "port 0 not set (chronyd may act as a server)"),
		"chronyd_no_chronyc_network":     chronyGrep(rx(`^[^:]*:\s*cmdport\s+0\b`), "cmdport 0 not set"),
		"chronyd_configure_local_socket": chronyGrep(rx(`^[^:]*:\s*cmdport\s+0\b`), "cmdport 0 not set"),
		"chronyd_or_ntpd_set_maxpoll": func(i *nodeinfo.Info) (Status, string) {
			hits, found := grep(i, servers, chronyFiles...)
			if !found || len(hits) == 0 {
				return Fail, "no server/pool directive"
			}
			re := rx(`\bmaxpoll\s+(\d+)`)
			for _, h := range hits {
				m := re.FindStringSubmatch(h)
				if m == nil {
					return Fail, "no maxpoll on: " + strings.TrimSpace(h)
				}
				if n, _ := atoi(m[1]); n > 16 {
					return Fail, "maxpoll " + m[1] + " > 16"
				}
			}
			return Pass, ""
		},
	})
}

// ---------- crypto policy / SSH ----------

var (
	rhelCiphers = "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"
	rhelMACs    = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
	ubCiphers   = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
	ubMACs      = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
	ubKex       = "ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256"
)

func sameSet(a, b string) bool {
	as, bs := strings.Split(a, ","), strings.Split(b, ",")
	if len(as) != len(bs) {
		return false
	}
	m := map[string]bool{}
	for _, x := range as {
		m[strings.TrimSpace(x)] = true
	}
	for _, x := range bs {
		if !m[strings.TrimSpace(x)] {
			return false
		}
	}
	return true
}

// cryptoBackend checks a "Ciphers ..." / "MACs ..." line in a crypto-policies
// back-end file (RHEL 9/10 "Ciphers a,b" or RHEL 8 "-oCiphers=a,b").
func cryptoBackend(path, key, want string) namedEval {
	re := rx(`(?im)^\s*(?:CRYPTO_POLICY=.*-o)?` + key + `[= ]([^ '"\n]+)`)
	return func(i *nodeinfo.Info) (Status, string) {
		c, ok := i.STIGFile(path)
		if !ok {
			return Fail, path + " missing"
		}
		m := re.FindStringSubmatch(c)
		if m == nil {
			return Fail, key + " not in " + path
		}
		if sameSet(m[1], want) {
			return Pass, ""
		}
		return Fail, key + " " + m[1] + " (want " + want + ")"
	}
}

// sshConfigExact checks a keyword in sshd_config / ssh_config (+ .d) for an
// exact, ordered list; conflicting lines fail.
func sshConfigExact(files []string, key, want string) namedEval {
	re := rx(`(?i)^[^:]*:\s*` + key + `\s+(\S+)`)
	return func(i *nodeinfo.Info) (Status, string) {
		hits, found := grep(i, re, files...)
		if !found {
			return Fail, files[0] + " missing"
		}
		vals := map[string]bool{}
		for _, h := range hits {
			if m := re.FindStringSubmatch(h); m != nil {
				vals[m[1]] = true
			}
		}
		switch {
		case len(vals) == 0:
			return Fail, key + " not set"
		case len(vals) > 1:
			return Fail, "conflicting " + key + " lines"
		}
		for v := range vals {
			if v == want {
				return Pass, ""
			}
			return Fail, key + " " + v + " (want " + want + ")"
		}
		return Fail, ""
	}
}

func init() {
	sshdFiles := []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/"}
	sshFiles := []string{"/etc/ssh/ssh_config", "/etc/ssh/ssh_config.d/"}
	register(map[string]namedEval{
		"configure_crypto_policy": func(i *nodeinfo.Info) (Status, string) {
			p := cmd(i, "crypto_policy")
			if strings.HasPrefix(p, "FIPS") {
				return Pass, ""
			}
			if p == "" {
				return Fail, "update-crypto-policies not available"
			}
			return Fail, "crypto policy " + p + " (want FIPS)"
		},
		"fips_crypto_subpolicy":       cryptoPolicyState,
		"fips_custom_stig_sub_policy": cryptoPolicyState,
		"crypto_policy_not_overridden": func(i *nodeinfo.Info) (Status, string) {
			chk := strings.ToLower(cmd(i, "crypto_check") + " " + cmd(i, "crypto_applied"))
			switch {
			case strings.Contains(chk, "does not match") || strings.Contains(chk, "not applied"):
				return Fail, "configured crypto policy does not match the generated one (run update-crypto-policies)"
			case strings.Contains(chk, "matches") || strings.Contains(chk, "is applied"):
				return Pass, ""
			}
			return Manual, "update-crypto-policies --check unavailable"
		},
		"configure_bind_crypto_policy": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "bind") {
				return NA, "bind not installed"
			}
			if strings.Contains(cmd(i, "named_include"), "crypto-policies/back-ends/bind.config") {
				return Pass, ""
			}
			return Fail, "/etc/named.conf does not include the crypto-policies bind.config"
		},
		"configure_libreswan_crypto_policy": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "libreswan") {
				return NA, "libreswan not installed"
			}
			if strings.Contains(cmd(i, "ipsec_include"), "crypto-policies/back-ends/libreswan.config") {
				return Pass, ""
			}
			return Fail, "/etc/ipsec.conf does not include the crypto-policies libreswan.config"
		},
		"libreswan_approved_tunnels": func(i *nodeinfo.Info) (Status, string) {
			if cmd(i, "ipsec_active") != "active" {
				return Pass, "ipsec not active"
			}
			return Manual, "ipsec active: confirm every configured conn is documented with the ISSO"
		},
		"harden_sshd_ciphers_opensshserver_conf_crypto_policy": cryptoBackend("/etc/crypto-policies/back-ends/opensshserver.config", "Ciphers", rhelCiphers),
		"harden_sshd_macs_opensshserver_conf_crypto_policy":    cryptoBackend("/etc/crypto-policies/back-ends/opensshserver.config", "MACs", rhelMACs),
		"harden_sshd_ciphers_openssh_conf_crypto_policy":       cryptoBackend("/etc/crypto-policies/back-ends/openssh.config", "Ciphers", rhelCiphers),
		"harden_sshd_macs_openssh_conf_crypto_policy":          cryptoBackend("/etc/crypto-policies/back-ends/openssh.config", "MACs", rhelMACs),
		"sshd_include_crypto_policy": func(i *nodeinfo.Info) (Status, string) {
			hits, found := grep(i, rx(`(?i)^[^:]*:\s*Include\s+/etc/crypto-policies/back-ends/opensshserver\.config`), sshdFiles...)
			if !found {
				return Fail, "/etc/ssh/sshd_config missing"
			}
			if len(hits) == 0 {
				return Fail, "sshd_config does not Include /etc/crypto-policies/back-ends/opensshserver.config"
			}
			return Pass, ""
		},
		"sshd_use_approved_ciphers_ordered_stig":       sshConfigExact(sshdFiles, "Ciphers", ubCiphers),
		"sshd_use_approved_macs_ordered_stig":          sshConfigExact(sshdFiles, "MACs", ubMACs),
		"sshd_use_approved_kex_ordered_stig":           sshConfigExact(sshdFiles, "KexAlgorithms", ubKex),
		"ssh_client_use_approved_ciphers_ordered_stig": sshConfigExact(sshFiles, "Ciphers", ubCiphers),
		"ssh_use_approved_macs_ordered_stig":           sshConfigExact(sshFiles, "MACs", ubMACs),
		"sshd_rekey_limit": func(i *nodeinfo.Info) (Status, string) {
			vals := i.SSHD["rekeylimit"]
			if len(vals) == 0 {
				return Manual, "sshd -T unavailable"
			}
			f := strings.Fields(vals[0])
			if len(f) == 2 && f[0] != "0" && f[1] != "0" {
				return Pass, ""
			}
			return Fail, "RekeyLimit " + vals[0] + " (want a data amount and a time, e.g. 1G 1h)"
		},
		"file_permissions_sshd_private_key": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, l := range sweep(i, "SSHKEY") { // path|mode
				if f := strings.Split(l, "|"); len(f) == 2 {
					if m, ok := modeBits(f[1]); ok && m&^0o600 != 0 {
						bad = append(bad, f[0]+" "+f[1])
					}
				}
			}
			return failIf(bad, "host keys more permissive than 0600")
		},
		"file_permissions_sshd_config_not_modified": rpmVerify("rpm_verify_sshd", "openssh-server"),
		"file_permissions_cron_not_modified":        rpmVerify("rpm_verify_cron", "cronie/crontabs"),
		"ssh_keys_passphrase_protected": func(i *nodeinfo.Info) (Status, string) {
			if v := cmd(i, "ssh_keys_unprotected"); v != "" {
				return Fail, "private keys without a passphrase: " + strings.TrimSuffix(v, ";")
			}
			return Pass, ""
		},
		"sysctl_crypto_fips_enabled":         fipsEnabled,
		"is_fips_mode_enabled":               fipsEnabled,
		"sysctl_kernel_exec_shield":          nxEnabled,
		"bios_enable_execution_restrictions": nxEnabled,
	})
}

func cryptoPolicyState(i *nodeinfo.Info) (Status, string) {
	if !strings.HasPrefix(cmd(i, "crypto_policy"), "FIPS") {
		return Fail, "crypto policy " + strutil.FirstNonEmpty(cmd(i, "crypto_policy"), "-") + " (want FIPS)"
	}
	c, ok := i.STIGFile("/etc/crypto-policies/state/CURRENT.pol")
	if !ok {
		return Manual, "CURRENT.pol not readable"
	}
	hash, _ := iniValue(c, "", "hash", "=")
	if strings.Contains(strings.ToUpper(hash), "SHA1") {
		return Fail, "hash list includes SHA1"
	}
	if rsa, ok := iniValue(c, "", "min_rsa_size", "="); ok {
		if n, _ := atoi(rsa); n < 2048 {
			return Fail, "min_rsa_size " + rsa + " (want >= 2048)"
		}
	}
	return Pass, ""
}

func rpmVerify(key, pkg string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		if !i.Packages["rpm"] && len(i.Packages) > 0 && isUbuntu(i) {
			return NA, "not an rpm system"
		}
		v := cmd(i, key)
		if strings.Contains(v, "is not installed") {
			return NA, pkg + " not installed"
		}
		if v != "" {
			return Fail, pkg + " files differ from the package: " + strings.TrimSuffix(v, ";")
		}
		return Pass, ""
	}
}

func fipsEnabled(i *nodeinfo.Info) (Status, string) {
	if i.SysctlAll["crypto.fips_enabled"] == "1" || i.Hardening["fips"] == "1" {
		return Pass, ""
	}
	return Fail, "crypto.fips_enabled != 1"
}

func nxEnabled(i *nodeinfo.Info) (Status, string) {
	if cmd(i, "nx") != "1" {
		return Fail, "CPU nx flag absent"
	}
	if cmdlineHas(i.Hardening["cmdline"], "noexec", "", "") {
		return Fail, "noexec on the kernel command line"
	}
	return Pass, ""
}

// ---------- firewall / network ----------

func init() {
	register(map[string]namedEval{
		"configured_firewalld_default_deny": func(i *nodeinfo.Info) (Status, string) {
			if i.ServiceState("firewalld") != "active" {
				return Fail, "firewalld not running"
			}
			zones := cmd(i, "firewalld_active_zones")
			target := cmd(i, "firewalld_target")
			switch {
			case strings.TrimSpace(zones) == "":
				return Fail, "no active firewalld zones"
			case !strings.EqualFold(target, "DROP"):
				return Fail, "default zone " + cmd(i, "firewalld_default_zone") + " target " + strutil.FirstNonEmpty(target, "-") + " (want DROP)"
			}
			return Pass, ""
		},
		"firewalld_sshd_port_enabled": firewallEvidence,
		"configure_firewalld_ports":   firewallEvidence,
		"ufw_only_required_services": func(i *nodeinfo.Info) (Status, string) {
			if i.UFWStatus == "" {
				return Fail, "ufw not installed or inactive"
			}
			return Manual, "compare the ufw rules against the PPSM CLSA: " + strutil.TruncList(strings.Split(i.UFWStatus, "\n"), 6)
		},
		"ufw_rate_limit": func(i *nodeinfo.Info) (Status, string) {
			if i.UFWStatus == "" {
				return Fail, "ufw not installed or inactive"
			}
			if strings.Contains(i.UFWStatus, "LIMIT") {
				return Pass, ""
			}
			return Fail, "no LIMIT rules in ufw"
		},
		"check_ufw_active": func(i *nodeinfo.Info) (Status, string) {
			if strings.HasPrefix(i.UFWStatus, "Status: active") {
				return Pass, ""
			}
			if i.ServiceState("firewalld") == "active" {
				return Pass, "firewalld active instead"
			}
			return Fail, "ufw inactive"
		},
		"network_sniffer_disabled": func(i *nodeinfo.Info) (Status, string) {
			if n, _ := atoi(cmd(i, "promisc")); n > 0 {
				return Fail, fmt.Sprintf("%d interface(s) in promiscuous mode", n)
			}
			return Pass, ""
		},
		"wireless_disable_interfaces": func(i *nodeinfo.Info) (Status, string) {
			if n, _ := atoi(cmd(i, "wireless")); n > 0 {
				return Fail, fmt.Sprintf("%d wireless interface(s) present", n)
			}
			return NA, "no wireless radios"
		},
		"network_configure_name_resolution": func(i *nodeinfo.Info) (Status, string) {
			hits, found := grep(i, rx(`^[^:]*:\s*nameserver\s+\S+`), "/etc/resolv.conf")
			if !found {
				return Fail, "/etc/resolv.conf missing"
			}
			if len(hits) >= 2 {
				return Pass, ""
			}
			return Fail, fmt.Sprintf("%d nameserver(s) in /etc/resolv.conf (want >= 2; NA with a single HA cloud resolver)", len(hits))
		},
		"postfix_prevent_unrestricted_relay": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "postfix") {
				return NA, "postfix not installed"
			}
			v := cmd(i, "postfix_relay")
			_, val, _ := strings.Cut(v, "=")
			var extra []string
			for _, e := range strings.Split(strings.ReplaceAll(strings.TrimSpace(val), " ", ","), ",") {
				if e = strings.TrimSpace(e); e != "" && e != "permit_mynetworks" && e != "reject" {
					extra = append(extra, e)
				}
			}
			if strings.TrimSpace(val) == "" {
				return Fail, "smtpd_client_restrictions not set"
			}
			return failIf(extra, "smtpd_client_restrictions entries beyond permit_mynetworks,reject")
		},
		"postfix_client_configure_mail_alias_postmaster": func(i *nodeinfo.Info) (Status, string) {
			hits, found := grep(i, rx(`^[^:]*:\s*postmaster:\s*root\s*$`), "/etc/aliases")
			if !found || len(hits) == 0 {
				return Fail, "no 'postmaster: root' alias"
			}
			return Pass, ""
		},
		"postfix_client_configure_mail_alias": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "postfix") {
				return NA, "postfix not installed"
			}
			if v := cmd(i, "postfix_root_alias"); v != "" {
				return Pass, "root -> " + v
			}
			return Fail, "no alias for root in /etc/aliases"
		},
	})
}

func firewallEvidence(i *nodeinfo.Info) (Status, string) {
	if i.ServiceState("firewalld") != "active" {
		return Fail, "firewalld not running"
	}
	return Manual, "compare against the PPSM CLSA - services: " + strutil.FirstNonEmpty(cmd(i, "firewalld_services"), "-") + "; ports: " + strutil.FirstNonEmpty(cmd(i, "firewalld_ports"), "-")
}

// ---------- filesystem sweep ----------

func sweepEmpty(kind, what string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) { return failIf(sweep(i, kind), what) }
}

func init() {
	register(map[string]namedEval{
		"dir_perms_world_writable_sticky_bits":        sweepEmpty("WWNOSTICKY", "world-writable directories without the sticky bit"),
		"dir_perms_world_writable_system_owned":       sweepEmpty("WWUSER", "world-writable directories not owned by a system account"),
		"dir_perms_world_writable_root_owned":         sweepEmpty("WWUSER", "world-writable directories not owned by a system account"),
		"dir_perms_world_writable_system_owned_group": sweepEmpty("WWGROUP", "world-writable directories not group-owned by a system group"),
		"file_permissions_ungroupowned":               sweepEmpty("NOGROUP", "files without a valid group"),
		"no_files_unowned_by_user":                    sweepEmpty("NOUSER", "files without a valid owner"),
		"no_host_based_files":                         sweepEmpty("SHOSTS", "shosts.equiv / .shosts files"),
		"no_user_host_based_files":                    sweepEmpty("SHOSTS", "shosts.equiv / .shosts files"),
		"file_permissions_binary_dirs":                sweepEmpty("BINPERM", "system commands group- or world-writable"),
		"file_ownership_binary_dirs":                  sweepEmpty("BINOWNER", "system commands not owned by root"),
		"file_groupownership_system_commands_dirs":    sweepEmpty("BINGROUP", "system commands not group-owned by a system group"),
		"mount_option_nodev_nonroot_local_partitions": func(i *nodeinfo.Info) (Status, string) {
			var bad []string
			for _, m := range i.Findmnt {
				// bind mounts of files/subtrees show as /dev/xxx[/path]
				if !strings.HasPrefix(m.Source, "/dev/") || m.Target == "/" || strings.Contains(m.Source, "[") {
					continue
				}
				if !slices.Contains(m.Options, "nodev") {
					bad = append(bad, m.Target)
				}
			}
			return failIf(bad, "non-root local partitions mounted without nodev")
		},
		"encrypt_partitions": func(i *nodeinfo.Info) (Status, string) {
			for _, l := range i.Lsblk {
				if f := strings.Fields(l); len(f) >= 2 && f[1] == "crypt" {
					return Pass, ""
				}
			}
			return Manual, "no encrypted block devices; NA only with a documented, approved alternative (hypervisor or array encryption)"
		},
		"selinux_all_devicefiles_labeled": func(i *nodeinfo.Info) (Status, string) {
			if !strings.EqualFold(i.Hardening["selinux"], "Enforcing") {
				return NA, "SELinux not enforcing"
			}
			if v := cmd(i, "dev_unlabeled"); v != "" {
				return Fail, "unlabeled device files: " + strings.TrimSuffix(v, ";")
			}
			return Pass, ""
		},
		"selinux_state": func(i *nodeinfo.Info) (Status, string) {
			h := i.Hardening
			if !strings.EqualFold(h["selinux"], "Enforcing") {
				return Fail, "SELinux " + strutil.FirstNonEmpty(h["selinux"], "-")
			}
			if cfg := h["selinux_config"]; cfg != "" && !strings.EqualFold(cfg, "enforcing") {
				return Fail, "enforcing now but /etc/selinux/config SELINUX=" + cfg
			}
			return Pass, ""
		},
	})
}

// ---------- AIDE ----------

func aideConf(i *nodeinfo.Info) ([]string, bool) {
	if ls, ok := lines(i, "/etc/aide.conf"); ok {
		return ls, true
	}
	return lines(i, "/etc/aide/aide.conf")
}

func aideHas(token, what string) namedEval {
	return func(i *nodeinfo.Info) (Status, string) {
		ls, ok := aideConf(i)
		if !ok {
			if !pkgAny(i, "aide") {
				return Fail, "aide not installed (or confirm another integrity tool covers " + what + ")"
			}
			return Fail, "aide.conf missing"
		}
		for _, l := range ls {
			if strings.Contains(l, token) {
				return Pass, ""
			}
		}
		return Fail, token + " not used in aide.conf"
	}
}

func init() {
	register(map[string]namedEval{
		"aide_use_fips_hashes":       aideHas("sha512", "FIPS hashes"),
		"aide_verify_acls":           aideHas("acl", "ACLs"),
		"aide_verify_ext_attributes": aideHas("xattrs", "extended attributes"),
		"aide_check_audit_tools": func(i *nodeinfo.Info) (Status, string) {
			ls, ok := aideConf(i)
			if !ok {
				return Fail, "aide not installed or aide.conf missing"
			}
			var missing []string
			for _, tool := range []string{"auditctl", "auditd", "ausearch", "aureport", "autrace", "augenrules"} {
				found := false
				for _, l := range ls {
					if strings.HasPrefix(strings.TrimSpace(l), "/usr/sbin/"+tool) || strings.HasPrefix(strings.TrimSpace(l), "/sbin/"+tool) {
						found = true
					}
				}
				if !found {
					missing = append(missing, tool)
				}
			}
			return failIf(missing, "audit tools without an aide.conf entry")
		},
		"aide_scan_notification": func(i *nodeinfo.Info) (Status, string) {
			cron, timer := cmd(i, "aide_cron"), cmd(i, "aide_timer")
			switch {
			case cron == "" && timer == "":
				return Fail, "no cron job or timer runs aide"
			case strings.Contains(cron, "mail") || strings.Contains(cron, "sendmail"):
				return Pass, ""
			}
			return Fail, "aide runs (" + strutil.FirstNonEmpty(firstField(cron+timer), "-") + ") but nothing mails the result"
		},
		"aide_build_database": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "aide", "aide-common") {
				return NA, "aide not installed"
			}
			if cmd(i, "aide_db") != "" {
				return Pass, ""
			}
			return Fail, "no AIDE database under /var/lib/aide (run aideinit / aide --init)"
		},
		"aide_periodic_checking_systemd_timer": aidePeriodic,
		"aide_periodic_cron_checking":          aidePeriodic,
	})
}

func aidePeriodic(i *nodeinfo.Info) (Status, string) {
	if !pkgAny(i, "aide", "aide-common") {
		return NA, "aide not installed"
	}
	if cmd(i, "aide_cron") != "" || cmd(i, "aide_timer") != "" {
		return Pass, ""
	}
	return Fail, "no cron job or systemd timer runs aide"
}

// ---------- boot loader ----------

func init() {
	grubPassword := func(uefi bool) namedEval {
		return func(i *nodeinfo.Info) (Status, string) {
			if !isUbuntu(i) && (cmd(i, "efi") == "1") != uefi {
				if uefi {
					return NA, "BIOS boot"
				}
				return NA, "UEFI boot"
			}
			if cmd(i, "grub_password") != "" {
				return Pass, ""
			}
			return Fail, "no boot loader superuser password (GRUB2_PASSWORD / password_pbkdf2)"
		}
	}
	grubUser := func(uefi bool) namedEval {
		return func(i *nodeinfo.Info) (Status, string) {
			if (cmd(i, "efi") == "1") != uefi {
				if uefi {
					return NA, "BIOS boot"
				}
				return NA, "UEFI boot"
			}
			line := cmd(i, "grub_superusers")
			m := rx(`superusers="?([^" ]*)`).FindStringSubmatch(line)
			if m == nil || m[1] == "" {
				return Fail, "no superusers set in grub.cfg"
			}
			switch strings.ToLower(m[1]) {
			case "root", "admin", "administrator":
				return Fail, "superusers is the guessable name " + m[1]
			}
			return Pass, ""
		}
	}
	register(map[string]namedEval{
		"grub2_password":            grubPassword(false),
		"grub2_uefi_password":       grubPassword(true),
		"grub2_admin_username":      grubUser(false),
		"grub2_uefi_admin_username": grubUser(true),
		"grub2_disable_interactive_boot": func(i *nodeinfo.Info) (Status, string) {
			for _, l := range append([]string{i.Hardening["cmdline"]}, i.GrubArgs...) {
				if strings.Contains(l, "systemd.confirm_spawn") {
					return Fail, "systemd.confirm_spawn on the kernel command line"
				}
			}
			return Pass, ""
		},
	})
}

// ---------- SSSD / PKI / miscellany ----------

func init() {
	register(map[string]namedEval{
		"sssd_enable_smartcards": func(i *nodeinfo.Info) (Status, string) {
			if strings.EqualFold(i.SSSDConf["pam_cert_auth"], "true") {
				return Pass, ""
			}
			return Fail, "pam_cert_auth not True in sssd.conf (NA only with an approved alternate MFA)"
		},
		"sssd_certificate_verification": func(i *nodeinfo.Info) (Status, string) {
			if strings.Contains(i.SSSDConf["certificate_verification"], "ocsp_dgst=sha512") {
				return Pass, ""
			}
			return Fail, "certificate_verification lacks ocsp_dgst=sha512 in sssd.conf"
		},
		"sssd_certification_path_trust_anchor": func(i *nodeinfo.Info) (Status, string) {
			if strings.Contains(i.SSSDConf["certificate_verification"], "ca") {
				return Pass, ""
			}
			return Fail, "certificate_verification does not include ca in sssd.conf"
		},
		"sssd_enable_pam_services": func(i *nodeinfo.Info) (Status, string) {
			if strings.Contains(i.SSSDConf["services"], "pam") {
				return Pass, ""
			}
			return Fail, "pam not in sssd services"
		},
		"sssd_enable_user_cert": func(i *nodeinfo.Info) (Status, string) {
			if i.SSSDConf["ldap_user_certificate"] != "" {
				return Pass, ""
			}
			return Fail, "ldap_user_certificate not set in sssd.conf"
		},
		"sssd_offline_cred_expiration": func(i *nodeinfo.Info) (Status, string) {
			if !strings.EqualFold(i.SSSDConf["cache_credentials"], "true") {
				return Pass, "cached credentials disabled"
			}
			if i.SSSDConf["offline_credentials_expiration"] == "1" {
				return Pass, ""
			}
			return Fail, "offline_credentials_expiration = " + strutil.FirstNonEmpty(i.SSSDConf["offline_credentials_expiration"], "-") + " (want 1)"
		},
		"sssd_has_trust_anchor": func(i *nodeinfo.Info) (Status, string) {
			subj := cmd(i, "sssd_ca_subject")
			switch {
			case subj == "":
				return Fail, "/etc/sssd/pki/sssd_auth_ca_db.pem missing"
			case strings.Contains(subj, "DoD") || strings.Contains(subj, "DOD"):
				return Pass, ""
			}
			return Fail, "sssd_auth_ca_db.pem is not a DoD root: " + subj
		},
		"configure_opensc_card_drivers": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "opensc") {
				return NA, "opensc not installed"
			}
			if strings.Contains(cmd(i, "opensc_drivers"), "cac") {
				return Pass, ""
			}
			return Fail, "cac not among opensc card_drivers"
		},
		"only_allow_dod_certs": func(i *nodeinfo.Info) (Status, string) {
			if cmd(i, "dod_certs") != "" {
				return Pass, ""
			}
			return Fail, "no DoD root certificate under /etc/ssl/certs"
		},
		"prevent_direct_root_logins": func(i *nodeinfo.Info) (Status, string) {
			if cmd(i, "root_passwd") == "L" {
				return Pass, ""
			}
			return Fail, "root password status " + strutil.FirstNonEmpty(cmd(i, "root_passwd"), "-") + " (want L = locked)"
		},
		"ensure_rtc_utc_configuration": func(i *nodeinfo.Info) (Status, string) {
			tz := cmd(i, "timezone")
			switch strings.ToUpper(tz) {
			case "UTC", "ETC/UTC", "GMT", "ETC/GMT", "UNIVERSAL", "ZULU":
				return Pass, ""
			}
			return Fail, "time zone " + strutil.FirstNonEmpty(tz, "-") + " (want UTC or GMT)"
		},
		"banner_etc_issue": func(i *nodeinfo.Info) (Status, string) {
			c, ok := i.STIGFile("/etc/issue")
			if ok && strings.Contains(c, "You are accessing a U.S. Government (USG) Information System (IS)") {
				return Pass, ""
			}
			return Fail, "/etc/issue is not the DoD notice and consent banner"
		},
		"banner_etc_profiled_ssh_confirm": func(i *nodeinfo.Info) (Status, string) {
			for _, f := range i.STIGFilesGlob("/etc/profile.d/") {
				if strings.Contains(f.Content, "You are accessing a U.S. Government (USG) Information System (IS)") && strings.Contains(f.Content, "SSH") {
					return Pass, ""
				}
			}
			return Fail, "no /etc/profile.d script prompting SSH users to accept the DoD banner"
		},
		"usbguard_generate_policy": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "usbguard") {
				return Manual, "usbguard not installed (NA for virtual machines without USB peripherals)"
			}
			if n, _ := atoi(cmd(i, "usbguard_rules")); n > 0 {
				return Pass, ""
			}
			return Fail, "/etc/usbguard/rules.conf has no rules (usbguard generate-policy)"
		},
		"fapolicy_default_deny": func(i *nodeinfo.Info) (Status, string) {
			if !pkgAny(i, "fapolicyd") {
				return Fail, "fapolicyd not installed"
			}
			v, ok := keyValue(i, "permissive", "/etc/fapolicyd/fapolicyd.conf")
			if !ok || v != "0" {
				return Fail, "fapolicyd permissive = " + strutil.FirstNonEmpty(v, "-") + " (want 0)"
			}
			if !strings.Contains(cmd(i, "fapolicy_rules_tail"), "deny perm=any all : all") {
				return Fail, "compiled rules do not end with 'deny perm=any all : all'"
			}
			return Pass, ""
		},
	})
}
