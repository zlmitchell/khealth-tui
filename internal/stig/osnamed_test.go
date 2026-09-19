package stig

import (
	"strings"
	"testing"

	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/stigdata"
)

func cf(path, content string) nodeinfo.ConfigFile {
	return nodeinfo.ConfigFile{Path: path, Content: content}
}

// hardenedNode is a RHEL 9 node configured the way the STIG wants.
func hardenedNode() *nodeinfo.Info {
	return &nodeinfo.Info{
		Node: "h1", Arch: "x86_64", STIGProbed: true,
		OS:        nodeinfo.OSRelease{ID: "rhel", VersionID: "9.4", Pretty: "RHEL 9.4"},
		Hardening: map[string]string{"selinux": "Enforcing", "selinux_config": "enforcing", "fips": "1", "cmdline": "audit=1"},
		Packages:  map[string]bool{"aide": true, "audit": true, "rsyslog": true, "sudo": true, "chrony": true, "opensc": true},
		UnitFiles: map[string]string{"ctrl-alt-del.target": "masked"},
		STIGCmd: map[string]string{
			"default_target": "multi-user.target", "efi": "0", "crypto_policy": "FIPS:OSPP", "crypto_check": "The configured policy matches the generated policy",
			"nx": "1", "promisc": "0", "wireless": "0", "timezone": "UTC", "root_passwd": "L",
			"gpg_keys":        "Red Hat, Inc. (release key 2) <security@redhat.com> public key;Red Hat, Inc. (auxiliary key 3) <security@redhat.com> public key;",
			"rpm_verify_cron": "", "repos": "rhel-9-baseos rhel-9-appstream", "faillock_ctx": "unconfined_u:object_r:faillog_t:s0",
			"emergency_sulogin": "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency", "rescue_sulogin": "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue",
			"grub_superusers": `set superusers="bootadmin"`, "grub_password": "GRUB2_PASSWORD=grub.pbkdf2.sha512",
			"aide_cron": "0 5 * * * root /usr/sbin/aide --check | /bin/mail -s aide root", "sssd_ca_subject": "subject=C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3",
			"opensc_drivers": "cac", "tmpfiles_rootfiles": "", "dev_unlabeled": "", "ssh_keys_unprotected": "", "keytabs": "",
		},
		STIGSweep: map[string][]string{
			"HOME":     {"alice|750|1000|/home/alice"},
			"AUDITDIR": {"/var/log/audit|700|root|root"},
			"SSHKEY":   {"/etc/ssh/ssh_host_ed25519_key|600"},
		},
		Passwd: []nodeinfo.PasswdEntry{
			{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"},
			{Name: "bin", UID: 1, GID: 1, Home: "/bin", Shell: "/sbin/nologin"},
			{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/bin/bash"},
		},
		Groups:        []nodeinfo.GroupEntry{{Name: "root", GID: 0}, {Name: "bin", GID: 1}, {Name: "alice", GID: 1000}, {Name: "wheel", GID: 10, Members: []string{"alice"}}},
		ShadowMeta:    map[string]nodeinfo.ShadowMeta{"root": {Hash: "$6$", MinDays: "1", MaxDays: "60"}, "bin": {Hash: "locked"}, "alice": {Hash: "$6$", MinDays: "1", MaxDays: "60"}},
		SSSDConf:      map[string]string{"pam_cert_auth": "True", "certificate_verification": "ocsp_dgst=sha512", "cache_credentials": "true", "offline_credentials_expiration": "1"},
		SELinuxLogins: []string{"__default__ user_u s0-s0:c0.c1023 *", "root unconfined_u s0-s0:c0.c1023 *"},
		Lsblk:         []string{"sda disk", "sda2 part", "luks-1 crypt /"},
		Findmnt:       []nodeinfo.MountEntry{{Target: "/", Source: "/dev/mapper/root", FSType: "xfs", Options: []string{"rw"}}, {Target: "/home", Source: "/dev/mapper/home", FSType: "xfs", Options: []string{"rw", "nodev"}}},
		Mounts:        []nodeinfo.Mount{{Mountpoint: "/", SizeKB: 50 << 20}, {Mountpoint: "/var/log/audit", SizeKB: 12 << 20}},
		SSHD:          map[string][]string{"rekeylimit": {"1073741824 3600"}},
		AuditRules: []string{
			"-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv",
			"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
			"-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv",
			"-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv",
			"-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -k privileged-umount",
			"-w /usr/sbin/modprobe -p x -k modules",
		},
		AuditRuleFiles: []string{"-w /etc/sudoers -p wa -k actions", "--loginuid-immutable", "-f 2", "-e 2"},
		STIGFiles: []nodeinfo.ConfigFile{
			cf("/etc/login.defs", "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 1\nPASS_MIN_LEN 15\nFAIL_DELAY 4\nCREATE_HOME yes\nUMASK 077\nENCRYPT_METHOD SHA512\nSHA_CRYPT_MIN_ROUNDS 100000\n"),
			cf("/etc/default/useradd", "INACTIVE=35\n"),
			cf("/etc/libuser.conf", "[defaults]\ncrypt_style = sha512\n"),
			cf("/etc/profile", "umask 077\n"), cf("/etc/bashrc", "[ `umask` -eq 0 ] && umask 077\n"), cf("/etc/csh.cshrc", "umask 077\n"),
			cf("/etc/profile.d/tmout.sh", "declare -xr TMOUT=600\n"),
			cf("/etc/security/limits.conf", "* hard maxlogins 10\n* hard core 0\n"),
			cf("/etc/systemd/logind.conf", "[Login]\nStopIdleSessionSec=600\n"),
			cf("/etc/systemd/system.conf.d/55-cad.conf", "[Manager]\nCtrlAltDelBurstAction=none\n"),
			cf("/etc/pam.d/system-auth", "auth required pam_faillock.so preauth silent\nauth sufficient pam_unix.so try_first_pass\nauth required pam_faillock.so authfail\naccount required pam_faillock.so\npassword requisite pam_pwquality.so\npassword sufficient pam_unix.so sha512 shadow rounds=100000\n"),
			cf("/etc/pam.d/password-auth", "auth required pam_faillock.so preauth silent\nauth sufficient pam_unix.so try_first_pass\nauth required pam_faillock.so authfail\naccount required pam_faillock.so\npassword requisite pam_pwquality.so\npassword sufficient pam_unix.so sha512 shadow rounds=100000\n"),
			cf("/etc/security/faillock.conf", "audit\nsilent\ndeny = 3\neven_deny_root\ndir = /var/log/faillock\n"),
			cf("/etc/security/pwquality.conf", "retry = 3\nminlen = 15\n"),
			cf("/etc/sudoers", "Defaults !targetpw\nDefaults !rootpw\nDefaults !runaspw\nDefaults timestamp_timeout=0\n%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL\n#includedir /etc/sudoers.d\n"),
			cf("/etc/audit/auditd.conf", "log_file = /var/log/audit/audit.log\nspace_left = 25%\nspace_left_action = email\naction_mail_acct = root\nadmin_space_left = 5%\nadmin_space_left_action = single\ndisk_full_action = HALT\ndisk_error_action = HALT\nmax_log_file_action = ROTATE\nname_format = hostname\noverflow_action = syslog\n"),
			cf("/etc/rsyslog.conf", "authpriv.* /var/log/secure\ncron.* /var/log/cron\n$DefaultNetstreamDriver gtls\n$ActionSendStreamDriverMode 1\n$ActionSendStreamDriverAuthMode x509/name\n*.* @@logs.example.mil:6514\n"),
			cf("/etc/chrony.conf", "server 0.us.pool.ntp.mil iburst maxpoll 16\nport 0\ncmdport 0\n"),
			cf("/etc/dnf/dnf.conf", "[main]\ngpgcheck=1\nlocalpkg_gpgcheck=1\nclean_requirements_on_remove=True\n"),
			cf("/etc/yum.repos.d/redhat.repo", "[baseos]\ngpgcheck = 1\n"),
			cf("/etc/issue", "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n"),
			cf("/etc/aide.conf", "All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux\n/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512\n/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512\n/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512\n/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512\n/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512\n/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512\n"),
			cf("/etc/crypto-policies/back-ends/opensshserver.config", "Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512\n"),
			cf("/etc/crypto-policies/back-ends/openssh.config", "CRYPTO_POLICY='-oCiphers=aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512'\n"),
			cf("/etc/crypto-policies/state/CURRENT.pol", "hash = SHA2-256 SHA2-384 SHA2-512\nmin_rsa_size = 2048\n"),
			cf("/etc/ssh/sshd_config", "Include /etc/crypto-policies/back-ends/opensshserver.config\n"),
			cf("/etc/resolv.conf", "nameserver 10.0.0.2\nnameserver 10.0.0.3\n"),
			cf("/etc/aliases", "postmaster: root\n"),
		},
	}
}

func TestNamedEvaluatorsHardened(t *testing.T) {
	n := hardenedNode()
	// every registered evaluator must pass or be N/A on the hardened node
	// except the ones that are Manual by design
	manualByDesign := map[string]bool{
		"accounts_authorized_local_users": true, "account_temp_expire_date": true, "ensure_sudo_group_restricted": true,
		"security_patches_up_to_date": true, "auditd_offload_logs": true, "usbguard_generate_policy": true,
	}
	skip := map[string]bool{ // need facts the fixture does not model
		"configured_firewalld_default_deny": true, "ufw_rate_limit": true, "check_ufw_active": true, "smartcard_pam_enabled": true,
		"firewalld_sshd_port_enabled": true, "configure_firewalld_ports": true, "ufw_only_required_services": true,
		"smartcard_configure_cert_checking": true, "smartcard_configure_ca": true, "smartcard_configure_crl": true,
		"only_allow_dod_certs": true, "sssd_enable_pam_services": true, "sssd_enable_user_cert": true, "sssd_certification_path_trust_anchor": true,
		"banner_etc_profiled_ssh_confirm": true, "sshd_use_approved_ciphers_ordered_stig": true, "sshd_use_approved_macs_ordered_stig": true,
		"sshd_use_approved_kex_ordered_stig": true, "ssh_client_use_approved_ciphers_ordered_stig": true, "ssh_use_approved_macs_ordered_stig": true,
		"apt_conf_disallow_unauthenticated": true, "aide_build_database": true, "aide_periodic_checking_systemd_timer": true, "aide_periodic_cron_checking": true,
		"fapolicy_default_deny": true, "rsyslog_omfwd_tls": true, "rsyslog_omfwd_streamdriver": true, "rsyslog_omfwd_authmode": true,
		"postfix_client_configure_mail_alias": true, "postfix_prevent_unrestricted_relay": true, "accounts_passwords_pam_faillock_silent": true,
		"file_permissions_sshd_config_not_modified": true, "rootfiles_configured": true, "file_permission_user_init_files": true,
		"set_password_hashing_algorithm_auth_stig": true, "prevent_direct_root_logins": true, "ensure_rtc_utc_configuration": true,
		"chronyd_configure_local_socket": true, "audit_rules_privileged_commands_fdisk": true, "audit_rules_cron_execution": true,
	}
	for name, ev := range namedEvals {
		if skip[name] {
			continue
		}
		st, detail := ev(n)
		if manualByDesign[name] {
			if st != Manual {
				t.Errorf("%s: want MANUAL, got %s (%s)", name, st, detail)
			}
			continue
		}
		if st != Pass && st != NA {
			t.Errorf("%s: hardened node got %s: %s", name, st, detail)
		}
	}
}

func TestNamedEvaluatorsFindings(t *testing.T) {
	n := hardenedNode()
	// break things one at a time and check the right evaluator notices
	n.STIGFiles = append(n.STIGFiles, cf("/etc/sudoers.d/ops", "ops ALL=(ALL) NOPASSWD: ALL\nDefaults !authenticate\n"))
	n.STIGSweep["WWNOSTICKY"] = []string{"/srv/shared"}
	n.STIGSweep["INITPERM"] = []string{"alice|/home/alice/.bashrc|755"}
	n.STIGSweep["UMASK"] = []string{"alice|/home/alice/.profile:umask 022"}
	n.STIGSweep["PATHLINE"] = []string{"alice|/home/alice/.bashrc:PATH=/opt/bin:$PATH"}
	n.Passwd = append(n.Passwd, nodeinfo.PasswdEntry{Name: "toor", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"}, nodeinfo.PasswdEntry{Name: "bob", UID: 1000, GID: 4242, Home: "", Shell: "/bin/bash"})
	n.ShadowMeta["bob"] = nodeinfo.ShadowMeta{Hash: "$y$", MinDays: "0", MaxDays: "99999"}
	n.ShadowMeta["svc"] = nodeinfo.ShadowMeta{Hash: "empty"}
	n.STIGCmd["default_target"] = "graphical.target"
	n.STIGCmd["crypto_policy"] = "DEFAULT"
	n.STIGCmd["promisc"] = "1"
	n.STIGCmd["rpm_verify_cron"] = "S.5....T. c /etc/crontab;"
	n.STIGCmd["repos"] = "baseos epel"
	n.UnitFiles["ctrl-alt-del.target"] = "static"
	cases := map[string]Status{
		"sudo_remove_nopasswd": Fail, "sudo_remove_no_authenticate": Fail,
		"dir_perms_world_writable_sticky_bits": Fail, "file_permission_user_init_files_root": Fail,
		"accounts_umask_interactive_users": Fail, "accounts_user_home_paths_only": Fail,
		"accounts_no_uid_except_zero": Fail, "account_unique_id": Fail, "gid_passwd_group_same": Fail,
		"accounts_user_interactive_home_directory_defined": Fail, "accounts_password_all_shadowed_sha512": Fail,
		"accounts_password_set_max_life_existing": Fail, "accounts_password_set_min_life_existing": Fail,
		"no_empty_passwords_etc_shadow": Fail, "xwindows_runlevel_target": Fail, "configure_crypto_policy": Fail,
		"network_sniffer_disabled": Fail, "file_permissions_cron_not_modified": Fail, "ensure_epel_repos_disabled": Fail,
		"disable_ctrlaltdel_reboot": Fail,
		// unaffected controls still pass
		"accounts_maximum_age_login_defs": Pass, "audit_rules_immutable": Pass, "chronyd_client_only": Pass,
	}
	for name, want := range cases {
		st, detail := namedEvals[name](n)
		if st != want {
			t.Errorf("%s: got %s (%s) want %s", name, st, detail, want)
		}
	}
	// not-installed rpm -V is N/A, not a finding
	n.STIGCmd["rpm_verify_cron"] = "package cronie is not installed;"
	if st, _ := namedEvals["file_permissions_cron_not_modified"](n); st != NA {
		t.Errorf("rpm -V on absent package should be NA, got %s", st)
	}
	// GNOME rules are N/A without a desktop, evaluated with one
	if st, _ := namedEvals["dconf_gnome_banner_enabled"](n); st != NA {
		t.Errorf("gnome rule without gdm should be NA, got %s", st)
	}
	n.Packages["gdm"] = true
	n.STIGFiles = append(n.STIGFiles, cf("/etc/dconf/db/local.d/00-security", "[org/gnome/login-screen]\nbanner-message-enable=true\n"), cf("/etc/dconf/db/local.d/locks/session", "/org/gnome/desktop/session/idle-delay\n"))
	if st, d := namedEvals["dconf_gnome_banner_enabled"](n); st != Pass {
		t.Errorf("gnome banner: %s %s", st, d)
	}
	if st, d := namedEvals["dconf_gnome_session_idle_user_locks"](n); st != Pass {
		t.Errorf("gnome lock: %s %s", st, d)
	}
	// the driver routes untemplated checks through the registry
	rule := hardenedRule("V-9", "sudo_remove_nopasswd")
	if st, d := evalTemplated(n, rule); st != Fail || !strings.Contains(d, "NOPASSWD") {
		t.Errorf("driver: %s %s", st, d)
	}
	if !templated(rule) {
		t.Errorf("rule with a named evaluator must count as automated")
	}
}

func hardenedRule(vid, cacRule string) stigdata.Rule {
	return stigdata.Rule{VID: vid, Checks: []stigdata.Check{{Rule: cacRule}}}
}
