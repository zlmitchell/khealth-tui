package stig

import (
	"strings"
	"testing"

	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/stigdata"
)

func chk(t string, params map[string]any, resolved map[string]string) stigdata.Check {
	return stigdata.Check{Rule: "r", Template: t, Params: params, Resolved: resolved}
}

func probedNode() *nodeinfo.Info {
	return &nodeinfo.Info{
		Node: "n1", Arch: "x86_64", STIGProbed: true,
		Hardening:  map[string]string{"cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 audit=1 audit_backlog_limit=8192"},
		SysctlAll:  map[string]string{"kernel.dmesg_restrict": "1", "net.ipv4.conf.all.accept_redirects": "1", "kernel.core_pattern": "|/bin/false"},
		Packages:   map[string]bool{"aide": true, "openssh-server": true, "audit": true},
		UnitFiles:  map[string]string{"auditd.service": "enabled", "debug-shell.service": "disabled", "sshd.service": "enabled"},
		UnitStates: map[string]nodeinfo.UnitState{"auditd.service": {Load: "loaded", Active: "active", Sub: "running"}, "debug-shell.service": {Load: "loaded", Active: "inactive", Sub: "dead"}},
		Findmnt:    []nodeinfo.MountEntry{{Target: "/tmp", Source: "tmpfs", FSType: "tmpfs", Options: []string{"rw", "nosuid", "nodev"}}, {Target: "/home", Source: "/dev/sda3", FSType: "xfs", Options: []string{"rw", "nodev"}}},
		Fstab:      []string{"/dev/sda3 /home xfs defaults,nodev 0 0"},
		SSHD:       map[string][]string{"permitrootlogin": {"no"}, "clientaliveinterval": {"600"}, "ciphers": {"aes256-gcm@openssh.com,aes128-gcm@openssh.com"}},
		AuditRules: []string{
			"-w /etc/sudoers -p wa -k actions",
			"-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged",
			"-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
			"-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
			"-a always,exit -F arch=b64 -S creat,open -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
			"-a always,exit -F arch=b32 -S creat,open -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
		},
		Modprobe:      []string{"install atm /bin/false", "blacklist atm", "install usb-storage /bin/false"},
		LoadedModules: map[string]bool{},
		GrubArgs:      []string{`args="ro audit=1 audit_backlog_limit=8192"`, `GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192"`},
		STIGStat: map[string]nodeinfo.Perm{
			"/etc/passwd":   {Path: "/etc/passwd", Mode: "644", User: "root", Group: "root", UID: "0", GID: "0", Type: "regular file"},
			"/etc/shadow":   {Path: "/etc/shadow", Mode: "640", User: "root", Group: "root", UID: "0", GID: "0", Type: "regular file"},
			"/usr/bin/sudo": {Path: "/usr/bin/sudo", Mode: "4111", User: "root", Group: "root", UID: "0", GID: "0"},
		},
		STIGViol: map[string][]string{"V-1:0": {"/var/log/messages"}},
		STIGFiles: []nodeinfo.ConfigFile{
			{Path: "/etc/audit/auditd.conf", Content: "log_file = /var/log/audit/audit.log\nspace_left_action = email\nlocal_events = yes\n"},
			{Path: "/etc/security/pwquality.conf", Content: "# comment\nminlen = 15\nretry = 3\n"},
			{Path: "/etc/security/faillock.conf", Content: "deny = 3\nfail_interval = 900\n"},
			{Path: "/etc/systemd/coredump.conf", Content: "[Coredump]\nStorage=none\n"},
			{Path: "/etc/systemd/coredump.conf.d/10-stig.conf", Content: "[Coredump]\nProcessSizeMax=0\n"},
			{Path: "/etc/pam.d/su", Content: "auth required pam_wheel.so use_uid\n"},
			{Path: "/etc/firewalld/firewalld.conf", Content: "FirewallBackend=nftables\n"},
			{Path: "/etc/selinux/config", Content: "SELINUX=enforcing\nSELINUXTYPE=targeted\n"},
		},
	}
}

func TestTemplateEvaluators(t *testing.T) {
	n := probedNode()
	cases := []struct {
		name string
		c    stigdata.Check
		want Status
	}{
		{"sysctl pass", chk("sysctl", map[string]any{"SYSCTLVAR": "kernel.dmesg_restrict", "SYSCTLVAL": "1"}, nil), Pass},
		{"sysctl fail", chk("sysctl", map[string]any{"SYSCTLVAR": "net.ipv4.conf.all.accept_redirects", "SYSCTLVAL": "0"}, nil), Fail},
		{"sysctl string", chk("sysctl", map[string]any{"SYSCTLVAR": "kernel.core_pattern", "SYSCTLVAL": "|/bin/false"}, nil), Pass},
		{"sysctl ipv6 absent", chk("sysctl", map[string]any{"SYSCTLVAR": "net.ipv6.conf.all.accept_ra", "SYSCTLVAL": "0", "IPV6": "true"}, nil), NA},
		{"pkg installed", chk("package_installed", map[string]any{"PKGNAME": "aide"}, nil), Pass},
		{"pkg missing", chk("package_installed", map[string]any{"PKGNAME": "fapolicyd"}, nil), Fail},
		{"pkg removed ok", chk("package_removed", map[string]any{"PKGNAME": "telnet-server"}, nil), Pass},
		{"pkg removed present", chk("package_removed", map[string]any{"PACKAGES": []any{"aide"}}, nil), Fail},
		{"guard var skip", chk("package_installed_guard_var", map[string]any{"PKGNAME": "x", "VARIABLE": "v", "VALUE": "yes"}, map[string]string{"v": "no"}), NA},
		{"service enabled", chk("service_enabled", map[string]any{"SERVICENAME": "auditd"}, nil), Pass},
		{"service disabled", chk("service_disabled", map[string]any{"SERVICENAME": "debug-shell"}, nil), Pass},
		{"service enabled missing", chk("service_enabled", map[string]any{"SERVICENAME": "fapolicyd"}, nil), Fail},
		{"mount", chk("mount", map[string]any{"MOUNTPOINT": "/home"}, nil), Pass},
		{"mount missing", chk("mount", map[string]any{"MOUNTPOINT": "/var/log/audit"}, nil), Fail},
		{"mount option", chk("mount_option", map[string]any{"MOUNTPOINT": "/tmp", "MOUNTOPTION": "nosuid", "MOUNT_HAS_TO_EXIST": true}, nil), Pass},
		{"mount option missing", chk("mount_option", map[string]any{"MOUNTPOINT": "/tmp", "MOUNTOPTION": "noexec", "MOUNT_HAS_TO_EXIST": true}, nil), Fail},
		{"mount option no mount", chk("mount_option", map[string]any{"MOUNTPOINT": "/var", "MOUNTOPTION": "nodev", "MOUNT_HAS_TO_EXIST": false}, nil), Pass},
		{"sshd pass", chk("sshd_lineinfile", map[string]any{"PARAMETER": "PermitRootLogin", "VALUE": "no", "DATATYPE": "string"}, nil), Pass},
		{"sshd var", chk("sshd_lineinfile", map[string]any{"PARAMETER": "ClientAliveInterval", "DATATYPE": "int", "XCCDF_VARIABLE": "sshd_idle_timeout_value"}, map[string]string{"sshd_idle_timeout_value": "600"}), Pass},
		{"sshd fail", chk("sshd_lineinfile", map[string]any{"PARAMETER": "Ciphers", "VALUE": "aes256-ctr", "DATATYPE": "string"}, nil), Fail},
		{"sshd missing pass", chk("sshd_lineinfile", map[string]any{"PARAMETER": "Compression", "VALUE": "no", "MISSING_PARAMETER_PASS": true}, nil), Pass},
		{"file perms ok", chk("file_permissions", map[string]any{"FILEPATH": []any{"/etc/passwd"}, "FILEMODE": "0644"}, nil), Pass},
		{"file perms too open", chk("file_permissions", map[string]any{"FILEPATH": []any{"/etc/passwd"}, "FILEMODE": "0640"}, nil), Fail},
		{"file perms absent", chk("file_permissions", map[string]any{"FILEPATH": []any{"/etc/nope"}, "FILEMODE": "0600"}, nil), Pass},
		{"file owner", chk("file_owner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "UID_OR_NAME": "0", "OWNER_REPRESENTED_WITH_UID": true}, nil), Pass},
		{"file group", chk("file_groupowner", map[string]any{"FILEPATH": []any{"/etc/shadow"}, "GID_OR_NAME": "shadow"}, nil), Fail},
		{"file exists", chk("file_existence", map[string]any{"FILEPATH": "/etc/passwd", "EXISTS": true}, nil), Pass},
		{"audit watch", chk("audit_rules_watch", map[string]any{"PATH": "/etc/sudoers"}, nil), Pass},
		{"audit watch missing", chk("audit_rules_watch", map[string]any{"PATH": "/etc/shadow"}, nil), Fail},
		{"audit privileged", chk("audit_rules_privileged_commands", map[string]any{"PATH": `\/usr\/bin\/sudo`}, nil), Pass},
		{"audit privileged absent binary", chk("audit_rules_privileged_commands", map[string]any{"PATH": `\/usr\/sbin\/userhelper`}, nil), NA},
		{"audit dac", chk("audit_rules_dac_modification", map[string]any{"ATTR": "fchmod"}, nil), Pass},
		{"audit dac missing", chk("audit_rules_dac_modification", map[string]any{"ATTR": "chown"}, nil), Fail},
		{"audit unsuccessful", chk("audit_rules_unsuccessful_file_modification", map[string]any{"NAME": "creat"}, nil), Fail}, // EPERM missing
		{"kmod disabled", chk("kernel_module_disabled", map[string]any{"KERNMODULE": "atm"}, nil), Pass},
		{"kmod not blacklisted", chk("kernel_module_disabled", map[string]any{"KERNMODULE": "usb-storage"}, nil), Fail},
		{"grub arg", chk("grub2_bootloader_argument", map[string]any{"ARG_NAME": "audit", "ARG_VALUE": "1"}, nil), Pass},
		{"grub arg var ge", chk("grub2_bootloader_argument", map[string]any{"ARG_NAME": "audit_backlog_limit", "ARG_VARIABLE": "var_audit_backlog_limit", "OPERATION": "greater than or equal"}, map[string]string{"var_audit_backlog_limit": "8192"}), Pass},
		{"grub arg missing", chk("grub2_bootloader_argument", map[string]any{"ARG_NAME": "vsyscall", "ARG_VALUE": "none"}, nil), Fail},
		{"auditd conf", chk("auditd_lineinfile", map[string]any{"PARAMETER": "space_left_action", "VALUE": "email"}, nil), Pass},
		{"auditd conf wrong", chk("auditd_lineinfile", map[string]any{"PARAMETER": "local_events", "VALUE": "no"}, nil), Fail},
		{"kv pair", chk("key_value_pair_in_file", map[string]any{"PATH": "/etc/selinux/config", "KEY": "SELINUXTYPE", "SEP": "=", "XCCDF_VARIABLE": "var_selinux_policy_name"}, map[string]string{"var_selinux_policy_name": "targeted"}), Pass},
		{"shell line", chk("shell_lineinfile", map[string]any{"PATH": "/etc/firewalld/firewalld.conf", "PARAMETER": "FirewallBackend", "VALUE": "nftables"}, nil), Pass},
		{"lineinfile", chk("lineinfile", map[string]any{"PATH": "/etc/security/pwquality.conf", "TEXT": "minlen = 15"}, nil), Pass},
		{"dropin", chk("systemd_dropin_configuration", map[string]any{"MASTER_CFG_FILE": "/etc/systemd/coredump.conf", "DROPIN_DIR": "/etc/systemd/coredump.conf.d", "SECTION": "Coredump", "PARAM": "ProcessSizeMax", "VALUE": "0"}, nil), Pass},
		{"dropin master", chk("systemd_dropin_configuration", map[string]any{"MASTER_CFG_FILE": "/etc/systemd/coredump.conf", "DROPIN_DIR": "/etc/systemd/coredump.conf.d", "SECTION": "Coredump", "PARAM": "Storage", "VALUE": "none"}, nil), Pass},
		{"dconf no gui", chk("dconf_ini_file", map[string]any{"PATH": "/etc/dconf/db/local.d/", "SECTION": "org/gnome/login-screen", "PARAMETER": "banner-message-enable", "VALUE": "true"}, nil), NA},
		{"pwquality", chk("accounts_password", map[string]any{"VARIABLE": "minlen", "OPERATION": "greater than or equal"}, map[string]string{"var_password_pam_minlen": "15"}), Pass},
		{"pwquality retry", chk("accounts_password", map[string]any{"VARIABLE": "retry", "OPERATION": "less than or equal", "ZERO_COMPARISON_OPERATION": "greater than"}, map[string]string{"var_password_pam_retry": "3"}), Pass},
		{"pwquality missing", chk("accounts_password", map[string]any{"VARIABLE": "dcredit", "OPERATION": "less than or equal"}, map[string]string{"var_password_pam_dcredit": "-1"}), Fail},
		{"faillock", chk("pam_account_password_faillock", map[string]any{"PRM_NAME": "deny", "EXT_VARIABLE": "v", "PRM_REGEX_CONF": `^[\s]*deny[\s]*=[\s]*([0-9]+)`, "PRM_REGEX_PAMD": `^[\s]*auth[\s]+.+pam_faillock.so[\s]+[^\n]*deny=([0-9]+)`, "VARIABLE_LOWER_BOUND": "1", "VARIABLE_UPPER_BOUND": "use_ext_variable"}, map[string]string{"v": "3"}), Pass},
		{"pam options", chk("pam_options", map[string]any{"PATH": "/etc/pam.d/su", "TYPE": "auth", "CONTROL_FLAG": "required", "MODULE": "pam_wheel.so", "ARGUMENTS": []any{map[string]any{"argument": "use_uid"}}}, nil), Pass},
	}
	for _, c := range cases {
		ev, ok := templateEvals[c.c.Template]
		if !ok {
			t.Fatalf("%s: no evaluator for %s", c.name, c.c.Template)
		}
		got, detail := ev(n, c.c, "V-1:0")
		if got != c.want {
			t.Errorf("%s: got %s (%s) want %s", c.name, got, detail, c.want)
		}
	}
	// find-scan violations
	if st, d := evalFilePermissions(n, chk("file_permissions", map[string]any{"FILEPATH": []any{"/var/log/"}, "FILEMODE": "0640", "RECURSIVE": true}, nil), "V-1:0"); st != Fail || !strings.Contains(d, "/var/log/messages") {
		t.Errorf("recursive scan: %s %s", st, d)
	}
	// unprobed node: manual, never a false fail
	old := &nodeinfo.Info{Node: "old"}
	if st, _ := evalTemplated(old, stigdata.Rule{VID: "V-1", Checks: []stigdata.Check{chk("package_installed", map[string]any{"PKGNAME": "aide"}, nil)}}); st != Manual {
		t.Errorf("unprobed node should be manual, got %s", st)
	}
	// partial automation: templated part passes but a custom check remains
	if st, d := evalTemplated(n, stigdata.Rule{VID: "V-2", Checks: []stigdata.Check{chk("package_installed", map[string]any{"PKGNAME": "aide"}, nil), {Rule: "custom_thing"}}}); st != Manual || !strings.Contains(d, "custom_thing") {
		t.Errorf("partial: %s %s", st, d)
	}
}

func TestEmbeddedTables(t *testing.T) {
	want := map[string]int{"rhel8": 369, "rhel9": 445, "rhel10": 434, "ubuntu2204": 188, "ubuntu2404": 194}
	for prod, n := range want {
		tb, err := stigdata.Load(prod)
		if err != nil {
			t.Fatalf("%s: %v", prod, err)
		}
		if len(tb.Rules) != n {
			t.Errorf("%s: %d rules, want %d", prod, len(tb.Rules), n)
		}
		for _, r := range tb.Rules {
			for _, c := range r.Checks {
				if c.Template != "" {
					if _, ok := templateEvals[c.Template]; !ok {
						t.Errorf("%s %s: template %s has no evaluator", prod, r.VID, c.Template)
					}
				}
			}
		}
	}
	for _, b := range OSBenchmarks {
		total, auto := b.Coverage()
		if total == 0 || auto*100/total < 98 {
			t.Errorf("%s: %d/%d automated", b.Name, auto, total)
		}
		t.Logf("%s: %d/%d automated", b.Name, auto, total)
	}
	if p := stigdata.ProbeScript(); !strings.Contains(p, "sec STIGSTAT") || !strings.Contains(p, "VIOL|") || !strings.Contains(p, "/etc/security/pwquality.conf") {
		t.Errorf("probe script incomplete")
	}
}
