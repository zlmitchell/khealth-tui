package checks

import (
	"strings"
	"testing"

	"k8s-health-tui/internal/nodeinfo"
)

// preflightInfo builds a node with the facts a hardened, mis-tuned RKE2
// vSphere node would report.
func preflightInfo() *nodeinfo.Info {
	ni := &nodeinfo.Info{
		Node: "cp-1", Dist: "rke2", DataDir: "/var/lib/rancher/rke2", SELinux: "Enforcing",
		Services:     []nodeinfo.Service{{Name: "rke2-server", Load: "loaded", Active: "active", Sub: "running"}, {Name: "fapolicyd", Load: "loaded", Active: "active", Sub: "running"}, {Name: "auditd", Load: "loaded", Active: "active", Sub: "running"}},
		Mounts:       []nodeinfo.Mount{{Mountpoint: "/", SizeKB: 50e6, AvailKB: 20e6, UsePct: 60}, {Mountpoint: "/var/log/audit", SizeKB: 1e6, AvailKB: 150e3, UsePct: 85}},
		KubeletFlags: map[string]string{}, Sysctl: map[string]string{"net.ipv4.ip_forward": "0", "fs.inotify.max_user_instances": "128"},
		Settings:   map[string]string{"cni": "canal", "selinux": "true"},
		Hardening:  map[string]string{},
		Registries: []nodeinfo.ConfigFile{{Path: "/etc/rancher/rke2/registries.yaml", Content: "mirrors:\n  docker.io:\n    endpoint:\n      - \"https://harbor.corp:5000\"\nconfigs:\n  \"harbor.corp\":\n    auth:\n      username: <masked>\n      password: <masked>\n"}},
	}
	ni.Preflight = nodeinfo.Preflight{
		Probed: true, DeniesProbed: true,
		Swaps:     []nodeinfo.SwapDev{{Name: "/dev/dm-1", Type: "partition", SizeKB: 2097148}},
		Units:     map[string]nodeinfo.PFUnit{"fapolicyd.service": {Active: true}, "auditd.service": {Active: true}, "NetworkManager.service": {Active: true}, "nm-cloud-setup.timer": {Enabled: true}, "firewalld.service": {Active: true}, "multipathd.service": {Active: true}},
		MountOpts: []nodeinfo.MountOpt{{Mountpoint: "/", Type: "xfs", Options: []string{"rw"}}, {Mountpoint: "/var", Type: "xfs", Options: []string{"rw", "nosuid", "nodev", "noexec"}}},
		Modprobe:  []nodeinfo.ModprobeLine{{File: "/etc/modprobe.d/stig.conf", Directive: "install", Module: "cdrom", Line: "install cdrom /bin/false"}},
		Modules:   map[string]bool{},
		Virt:      nodeinfo.VirtInfo{Vendor: "VMware, Inc.", Product: "VMware20,1"},
		CloudInit: nodeinfo.CloudInit{Installed: true, Datasource: "DataSourceNoCloud [seed=/dev/sr0][dsmode=net]", DatasourceList: "[ VMware, None ]", Errors: []string{"modules-final: runcmd failed"}},
		Fapolicyd: nodeinfo.Fapolicyd{Present: true, Permissive: "0", DenyFile: "90-deny-execute.rules", CompiledK8s: 4, CompiledMtime: 100, RulesdMtime: 200,
			AllowRules: []string{"80-rke2.rules:allow perm=any all : dir=/var/lib/rancher/", "80-rke2.rules:allow perm=any all : dir=/opt/cni/"},
			K8sRules:   []string{"80-rke2.rules:allow perm=any all : dir=/var/lib/rancher/", "80-rke2.rules:allow perm=any all : dir=/opt/cni/"}},
		CSI:      nodeinfo.CSIInfo{Drivers: []string{"driver.longhorn.io"}, HostDirs: []string{"/var/lib/longhorn/engine-binaries", "/var/lib/longhorn"}, MultipathBlacklist: -1},
		Auditd:   map[string]string{"log_file": "/var/log/audit/audit.log", "max_log_file_action": "keep_logs", "admin_space_left": "50", "admin_space_left_action": "single", "disk_full_action": "halt", "space_left_action": "email"},
		SudoUser: "rancher", Today: 20000,
		Accounts: []nodeinfo.Account{
			{Name: "root", UID: 0, Shell: "/bin/bash", PW: "set", LastChange: 19950, Max: 60, Min: 1, Warn: 7, Inactive: -1, Expire: -1},
			{Name: "rancher", UID: 1000, Shell: "/bin/bash", PW: "set", LastChange: 19900, Max: 60, Min: 1, Warn: 7, Inactive: 35, Expire: -1},
			{Name: "etcd", UID: 998, Shell: "/sbin/nologin", PW: "none", LastChange: 19000, Max: 60, Inactive: -1, Expire: -1},
			{Name: "ops", UID: 1001, Shell: "/bin/bash", PW: "set", LastChange: 19995, Max: 60, Inactive: -1, Expire: 19999},
		},
		Faillock: map[string]int{"rancher": 3, "root": 0}, FaillockDeny: 3,
		Proxy:    []nodeinfo.ProxyLine{{File: "/etc/default/rke2-server", Key: "HTTP_PROXY", Value: "http://proxy:3128"}, {File: "/etc/default/rke2-server", Key: "NO_PROXY", Value: "127.0.0.0/8,10.42.0.0/16,10.43.0.0/16"}},
		Iptables: "iptables v1.8.4 (nf_tables)",
		SEPkgs:   []string{"package rke2-selinux is not installed", "container-selinux-2.229.0-1.el9.noarch"},
		RegFiles: []nodeinfo.RegFile{{Key: "harbor.corp:5000", Kind: "ca_file", Path: "/etc/rancher/rke2/ca.crt", Missing: true}},
		RegProbes: []nodeinfo.RegProbe{
			{Host: "harbor.corp:5000", URL: "https://harbor.corp:5000", Code: 401, TokenCode: 401, Auth: true},
			{Host: "registry-1.docker.io", URL: "https://registry-1.docker.io", Code: 401, TokenCode: 200},
			{Host: "mirror.corp", URL: "https://mirror.corp", Exit: 60},
			{Host: "ok.corp", URL: "https://ok.corp", Code: 200},
		},
		Denies: []nodeinfo.FapDeny{{Count: 7, Exe: "/var/lib/rancher/rke2/data/v1/bin/containerd-shim-runc-v2", Path: "/var/lib/rancher/rke2/data/v1/bin/runc"}},
	}
	return ni
}

func findingWith(f []Finding, sev Severity, area, substr string) *Finding {
	for i := range f {
		if f[i].Severity == sev && f[i].Area == area && strings.Contains(f[i].Message, substr) {
			return &f[i]
		}
	}
	return nil
}

func TestPreflightFindings(t *testing.T) {
	in := baseInput()
	in.Nodes["cp-1"] = preflightInfo()
	f := Evaluate(in)
	want := []struct {
		sev    Severity
		area   string
		substr string
	}{
		{SevCrit, "node", "swap active (2.0GiB on /dev/dm-1): the running kubelet"},
		{SevWarn, "node", "rules.d changed after compiled.rules"},
		{SevCrit, "storage", "fapolicyd allows the rke2 paths but not /var/lib/longhorn/engine-binaries"},
		{SevCrit, "node", "fapolicyd denied 7 executions of rke2/k8s binaries"},
		{SevWarn, "storage", "iscsid is not running"},
		{SevWarn, "storage", "multipathd is running without a blacklist"},
		{SevCrit, "node", "auditd admin_space_left_action=single,disk_full_action=halt"},
		{SevCrit, "node", "/var/lib/rancher/rke2 is on /var mounted noexec"},
		{SevCrit, "security", "password of ssh user rancher expired 40 days ago (account locks 35 days later)"},
		{SevWarn, "security", "password of root root expires in 10 days"},
		{SevWarn, "security", "account user ops expired 1 days ago"},
		{SevCrit, "security", "rancher is locked out by pam_faillock (3 failed attempts, deny=3)"},
		{SevWarn, "node", "NO_PROXY does not cover node IPs 10.0.0.1, 10.0.0.2, 10.0.0.3"},
		{SevCrit, "node", "cloud-init read its NoCloud seed from /dev/sr0"},
		{SevWarn, "node", "datasource_list [ VMware, None ] excludes NoCloud"},
		{SevWarn, "node", "cloud-init reported errors"},
		{SevWarn, "node", "VMware VM without open-vm-tools"},
		{SevWarn, "node", "firewalld is active"},
		{SevWarn, "node", "NetworkManager manages the CNI interfaces"},
		{SevWarn, "node", "nm-cloud-setup is enabled"},
		{SevWarn, "node", "host iptables v1.8.4"},
		{SevCrit, "node", "SELinux is enforcing but the rke2-selinux/container-selinux"},
		{SevCrit, "node", "net.ipv4.ip_forward=0"},
		{SevInfo, "node", "fs.inotify.max_user_instances=128"},
		{SevCrit, "images", "registries.yaml configs harbor.corp:5000: ca_file /etc/rancher/rke2/ca.crt does not exist"},
		{SevCrit, "images", "registry harbor.corp:5000 rejects the credentials in registries.yaml (HTTP 401)"},
		{SevWarn, "images", "registry mirror.corp unreachable from the node: certificate not trusted"},
		{SevWarn, "images", `configs key "harbor.corp" does not match mirror endpoint "harbor.corp:5000"`},
	}
	for _, w := range want {
		if findingWith(f, w.sev, w.area, w.substr) == nil {
			t.Errorf("missing %s/%s finding containing %q", w.sev, w.area, w.substr)
		}
	}
	for _, bad := range []string{"registry-1.docker.io", "registry ok.corp", "password of user etcd", "root is locked out"} {
		for _, x := range f {
			if strings.Contains(x.Message, bad) {
				t.Errorf("unexpected finding: %s %s", x.Severity, x.Message)
			}
		}
	}
	if len(findingsFor(f, "cp-1")) == 0 {
		t.Fatal("no findings")
	}
}

func TestPreflightQuiet(t *testing.T) {
	in := baseInput()
	ni := &nodeinfo.Info{Node: "cp-1", Dist: "rke2", DataDir: "/var/lib/rancher/rke2", Services: []nodeinfo.Service{{Name: "rke2-server", Load: "loaded", Active: "active", Sub: "running"}}, KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Settings: map[string]string{}, Hardening: map[string]string{}}
	ni.Preflight = nodeinfo.Preflight{
		Probed: true, Units: map[string]nodeinfo.PFUnit{"fapolicyd.service": {Active: true}, "vmtoolsd.service": {Active: true}},
		MountOpts: []nodeinfo.MountOpt{{Mountpoint: "/", Type: "xfs", Options: []string{"rw"}}},
		Virt:      nodeinfo.VirtInfo{Vendor: "VMware, Inc.", VMTools: true},
		CloudInit: nodeinfo.CloudInit{Installed: true, Datasource: "DataSourceNoCloud [seed=/dev/sr0]"},
		Fapolicyd: nodeinfo.Fapolicyd{Present: true, Permissive: "0", DenyFile: "90-deny-execute.rules", CompiledK8s: 4, CompiledMtime: 200, RulesdMtime: 100,
			AllowRules: []string{"80-rke2.rules:allow perm=any all : dir=/var/lib/rancher/", "81-csi.rules:allow perm=any all : dir=/var/lib/longhorn/"},
			K8sRules:   []string{"80-rke2.rules:allow perm=any all : dir=/var/lib/rancher/"}},
		CSI:      nodeinfo.CSIInfo{Drivers: []string{"driver.longhorn.io"}, HostDirs: []string{"/var/lib/longhorn/engine-binaries", "/var/lib/longhorn"}, ISCSID: true, MultipathBlacklist: 1},
		SudoUser: "root", Today: 20000,
		Accounts:  []nodeinfo.Account{{Name: "root", PW: "set", LastChange: 19990, Max: 99999, Inactive: -1, Expire: -1}},
		RegProbes: []nodeinfo.RegProbe{{Host: "harbor.corp", URL: "https://harbor.corp", Code: 200, Auth: true}},
	}
	in.Nodes["cp-1"] = ni
	for _, x := range findingsFor(Evaluate(in), "cp-1") {
		if (x.Area == "node" || x.Area == "security" || x.Area == "images" || x.Area == "storage") && !strings.Contains(x.Message, "taint") {
			t.Errorf("unexpected finding on a healthy node: %s %s: %s", x.Severity, x.Area, x.Message)
		}
	}
}

func findingsFor(f []Finding, obj string) []Finding {
	var out []Finding
	for _, x := range f {
		if x.Object == obj {
			out = append(out, x)
		}
	}
	return out
}

func TestNoProxyCovers(t *testing.T) {
	entries := []string{"127.0.0.0/8", "10.0.0.0/16", "192.168.1.5", ".svc"}
	if !noProxyCovers(entries, "10.0.3.4") || !noProxyCovers(entries, "192.168.1.5") || noProxyCovers(entries, "192.168.1.6") {
		t.Error("noProxyCovers")
	}
	if !noProxyCovers([]string{"*"}, "1.2.3.4") {
		t.Error("wildcard")
	}
}

func TestAuditMB(t *testing.T) {
	if auditMB("25%", 1024*1000) != 250 || auditMB("50", 0) != 50 || auditMB("", 0) != 0 {
		t.Error("auditMB")
	}
}
