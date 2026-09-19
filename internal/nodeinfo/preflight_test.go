package nodeinfo

import (
	"strings"
	"testing"
	"time"
)

const preflightSample = `
===CERTS
===DIST
/etc/rancher/rke2
/var/lib/rancher/rke2/agent
===UNITS
rke2-server|active|running|0|Wed 2024-09-18 10:00:00 UTC|success|
cloud-init|active|exited|0|Wed 2024-09-18 10:00:00 UTC|success|
cloud-final|failed|failed|0|Wed 2024-09-18 10:00:05 UTC|exit-code|
===SWAPS
/dev/dm-1                               partition	2097148	1024	-2
===PFUNITS
NetworkManager.service|active|enabled
nm-cloud-setup.timer|inactive|enabled
vmtoolsd.service|inactive|disabled
fapolicyd.service|active|enabled
auditd.service|active|enabled
firewalld.service|inactive|disabled
===FSTABSWAP
/dev/mapper/rl-swap     none                    swap    defaults        0 0
===KUBELETSWAP
failSwapOn:false
swapBehavior:LimitedSwap
===MOUNTOPTS
/|xfs|rw,relatime,seclabel
/var|xfs|rw,nosuid,nodev,noexec,relatime,seclabel
/var/log/audit|xfs|rw,nosuid,nodev,noexec,relatime,seclabel
===MODPROBE
/etc/modprobe.d/stig.conf:install cdrom /bin/false
/etc/modprobe.d/stig.conf:install usb-storage /bin/false
===MODULES
overlay
br_netfilter
===VIRT
vendor=VMware, Inc.
product=VMware20,1
cloud_init=yes
datasource_list=[ NoCloud, VMware, None ]
datasource=DataSourceNoCloud [seed=/dev/sr0][dsmode=net]
status={"v1": {"datasource": "DataSourceNoCloud [seed=/dev/sr0][dsmode=net]", "init": {"errors": [], "finished": 1.0, "start": 0.5}, "modules-final": {"errors": ["('scripts-user', RuntimeError('Runparts: 1 failures'))"], "finished": 3.0, "start": 2.0}, "stage": null}}
srdev=/dev/sr0
wwn=2
===CLOUDINIT
result={"v1": {"datasource": "DataSourceNoCloud", "errors": ["('scripts-user', RuntimeError('Runparts'))"]}}
log=2026-09-19 10:00:00,000 - cc_scripts_user.py[ERROR]: Failed to run module scripts_user
===VCENTER
vc.corp:443|200|0
vc2.corp|000|7
===FAPOLICYD
present=yes
permissive=0
rules_files=10-languages.rules 20-dracut.rules 80-rke2.rules 90-deny-execute.rules 95-allow-open.rules
compiled_mtime=1700000000
rulesd_mtime=1700000500
deny_file=90-deny-execute.rules
compiled_k8s=4
rule=80-rke2.rules:allow perm=any all : dir=/var/lib/rancher/
rule=80-rke2.rules:allow perm=any all : dir=/opt/cni/
rule=80-rke2.rules:allow perm=any all : dir=/run/k3s/
rule=80-rke2.rules:allow perm=any all : dir=/var/lib/kubelet/
rule=30-patterns.rules:allow perm=open all : dir=/usr/share/
===CSI
driver=driver.longhorn.io|
driver=csi.vsphere.vmware.com|
dir=/var/lib/longhorn/engine-binaries
dir=/var/lib/longhorn
multipath_blacklist=0
find_multipaths=no
mount_nfs=yes
===AUDITD
log_file=/var/log/audit/audit.log
max_log_file=8
max_log_file_action=keep_logs
space_left=25%
space_left_action=email
admin_space_left=50
admin_space_left_action=single
disk_full_action=halt
disk_error_action=halt
===ACCOUNTS
sudo_user=rancher
today=20000
login_defs_PASS_MAX_DAYS=60
default_inactive=35
user|root|0|/bin/bash|set|19990|1|60|7||
user|rancher|1000|/bin/bash|set|19900|1|60|7|35|
user|etcd|998|/sbin/nologin|none|19800|0|99999|7||
user|ops|1001|/bin/bash|locked|19950|1|60|7||20100
faillock_deny=3
faillock|root|0
faillock|rancher|3
ci_user=rancher
ci_default=rocky
sudo|rancher|nopasswd=yes|keys=1
===PROXY
/etc/default/rke2-server|HTTP_PROXY=http://<masked>@proxy.corp:3128
/etc/default/rke2-server|NO_PROXY=127.0.0.0/8,10.42.0.0/16,10.43.0.0/16,.svc,.cluster.local
===IPTABLES
iptables=iptables v1.8.4 (nf_tables)
===SEPKG
package rke2-selinux is not installed
container-selinux-2.229.0-1.el9.noarch
===NMCONF
===REGPROBE
F|harbor.corp:5000|ca_file|/etc/rancher/rke2/harbor-ca.crt|missing
harbor.corp:5000|https://harbor.corp:5000|401|0|401|yes|yes|false
registry-1.docker.io|https://registry-1.docker.io|401|0|200|||false
mirror.corp|https://mirror.corp|000|60||||false
===FAPDENY
7|1700003600|/var/lib/rancher/rke2/data/v1.30/bin/containerd-shim-runc-v2|/var/lib/rancher/rke2/data/v1.30/bin/runc
2|1700003000|/usr/bin/bash|/home/ops/tool.sh
===END
`

func TestParsePreflight(t *testing.T) {
	info := Parse("n1", "10.0.0.1", preflightSample, time.Now())
	p := info.Preflight
	if !p.Probed || !p.DeniesProbed {
		t.Fatalf("expected config and heavy tiers parsed: %+v", p)
	}
	if len(p.Swaps) != 1 || p.Swaps[0].SizeKB != 2097148 || p.Swaps[0].Name != "/dev/dm-1" {
		t.Errorf("swaps: %+v", p.Swaps)
	}
	if !p.Units["fapolicyd.service"].Active || !p.Units["nm-cloud-setup.timer"].Enabled || p.Units["vmtoolsd.service"].Active {
		t.Errorf("units: %+v", p.Units)
	}
	if len(p.FstabSwap) != 1 || p.FailSwapOn != "false" || p.SwapBehavior != "LimitedSwap" {
		t.Errorf("fstab swap: %v failSwapOn=%q behavior=%q", p.FstabSwap, p.FailSwapOn, p.SwapBehavior)
	}
	if m := p.MountOpt("/var/lib/rancher/rke2"); m == nil || m.Mountpoint != "/var" || !m.Has("noexec") {
		t.Errorf("mount for data-dir: %+v", m)
	}
	if m := p.MountOpt("/var/log/audit/audit.log"); m == nil || m.Mountpoint != "/var/log/audit" {
		t.Errorf("mount for audit log: %+v", m)
	}
	if len(p.Modprobe) != 2 || p.Modprobe[0].Module != "cdrom" || p.Modprobe[1].Module != "usb_storage" || p.Modprobe[0].Directive != "install" {
		t.Errorf("modprobe: %+v", p.Modprobe)
	}
	if !p.Modules["overlay"] || p.Modules["sr_mod"] {
		t.Errorf("modules: %v", p.Modules)
	}
	if !p.Virt.VMware() || p.Virt.VMTools || len(p.Virt.SRDevs) != 1 {
		t.Errorf("virt: %+v", p.Virt)
	}
	if p.CloudInit.Seed() != "/dev/sr0" || !p.CloudInit.Installed || len(p.CloudInit.Errors) != 1 || !strings.HasPrefix(p.CloudInit.Errors[0], "modules-final: ") {
		t.Errorf("cloud-init: %+v", p.CloudInit)
	}
	if len(p.CloudInit.Units) != 2 || len(p.CloudInit.FailedUnits()) != 1 || p.CloudInit.FailedUnits()[0] != "cloud-final (exit-code)" || len(p.CloudInit.LogErrors) != 1 || len(p.CloudInit.ResultErrors) != 1 {
		t.Errorf("cloud-init units/log: %+v", p.CloudInit)
	}
	if p.Virt.WWNDisks != 2 || len(p.VCenters) != 2 || p.VCenters[0].Code != 200 || p.VCenters[1].Exit != 7 {
		t.Errorf("wwn/vcenter: %+v %+v", p.Virt, p.VCenters)
	}
	if len(p.CIUsers) != 1 || p.CIUsers[0] != "rancher" || p.CIDefault != "rocky" || !p.Sudo["rancher"].NoPasswd || p.Sudo["rancher"].Keys != 1 {
		t.Errorf("ci users/sudo: %v %q %+v", p.CIUsers, p.CIDefault, p.Sudo)
	}
	if p.CSI.FindMultipaths != "no" || !p.CSI.MountNFS {
		t.Errorf("csi host prereqs: %+v", p.CSI)
	}
	fa := p.Fapolicyd
	if !fa.Present || fa.Permissive != "0" || len(fa.RulesFiles) != 5 || fa.DenyFile != "90-deny-execute.rules" || fa.CompiledK8s != 4 || len(fa.AllowRules) != 5 || len(fa.K8sRules) != 4 {
		t.Errorf("fapolicyd: %+v", fa)
	}
	if fa.RulesdMtime <= fa.CompiledMtime {
		t.Errorf("mtimes: %+v", fa)
	}
	if _, ok := fa.Covers("/var/lib/rancher/rke2"); !ok {
		t.Errorf("rke2 data-dir should be covered")
	}
	if _, ok := fa.Covers("/var/lib/longhorn/engine-binaries"); ok {
		t.Errorf("longhorn dir must not be covered")
	}
	if len(p.CSI.Drivers) != 2 || p.CSI.Drivers[0] != "driver.longhorn.io" || !p.CSI.Has("longhorn") || len(p.CSI.HostDirs) != 2 || p.CSI.ISCSID || p.CSI.MultipathBlacklist != 0 {
		t.Errorf("csi: %+v", p.CSI)
	}
	if p.Auditd["disk_full_action"] != "halt" || p.Auditd["admin_space_left"] != "50" || p.Auditd["log_file"] != "/var/log/audit/audit.log" {
		t.Errorf("auditd: %v", p.Auditd)
	}
	if p.SudoUser != "rancher" || p.Today != 20000 || p.LoginDefs["PASS_MAX_DAYS"] != "60" || p.LoginDefs["INACTIVE"] != "35" {
		t.Errorf("accounts meta: sudo=%q today=%d defs=%v", p.SudoUser, p.Today, p.LoginDefs)
	}
	if len(p.Accounts) != 4 {
		t.Fatalf("accounts: %+v", p.Accounts)
	}
	r := p.Account("rancher")
	if r == nil || r.PW != "set" || r.LastChange != 19900 || r.Max != 60 || r.Inactive != 35 || r.PasswordExpiry() != 19960 {
		t.Errorf("rancher account: %+v", r)
	}
	if e := p.Account("etcd"); e == nil || e.PW != "none" || e.PasswordExpiry() != 0 {
		t.Errorf("etcd account: %+v", e)
	}
	if o := p.Account("ops"); o == nil || o.PW != "locked" || o.Expire != 20100 || o.PasswordExpiry() != 0 {
		t.Errorf("ops account: %+v", o)
	}
	if p.Faillock["rancher"] != 3 || p.FaillockDeny != 3 {
		t.Errorf("faillock: %v deny=%d", p.Faillock, p.FaillockDeny)
	}
	if len(p.Proxy) != 2 || p.Proxy[0].Key != "HTTP_PROXY" || !strings.Contains(p.Proxy[0].Value, "<masked>") || p.Proxy[1].Key != "NO_PROXY" {
		t.Errorf("proxy: %+v", p.Proxy)
	}
	if p.Iptables != "iptables v1.8.4 (nf_tables)" {
		t.Errorf("iptables: %q", p.Iptables)
	}
	if len(p.SEPkgs) != 2 {
		t.Errorf("sepkgs: %v", p.SEPkgs)
	}
	if len(p.RegFiles) != 1 || !p.RegFiles[0].Missing || p.RegFiles[0].Kind != "ca_file" {
		t.Errorf("regfiles: %+v", p.RegFiles)
	}
	if len(p.RegProbes) != 3 {
		t.Fatalf("regprobes: %+v", p.RegProbes)
	}
	var harbor, hub, mirror RegProbe
	for _, r := range p.RegProbes {
		switch r.Host {
		case "harbor.corp:5000":
			harbor = r
		case "registry-1.docker.io":
			hub = r
		case "mirror.corp":
			mirror = r
		}
	}
	if harbor.Code != 401 || harbor.TokenCode != 401 || !harbor.Auth || !harbor.CA {
		t.Errorf("harbor probe: %+v", harbor)
	}
	if hub.Code != 401 || hub.TokenCode != 200 || hub.Auth {
		t.Errorf("hub probe: %+v", hub)
	}
	if mirror.Code != 0 || mirror.Exit != 60 {
		t.Errorf("mirror probe: %+v", mirror)
	}
	if len(p.Denies) != 2 || p.Denies[0].Count != 7 || !strings.HasSuffix(p.Denies[0].Path, "/runc") || p.Denies[0].Last.Unix() != 1700003600 {
		t.Errorf("denies: %+v", p.Denies)
	}
}

func TestPreflightMerge(t *testing.T) {
	prev := Parse("n1", "h", preflightSample, time.Now())
	light := Parse("n1", "h", "===SWAPS\n===PFUNITS\nfapolicyd.service|inactive|disabled\n===END\n", time.Now())
	if light.Preflight.Probed || light.Preflight.DeniesProbed {
		t.Fatalf("light probe must not carry config/heavy tiers: %+v", light.Preflight)
	}
	light.MergeConfig(prev)
	light.MergeHeavy(prev)
	p := light.Preflight
	if !p.Probed || len(p.Accounts) != 4 || len(p.RegProbes) != 3 {
		t.Errorf("config tier not carried forward: %+v", p)
	}
	if len(p.Swaps) != 0 || p.Units["fapolicyd.service"].Active {
		t.Errorf("light facts must win: swaps=%v units=%v", p.Swaps, p.Units)
	}
	if !p.DeniesProbed || len(p.Denies) != 2 {
		t.Errorf("heavy tier not carried forward: %+v", p.Denies)
	}
}

func TestScriptIncludesPreflight(t *testing.T) {
	s := Script(Options{Config: true, Heavy: true, VCenters: []string{"vc.corp:443", "bad host;rm", "vc2.corp"}})
	if !strings.Contains(s, "for vc in vc.corp:443 vc2.corp; do") {
		t.Errorf("vcenter list not substituted/sanitised")
	}
	for _, want := range []string{"sec SWAPS", "sec PFUNITS", "sec MOUNTOPTS", "sec REGPROBE", "sec FAPDENY", "sec CSI"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %s", want)
		}
	}
	if strings.Contains(s, "__CONFIG__") || strings.Contains(s, "__HEAVY__") {
		t.Errorf("placeholders left in script")
	}
	light := Script(Options{})
	if !strings.Contains(light, `if [ "0" = 1 ]; then
sec FSTABSWAP`) {
		t.Errorf("light script should skip the preflight config tier")
	}
}
