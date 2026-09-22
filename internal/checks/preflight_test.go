package checks

import (
	"strings"
	"testing"
	"time"

	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
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
		Rancher:    nodeinfo.RancherNode{Provisioned: true},
		Registries: []nodeinfo.ConfigFile{{Path: "/etc/rancher/rke2/registries.yaml", Content: "mirrors:\n  docker.io:\n    endpoint:\n      - \"https://harbor.corp:5000\"\nconfigs:\n  \"harbor.corp\":\n    auth:\n      username: <masked>\n      password: <masked>\n"}},
	}
	ni.Preflight = nodeinfo.Preflight{
		Probed: true, DeniesProbed: true, FailSwapOn: "true",
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
		SEPkgs:   []string{"package rke2-selinux is not installed", "container-selinux-2.229.0-1.el9.noarch", "package rancher-selinux is not installed"},
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
		{SevCrit, "storage", "fapolicyd has no allow rule for /var/lib/longhorn/engine-binaries"},
		{SevCrit, "node", "fapolicyd denied 7 executions of rke2/CSI binaries"},
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
		{SevCrit, "node", "SELinux is enforcing on a Rancher-provisioned node but rancher-selinux is not installed"},
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

func TestPreflightSwapRKE2Default(t *testing.T) {
	in := baseInput()
	ni := preflightInfo()
	ni.Preflight.FailSwapOn = "false"
	ni.SwapTotal, ni.SwapFree = 2097148*1024, 2000000*1024
	in.Nodes["cp-1"] = ni
	f := Evaluate(in)
	if findingWith(f, SevCrit, "node", "swap active") != nil {
		t.Error("rke2 failSwapOn=false must not raise the CRIT swap finding")
	}
	if findingWith(f, SevInfo, "node", "swap in use") == nil {
		t.Error("expected the INFO swap-in-use finding")
	}
}

func TestModprobeDisables(t *testing.T) {
	cases := map[string]bool{
		"install cdrom /bin/false": true,
		"blacklist sr_mod":         true,
		"install nf_conntrack /sbin/modprobe --ignore-install nf_conntrack $CMDLINE_OPTS": false,
		"install usb-storage /bin/true": true,
	}
	for line, want := range cases {
		f := strings.Fields(line)
		m := nodeinfo.ModprobeLine{Directive: f[0], Module: f[1], Line: line}
		if m.Disables() != want {
			t.Errorf("%q: Disables=%v want %v", line, m.Disables(), want)
		}
	}
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

func TestRegistryProbeOffline(t *testing.T) {
	// airgapped node: implicit upstreams are listed as skipped, never a finding
	skipped := nodeinfo.RegProbe{Host: "docker.io", URL: "https://registry-1.docker.io", Implicit: true, Skipped: "airgap"}
	if _, _, _, bad := regVerdict(skipped, distro.For("rke2")); bad {
		t.Fatal("skipped probe produced a finding")
	}
	// an implicit upstream that was probed and is unreachable says why containerd would go there
	msg, _, sev, bad := regVerdict(nodeinfo.RegProbe{Host: "docker.io", URL: "https://registry-1.docker.io", Exit: 6, Implicit: true}, distro.For("rke2"))
	if !bad || sev != SevWarn || !strings.Contains(msg, "no mirror endpoint") {
		t.Fatalf("implicit unreachable: %v %q", bad, msg)
	}
	// explicit mirror endpoints keep the plain wording
	msg, _, _, _ = regVerdict(nodeinfo.RegProbe{Host: "harbor.local", URL: "https://harbor.local", Exit: 7}, distro.For("rke2"))
	if strings.Contains(msg, "no mirror endpoint") {
		t.Fatalf("explicit endpoint tagged implicit: %q", msg)
	}
}

// The crictl pull dry run goes through the hosts.toml containerd renders
// from registries.yaml; its verdicts name the host containerd's error
// names and tell a mirror that failed from a mirror that fell through to
// the upstream registry.
func TestRegistryPullVerdicts(t *testing.T) {
	v := distro.For("rke2")
	dd := "/var/lib/rancher/rke2"
	img := "docker.io/rancher/mirrored-pause@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pf := &nodeinfo.Preflight{RegProbes: []nodeinfo.RegProbe{{Host: "harbor.corp:5000", URL: "https://harbor.corp:5000", Code: 200, Auth: true}}}
	for _, r := range []nodeinfo.RegPull{
		{Registry: "docker.io", Image: img, Endpoints: []string{"harbor.corp:5000"}, OK: true},
		{Registry: "quay.io", Skipped: "airgap"},
		{Registry: "quay.io", Skipped: "no image from this registry on the node"},
	} {
		if _, _, _, bad := pullVerdict(r, pf, false, dd, v); bad {
			t.Errorf("finding for %+v", r)
		}
	}
	// 401 from the mirror while curl with the same credentials succeeds: the rendered hosts.toml is at fault
	msg, hint, sev, bad := pullVerdict(nodeinfo.RegPull{Registry: "docker.io", Image: img, Endpoints: []string{"harbor.corp:5000"},
		Detail: "pulling from host harbor.corp:5000 failed with status code https://harbor.corp:5000/v2/rancher/mirrored-pause/manifests/sha256:aaaa: 401 Unauthorized"}, pf, false, dd, v)
	if !bad || sev != SevCrit || !strings.Contains(msg, "authentication rejected") || !strings.Contains(msg, "curl from the node") || !strings.Contains(hint, dd+"/agent/etc/containerd/certs.d/docker.io/hosts.toml") {
		t.Errorf("401: %v %s %q %q", bad, sev, msg, hint)
	}
	// the mirror answered 404 and containerd fell through to the registry itself, which has no DNS
	fell := nodeinfo.RegPull{Registry: "gone.example", Image: "gone.example/x/y@sha256:dddd", Endpoints: []string{"gone-mirror.corp"},
		Detail: `failed to do request: Head "https://gone.example/v2/x/y/manifests/sha256:dddd": dial tcp: lookup gone.example on 10.0.0.2:53: no such host`}
	msg, _, sev, bad = pullVerdict(fell, pf, false, dd, v)
	if !bad || sev != SevWarn || !strings.Contains(msg, "does not hold") || !strings.Contains(msg, "fell through to gone.example") {
		t.Errorf("fell through: %v %s %q", bad, sev, msg)
	}
	// ... which on an airgapped node is expected: INFO, no egress complaint
	msg, _, sev, bad = pullVerdict(fell, pf, true, dd, v)
	if !bad || sev != SevInfo || !strings.Contains(msg, "airgapped") {
		t.Errorf("fell through on airgap: %v %s %q", bad, sev, msg)
	}
	// the mirror endpoint itself is unreachable
	msg, hint, sev, bad = pullVerdict(nodeinfo.RegPull{Registry: "ghcr.io", Image: "ghcr.io/org/app@sha256:cccc", Endpoints: []string{"ghcr-mirror.corp"},
		Detail: `failed to do request: Head "https://ghcr-mirror.corp/v2/org/app/manifests/sha256:cccc": dial tcp 10.0.0.9:443: connect: connection refused`}, pf, false, dd, v)
	if !bad || sev != SevWarn || !strings.Contains(msg, "cannot pull from registry ghcr.io through its mirror ghcr-mirror.corp") || strings.Contains(msg, "curl from the node") || !strings.Contains(hint, "certs.d/ghcr.io/hosts.toml") {
		t.Errorf("unreachable mirror: %v %s %q %q", bad, sev, msg, hint)
	}
	// three digits of a digest are not a status code
	msg, _, sev, _ = pullVerdict(nodeinfo.RegPull{Registry: "ghcr.io", Image: "ghcr.io/org/app@sha256:4013cccc", Endpoints: []string{"ghcr-mirror.corp"},
		Detail: `failed to do request: Head "https://ghcr-mirror.corp/v2/org/app/manifests/sha256:4013cccc": dial tcp 10.0.0.9:443: connect: connection refused`}, pf, false, dd, v)
	if sev != SevWarn || strings.Contains(msg, "authentication") {
		t.Errorf("digest digits read as a status: %s %q", sev, msg)
	}
	// no mirror endpoint, the registry itself no longer has the image: informational
	msg, _, sev, bad = pullVerdict(nodeinfo.RegPull{Registry: "quay.io", Image: "quay.io/a/b@sha256:eeee", Detail: "quay.io/a/b@sha256:eeee: not found"}, pf, false, dd, v)
	if !bad || sev != SevInfo || !strings.Contains(msg, "no longer serves") {
		t.Errorf("not found: %v %s %q", bad, sev, msg)
	}
	msg, _, sev, bad = pullVerdict(nodeinfo.RegPull{Registry: "slow.example", Image: "slow.example/x/y@sha256:ffff", Endpoints: []string{"slow-mirror.corp"}, Detail: "timed out after 20 s"}, pf, false, dd, v)
	if !bad || sev != SevWarn || !strings.Contains(msg, "timed out") {
		t.Errorf("timeout: %v %s %q", bad, sev, msg)
	}
	// kubeadm nodes: containerd's own certs.d
	_, hint, _, _ = pullVerdict(nodeinfo.RegPull{Registry: "docker.io", Image: img, Endpoints: []string{"harbor.corp:5000"}, Detail: "x: 403 Forbidden"}, pf, false, "/var/lib/kubelet", distro.For("kubeadm"))
	if strings.Contains(hint, "/etc/containerd/certs.d/") {
		t.Errorf("403 hint should point at the registry ACLs, got %q", hint)
	}
	_, hint, _, _ = pullVerdict(nodeinfo.RegPull{Registry: "docker.io", Image: img, Endpoints: []string{"harbor.corp:5000"}, Detail: "timed out after 20 s"}, pf, false, "/var/lib/kubelet", distro.For("kubeadm"))
	if !strings.Contains(hint, "/etc/containerd/certs.d/docker.io/hosts.toml") {
		t.Errorf("kubeadm hosts.toml path: %q", hint)
	}
}

// Pull results flow into Evaluate (heavy tier) and the preflight detail rows.
func TestRegistryPullFindingsAndRows(t *testing.T) {
	in := baseInput()
	ni := &nodeinfo.Info{Node: "cp-1", Dist: "rke2", DataDir: "/var/lib/rancher/rke2", RegistryMirrors: []string{"docker.io"}, KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Settings: map[string]string{}, Hardening: map[string]string{}}
	ni.Preflight = nodeinfo.Preflight{Probed: true, PullsProbed: true, Pulls: []nodeinfo.RegPull{
		{Registry: "docker.io", Image: "docker.io/rancher/mirrored-pause@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Endpoints: []string{"harbor.corp:5000"}, Detail: "pulling from host harbor.corp:5000 failed with status code https://harbor.corp:5000/v2/x: 401 Unauthorized"},
		{Registry: "quay.io", Skipped: "airgap"},
	}}
	in.Nodes["cp-1"] = ni
	var got bool
	for _, f := range findingsFor(Evaluate(in), "cp-1") {
		if strings.Contains(f.Message, "authentication rejected") {
			got = true
			if f.Area != "images" || f.Severity != SevCrit {
				t.Errorf("finding: %+v", f)
			}
		}
	}
	if !got {
		t.Error("no pull finding")
	}
	rows := PreflightRows(ni, in.Cfg, time.Now())
	var pullRows []string
	for _, r := range rows {
		if strings.HasPrefix(r[0], "pull ") {
			pullRows = append(pullRows, r[0]+"="+r[2]+":"+r[1])
		}
	}
	if len(pullRows) != 2 || !strings.HasPrefix(pullRows[0], "pull docker.io=crit:FAILED via mirror harbor.corp:5000") || !strings.HasPrefix(pullRows[1], "pull quay.io=dim:not tested: node has airgap") {
		t.Errorf("rows: %q", pullRows)
	}
	// crictl missing on a node with mirrors: one INFO, one dim row
	ni.Preflight = nodeinfo.Preflight{Probed: true, PullsProbed: true, CrictlMissing: true}
	got = false
	for _, f := range findingsFor(Evaluate(in), "cp-1") {
		if strings.Contains(f.Message, "crictl is not on the node") {
			got = f.Severity == SevInfo
		}
	}
	if !got {
		t.Error("no crictl-missing finding")
	}
}

// Host enforcing with the policy packages installed but no selinux: true:
// rke2 is confined, the pods are not.
func TestSELinuxPodsUnconfined(t *testing.T) {
	ni := preflightInfo()
	ni.Preflight.SEPkgs = []string{"rke2-selinux-0.19-1.el9.noarch", "container-selinux-2.229.0-1.el9.noarch", "rancher-selinux-0.5-1.el9.noarch"}
	ni.Settings = map[string]string{"cni": "canal"}
	in := baseInput()
	in.Nodes["cp-1"] = ni
	fs := Evaluate(in)
	if f := findingWith(fs, SevWarn, "node", "has no selinux: true: containerd runs the pods unconfined"); f == nil {
		t.Errorf("unconfined pods not reported")
	}
	for _, f := range fs {
		if strings.Contains(f.Message, "policy packages are not installed") || strings.Contains(f.Message, "rancher-selinux is not installed") {
			t.Errorf("packages reported missing: %s", f.Message)
		}
	}
	// with selinux: true everything is in place: nothing about SELinux
	ni.Settings["selinux"] = "true"
	for _, f := range Evaluate(in) {
		if strings.Contains(f.Message, "SELinux is enforcing") {
			t.Errorf("unexpected: %s", f.Message)
		}
	}
}

// A leftover /var/lib/rook or /var/lib/trident on a node whose cluster runs
// neither driver is not a fapolicyd finding; the driver registered on the
// node (or installed in the cluster) is what makes the directory matter.
func TestFapolicydCSIDirsOnlyForPresentDrivers(t *testing.T) {
	ni := preflightInfo()
	ni.Preflight.CSI.Drivers = []string{"driver.longhorn.io"}
	ni.Preflight.CSI.HostDirs = []string{"/var/lib/longhorn/engine-binaries", "/var/lib/rook", "/var/lib/trident"}
	in := baseInput()
	in.Nodes["cp-1"] = ni
	fs := Evaluate(in)
	if findingWith(fs, SevCrit, "storage", "fapolicyd has no allow rule for /var/lib/longhorn/engine-binaries") == nil {
		t.Error("longhorn dir (driver registered) not reported")
	}
	for _, d := range []string{"/var/lib/rook", "/var/lib/trident"} {
		if f := findingWith(fs, SevCrit, "storage", "fapolicyd has no allow rule for "+d); f != nil {
			t.Errorf("leftover %s reported without the driver: %s", d, f.Message)
		}
	}
	// Trident installed in the cluster (CSIDriver object) but not registered
	// on this node yet: the cluster-level presence counts
	in.Snap.CSIDrivers = []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "csi.trident.netapp.io"}}}
	if findingWith(Evaluate(in), SevCrit, "storage", "fapolicyd has no allow rule for /var/lib/trident") == nil {
		t.Error("trident dir not reported although the driver is installed")
	}
}
