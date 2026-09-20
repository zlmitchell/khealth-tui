package nodeinfo

import (
	"math"
	"strings"
	"testing"
	"time"
)

const sample = `
===TIME
1726700000.500000000
===HOST
cp-1
5.15.0-100-generic
x86_64
===UPTIME
86400.12 300000.00
===LOAD
1.50 1.20 1.00 2/500 12345
===NPROC
4
===STAT1
cpu  1000 0 500 8000 100 0 0 0 0 0
===STAT2
cpu  1200 0 600 8100 100 0 0 0 0 0
===MEM
MemTotal:        8000000 kB
MemFree:         1000000 kB
MemAvailable:    2000000 kB
Buffers:          100000 kB
Cached:           500000 kB
SwapTotal:             0 kB
SwapFree:              0 kB
===DF
Filesystem     Type 1024-blocks    Used Available Capacity Mounted on
/dev/sda1      ext4    50000000 45000000   5000000      90% /
/dev/sdb1      xfs    200000000 20000000 180000000      10% /var/lib/rancher
===DFI
Filesystem      Inodes IUsed   IFree IUse% Mounted on
/dev/sda1      3000000 300000 2700000   10% /
/dev/sdb1     10000000 100000 9900000    1% /var/lib/rancher
===STALEMOUNTS
/var/lib/kubelet/plugins/kubernetes.io/csi/driver.longhorn.io/78dc/globalmount|10.43.224.112:/pvc-be8106a9|nfs4
/var/lib/kubelet/pods/0223/volumes/kubernetes.io~csi/pvc-be8106a9/mount|10.43.224.112:/pvc-be8106a9|nfs4
junk line
===SVC
rke2-server loaded active running
containerd loaded active running
chronyd loaded active running
===UNITS
rke2-server|active|running|2|Wed 2024-09-18 10:00:00 UTC|success|
===NTP
yes
yes
===DIST
/etc/rancher/rke2
/var/lib/rancher/rke2/server
/var/lib/rancher/rke2/agent
/var/lib/rancher/rke2/server/db/etcd
===CERTS
/var/lib/rancher/rke2/server/tls/client-admin.crt|Sep 18 10:00:00 2027 GMT
/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt|Jan  1 00:00:00 2034 GMT
===KUBELETCMD
kubelet
--protect-kernel-defaults=true
--hostname-override=cp-1
--anonymous-auth=false
===SYSCTL
vm.overcommit_memory=1
vm.panic_on_oom=0
kernel.panic=10
===PERMS
600|root|root|regular file|/etc/rancher/rke2/config.yaml
700|etcd|etcd|directory|/var/lib/rancher/rke2/server/db/etcd
644|root|root|regular file|/var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml
===ETCDUSER
uid=998(etcd) gid=996(etcd) groups=996(etcd)
===SELINUX
Enforcing
===OSREL
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
===HARDENING
selinux=Enforcing
selinux_config=enforcing
fips=1
fips_setup=FIPS mode is enabled.
svc_fapolicyd=loaded active
svc_auditd=loaded active
svc_firewalld=loaded inactive
lockdown=[none] integrity confidentiality
secureboot=SecureBoot enabled
crypto_policy=FIPS
===RKE2CFG
--- /etc/rancher/rke2/config.yaml
token: <masked>
profile: cis
cni: canal
etcd-snapshot-retention: 10
etcd-s3: true
etcd-s3-config-secret: rke2-s3
tls-san:
  - lb.example.com
--- /etc/rancher/rke2/config.yaml.d/50-rancher.yaml
server: https://10.0.0.1:9345
node-label:
  - cattle.io/os=linux
===MANIFESTS
--- /var/lib/rancher/rke2/server/manifests/rke2-canal.yaml|500000|1700000000|HelmChart x1,
(content omitted: bundled chart tarball / >64KB)
--- /var/lib/rancher/rke2/server/manifests/rke2-canal-config.yaml|200|1700000001|HelmChartConfig x1,
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-canal
  namespace: kube-system
spec:
  valuesContent: |-
    flannel:
      iface: eth1
===STATICPODS
--- /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml|3000|1700000002|
image: docker.io/rancher/hardened-etcd:v3.5.16
- --config-file=/var/lib/rancher/rke2/server/db/etcd/config
===RANCHER
system-agent=loaded active running
agent-url=https://rancher.example.com
rancher-provisioned=yes
applied-plans=3
===CNI
--- /var/lib/rancher/rke2/agent/etc/cni/net.d/10-canal.conflist
{"name":"k8s-pod-network","cniVersion":"0.3.1","plugins":[{"type":"calico"},{"type":"portmap"},{"type":"bandwidth"}]}
===REGISTRIES
--- /etc/rancher/rke2/registries.yaml
mirrors:
  docker.io:
    endpoint:
      - "https://harbor.example.com"
  "*":
    endpoint:
      - "https://harbor.example.com"
configs:
  "harbor.example.com":
    auth:
      username: <masked>
      password: <masked>
===CONTAINERDREG
--- /var/lib/rancher/rke2/agent/etc/containerd/certs.d/docker.io/hosts.toml
server = "https://docker.io"
[host."https://harbor.example.com"]
  capabilities = ["pull", "resolve"]
--- /var/lib/rancher/rke2/agent/etc/containerd/certs.d/_default/hosts.toml
[host."https://harbor.example.com"]
===CRICTL
crictl=/var/lib/rancher/rke2/bin/crictl cri=unix:///run/k3s/containerd/containerd.sock
===IMAGES
{"images":[{"id":"sha256:aaa","repoTags":["docker.io/rancher/mirrored-pause:3.6"],"repoDigests":[],"size":"700000"},{"id":"sha256:bbb","repoTags":["docker.io/rancher/nginx:old"],"repoDigests":[],"size":"90000000"}]}
===CONTAINERS
{"containers":[{"id":"c1","metadata":{"name":"pause"},"image":{"image":"sha256:aaa"},"imageRef":"sha256:aaa","labels":{"io.kubernetes.pod.namespace":"kube-system","io.kubernetes.pod.name":"x"}}]}
===TARBALLS
--- /var/lib/rancher/rke2/agent/images/rke2-images.linux-amd64.tar.zst|1000|1700000000
[{"Config":"a.json","RepoTags":["docker.io/rancher/mirrored-pause:3.6","docker.io/rancher/hardened-etcd:v3.5.16"],"Layers":[]}]

--- /var/lib/rancher/rke2/agent/images/extra.txt|10|1700000001
docker.io/library/busybox:1.36
===JOURNAL
2024-09-18T10:00:01+00:00 cp-1 rke2[100]: time="2024-09-18T10:00:01Z" level=info msg="rke2 is up and running"
===LOGFILES
===END
`

func TestParse(t *testing.T) {
	sent := time.Unix(1726700000, 0)
	info := Parse("cp-1", "10.0.0.1", sample, sent)
	if info.Hostname != "cp-1" || info.Kernel != "5.15.0-100-generic" {
		t.Fatalf("host parse: %+v", info)
	}
	if info.CPUs != 4 || info.Load1 != 1.5 {
		t.Errorf("cpus/load: %d %v", info.CPUs, info.Load1)
	}
	// STAT: total delta 400, idle delta 100 -> 75% busy
	if info.CPUPct < 74 || info.CPUPct > 76 {
		t.Errorf("cpu pct = %v", info.CPUPct)
	}
	if info.MemTotal != 8000000*1024 || info.MemAvail != 2000000*1024 || int(info.MemPct) != 75 {
		t.Errorf("mem: %d %d %v", info.MemTotal, info.MemAvail, info.MemPct)
	}
	if len(info.StaleMounts) != 2 || info.StaleMounts[0].Source != "10.43.224.112:/pvc-be8106a9" || info.StaleMounts[0].FSType != "nfs4" || info.StaleMounts[1].Mountpoint != "/var/lib/kubelet/pods/0223/volumes/kubernetes.io~csi/pvc-be8106a9/mount" {
		t.Errorf("stale mounts: %+v", info.StaleMounts)
	}
	if len(info.Mounts) != 2 || info.Mounts[0].Mountpoint != "/" || info.Mounts[0].UsePct != 90 || info.Mounts[0].InodePct != 10 {
		t.Errorf("mounts: %+v", info.Mounts)
	}
	if m := info.DataMount(); m == nil || m.Mountpoint != "/var/lib/rancher" {
		t.Errorf("data mount: %+v", m)
	}
	if info.ClockOffset != 500*time.Millisecond {
		t.Errorf("clock offset = %v", info.ClockOffset)
	}
	if svc := info.Service("rke2-server"); svc == nil || svc.Active != "active" {
		t.Errorf("service: %+v", svc)
	}
	if u := info.Unit("rke2-server"); u == nil || u.NRestarts != 2 || u.Started.IsZero() {
		t.Errorf("unit: %+v", u)
	}
	if info.NTPSynced == nil || !*info.NTPSynced {
		t.Errorf("ntp")
	}
	if info.Dist != "rke2" || !info.ControlPlane {
		t.Errorf("dist=%s cp=%v", info.Dist, info.ControlPlane)
	}
	if len(info.Certs) != 2 || info.Certs[0].NotAfter.Year() != 2027 || info.Certs[1].NotAfter.Year() != 2034 {
		t.Errorf("certs: %+v", info.Certs)
	}
	if info.KubeletFlags["protect-kernel-defaults"] != "true" || info.KubeletFlags["hostname-override"] != "cp-1" {
		t.Errorf("kubelet flags: %v", info.KubeletFlags)
	}
	if info.Sysctl["kernel.panic"] != "10" {
		t.Errorf("sysctl: %v", info.Sysctl)
	}
	if p := info.Perm("/var/lib/rancher/rke2/server/db/etcd"); p == nil || p.User != "etcd" || p.Mode != "700" {
		t.Errorf("perm: %+v", p)
	}
	if !info.EtcdUser || info.SELinux != "Enforcing" {
		t.Errorf("etcd user / selinux")
	}
	if info.OS.ID != "rhel" || info.OS.VersionID != "9.4" || info.OS.Family() != "rhel" || !info.FIPS() || info.ServiceState("fapolicyd") != "active" || info.ServiceState("firewalld") != "inactive" || info.Hardening["secureboot"] != "SecureBoot enabled" {
		t.Errorf("os/hardening: %+v %v", info.OS, info.Hardening)
	}
	if info.Settings["profile"] != "cis" || info.Settings["server"] != "https://10.0.0.1:9345" || info.Settings["etcd-s3-config-secret"] != "rke2-s3" {
		t.Errorf("settings: %v", info.Settings)
	}
	if info.Settings["token"] != "<masked>" {
		t.Errorf("token should be masked: %q", info.Settings["token"])
	}
	if !info.Rancher.Provisioned || info.Rancher.AgentURL != "https://rancher.example.com" || info.Rancher.Plans != 3 {
		t.Errorf("rancher: %+v", info.Rancher)
	}
	if len(info.CNI) != 1 || info.CNI[0].Name != "k8s-pod-network" || strings.Join(info.CNI[0].Types, ",") != "calico,portmap,bandwidth" {
		t.Errorf("cni: %+v", info.CNI)
	}
	if strings.Join(info.RegistryMirrors, ",") != "docker.io,*" {
		t.Errorf("mirrors: %v", info.RegistryMirrors)
	}
	if strings.Join(info.ContainerdHosts, ",") != "docker.io,_default" {
		t.Errorf("containerd hosts: %v", info.ContainerdHosts)
	}
	if !info.Heavy || len(info.Images) != 2 || len(info.Containers) != 1 {
		t.Fatalf("heavy: %v %d %d", info.Heavy, len(info.Images), len(info.Containers))
	}
	unused, bytes := info.UnusedImages()
	if len(unused) != 1 || unused[0].ID != "sha256:bbb" || bytes != 90000000 {
		t.Errorf("unused: %+v %d", unused, bytes)
	}
	if len(info.Tarballs) != 2 || !info.Tarballs[0].Parsed || len(info.Tarballs[0].Images) != 2 || info.Tarballs[1].Images[0] != "docker.io/library/busybox:1.36" {
		t.Errorf("tarballs: %+v", info.Tarballs)
	}
	if keys := info.TarballKeys(); len(keys) != 2 || keys[0] != "/var/lib/rancher/rke2/agent/images/rke2-images.linux-amd64.tar.zst|1000|1700000000" {
		t.Errorf("tarball keys: %v", keys)
	}
	if len(info.Journal) != 1 {
		t.Errorf("journal: %v", info.Journal)
	}
	if len(info.Manifests) != 2 || !info.Manifests[0].Bundled || info.Manifests[0].Kinds != "HelmChart x1" || info.Manifests[1].Bundled || !strings.Contains(info.Manifests[1].Content, "iface: eth1") || info.Manifests[1].Size != 200 {
		t.Errorf("manifests: %+v", info.Manifests)
	}
	if len(info.StaticPods) != 1 || !strings.Contains(info.StaticPods[0].Content, "hardened-etcd") {
		t.Errorf("static pods: %+v", info.StaticPods)
	}
}

func TestMergeHeavy(t *testing.T) {
	prev := Parse("n", "h", sample, time.Now())
	light := Parse("n", "h", "===HOST\nn\n===END\n", time.Now())
	light.MergeHeavy(prev)
	if len(light.Images) != 2 || len(light.Tarballs) != 2 || len(light.Journal) != 1 {
		t.Errorf("merge did not carry heavy data")
	}
	// cached tarball keeps previous manifest
	cached := Parse("n", "h", "===CRICTL\nx\n===TARBALLS\n--- /var/lib/rancher/rke2/agent/images/rke2-images.linux-amd64.tar.zst|1000|1700000000\n(cached)\n===END\n", time.Now())
	cached.MergeHeavy(prev)
	if len(cached.Tarballs) != 1 || len(cached.Tarballs[0].Images) != 2 {
		t.Errorf("cached tarball not restored: %+v", cached.Tarballs)
	}
}

func TestScriptOptions(t *testing.T) {
	s := Script(Options{Heavy: true, LogLines: 100, LogSince: "-2h", KnownTarballs: []string{"/a|1|2"}})
	if !strings.Contains(s, "-n 100") || !strings.Contains(s, "--since '-2h'") || !strings.Contains(s, "KNOWN='|/a|1|2|'") {
		t.Errorf("script substitution failed")
	}
	s = Script(Options{Heavy: true, LogSince: "'; rm -rf /"})
	if !strings.Contains(s, "--since '-24h'") {
		t.Errorf("unsafe since not sanitized")
	}
	if strings.Contains(Script(Options{}), "===JOURNAL") {
		t.Errorf("light script should not include journal")
	}
}

func TestOSStigOptionAndMerge(t *testing.T) {
	if s := Script(Options{}); strings.Contains(s, "sec SYSCTLALL") || strings.Contains(s, "sec STIGSTAT") {
		t.Errorf("light probe must not carry the OS STIG sections")
	}
	if s := Script(Options{OSStig: true}); !strings.Contains(s, "sec SYSCTLALL") || !strings.Contains(s, "sec STIGSTAT") || !strings.Contains(s, "sec STIGFILES") {
		t.Errorf("OSStig probe missing sections")
	}
	out := "===SYSCTLALL\nkernel.dmesg_restrict = 1\n===PKGS\naide\n===STIGSTAT\n644|root|root|0|0|regular file|/etc/passwd\n===STIGVIOL\nVIOL|V-1:0|/var/log/x\n===STIGFILES\n--- /etc/audit/auditd.conf\nlog_file = /var/log/audit/audit.log\n===END\n"
	first := Parse("n1", "h", out, time.Now())
	if !first.STIGProbed || first.SysctlAll["kernel.dmesg_restrict"] != "1" || !first.Packages["aide"] || first.STIGStat["/etc/passwd"].Mode != "644" || len(first.STIGViol["V-1:0"]) != 1 || len(first.STIGFiles) != 1 || first.STIGCollected.IsZero() {
		t.Fatalf("parse: %+v", first)
	}
	later := Parse("n1", "h", "===HOST\nn1\n===END\n", time.Now())
	if later.STIGProbed {
		t.Fatalf("light probe output must not claim STIG facts")
	}
	later.MergeSTIG(first)
	if !later.STIGProbed || later.STIGCollected != first.STIGCollected || later.SysctlAll["kernel.dmesg_restrict"] != "1" || len(later.STIGFiles) != 1 {
		t.Errorf("merge lost facts: %+v", later)
	}
	fresh := Parse("n1", "h", out, time.Now().Add(time.Minute))
	fresh.MergeSTIG(first)
	if fresh.STIGCollected == first.STIGCollected {
		t.Errorf("a re-collection must keep its own facts")
	}
}

// TestSTIGStages: the four stage scripts carry their own sections plus the
// helpers and footer; the one-script probe is their concatenation; stage
// output merges into an Info without claiming the facts complete until the
// caller adopts them.
func TestSTIGStages(t *testing.T) {
	want := map[string][]string{
		"system":   {"sec SYSCTLALL", "sec PKGS", "sec AUDITRULES", "sec GRUBCFG"},
		"files":    {"sec STIGSTAT", "sec STIGVIOL", "sec STIGFILES"},
		"accounts": {"sec STIGCMD", "sec PASSWD", "sec SHADOWMETA"},
		"sweep":    {"sec STIGSWEEP"},
	}
	stages := STIGStages()
	if len(stages) != 4 {
		t.Fatalf("stages: %+v", stages)
	}
	full := Script(Options{OSStig: true})
	for _, st := range stages {
		s := STIGStageScript(st.Name)
		for _, sec := range want[st.Name] {
			if !strings.Contains(s, sec) {
				t.Errorf("stage %s lacks %s", st.Name, sec)
			}
			if !strings.Contains(full, sec) {
				t.Errorf("one-script probe lacks %s", sec)
			}
		}
		for other, secs := range want {
			if other == st.Name {
				continue
			}
			for _, sec := range secs {
				if strings.Contains(s, sec) {
					t.Errorf("stage %s carries %s of stage %s", st.Name, sec, other)
				}
			}
		}
		for _, need := range []string{"sec() {", "mask() {", "sec PERF", "echo '===END'"} {
			if !strings.Contains(s, need) {
				t.Errorf("stage %s lacks %q", st.Name, need)
			}
		}
		if strings.Contains(s, "sec HOST") || strings.Contains(s, "sec KUBELET") {
			t.Errorf("stage %s carries the base probe", st.Name)
		}
	}
	if STIGStageScript("nope") != "" {
		t.Errorf("unknown stage must yield no script")
	}
	if !stages[3].Slow || stages[0].Slow {
		t.Errorf("only the sweep is slow: %+v", stages)
	}

	info := &Info{Node: "n1"}
	cost := ParseSTIGStage(info, "===SYSCTLALL\nkernel.dmesg_restrict = 1\n===PKGS\naide\n===PERF\n1.5 1.0 0.5 3/400 999\n0m0.020s 0m0.010s\n0m0.800s 0m0.300s\n===END\n")
	ParseSTIGStage(info, "===STIGSTAT\n644|root|root|0|0|regular file|/etc/passwd\n===END\n")
	ParseSTIGStage(info, "===STIGCMD\nefi=1\n===PASSWD\nroot:x:0:0:root:/root:/bin/bash\n===END\n")
	if info.STIGProbed || info.SysctlAll["kernel.dmesg_restrict"] != "1" || !info.Packages["aide"] || info.STIGStat["/etc/passwd"].Mode != "644" || info.STIGCmd["efi"] != "1" || len(info.Passwd) != 1 {
		t.Fatalf("stage merge: %+v", info)
	}
	if !cost.Parsed || cost.CPU() < 1 {
		t.Errorf("stage cost not parsed: %+v", cost)
	}
	// a repeated stage replaces its own sections only
	ParseSTIGStage(info, "===PKGS\nsudo\n===END\n")
	if info.Packages["aide"] || !info.Packages["sudo"] || info.SysctlAll["kernel.dmesg_restrict"] != "1" {
		t.Errorf("repeat merge: %+v", info.Packages)
	}
	at := time.Now()
	node := Parse("n1", "h", "===HOST\nn1\n===END\n", at)
	node.AdoptSTIG(info, at)
	if !node.STIGProbed || node.STIGCollected != at || node.STIGCmd["efi"] != "1" || !node.Packages["sudo"] {
		t.Errorf("adopt: %+v", node)
	}
}

func TestScriptPerfFooterAndCost(t *testing.T) {
	s := Script(Options{})
	i, j := strings.Index(s, "sec PERF"), strings.Index(s, "echo '===END'")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("PERF footer must precede END: perf=%d end=%d", i, j)
	}
	info := Parse("n1", "10.0.0.1", "===HOST\nn1\n===PERF\n1.5 1.0 0.5 3/400 999\n0m0.020s 0m0.010s\n0m0.800s 0m0.300s\n===END\n", time.Now())
	if !info.Cost.Parsed || math.Abs(info.Cost.User-0.82) > 1e-9 || math.Abs(info.Cost.Sys-0.31) > 1e-9 || info.Cost.Load1 != 1.5 {
		t.Fatalf("cost %+v", info.Cost)
	}
	if info.OutBytes == 0 {
		t.Fatal("out bytes not recorded")
	}
	if Parse("n1", "h", "===HOST\nn1\n===END\n", time.Now()).Cost.Parsed {
		t.Fatal("cost parsed without a PERF section")
	}
}

func TestConfigTierScriptAndMerge(t *testing.T) {
	full, light := Script(Options{Config: true}), Script(Options{})
	if strings.Contains(full, "__CONFIG__") || strings.Contains(light, "__CONFIG__") {
		t.Fatal("__CONFIG__ not substituted")
	}
	if !strings.Contains(full, `[ "1" = 1 ]`) || !strings.Contains(light, `[ "0" = 1 ]`) {
		t.Fatal("config tier flag wrong")
	}
	// single systemctl call for every unit, no per-unit loop
	if strings.Count(light, "systemctl show") != 1 || strings.Count(light, "timedatectl show") != 1 {
		t.Fatalf("expected one systemctl show and one timedatectl call: %d / %d", strings.Count(light, "systemctl show"), strings.Count(light, "timedatectl show"))
	}

	fullOut := "===CERTS\n/etc/kubernetes/pki/ca.crt|Jan  1 00:00:00 2030 GMT\n===HARDENING\nselinux=Enforcing\nfips_setup=FIPS mode is enabled.\nsecureboot=SecureBoot enabled\nconfig_probed=yes\n===SYSCTL\nvm.overcommit_memory=1\n===NTP\nNTP=yes\nNTPSynchronized=no\n===END\n"
	prev := Parse("n1", "h", fullOut, time.Now())
	if !prev.ConfigProbed || len(prev.Certs) != 1 || prev.Sysctl["vm.overcommit_memory"] != "1" || prev.Hardening["config_probed"] != "" {
		t.Fatalf("full parse: %+v", prev)
	}
	if prev.NTPEnabled == nil || !*prev.NTPEnabled || prev.NTPSynced == nil || *prev.NTPSynced {
		t.Fatalf("NTP key=value form not parsed: %v %v", prev.NTPEnabled, prev.NTPSynced)
	}
	cur := Parse("n1", "h", "===HARDENING\nselinux=Permissive\n===END\n", time.Now())
	if cur.ConfigProbed {
		t.Fatal("light probe must not claim the config tier")
	}
	cur.MergeConfig(prev)
	if !cur.ConfigProbed || len(cur.Certs) != 1 || cur.Sysctl["vm.overcommit_memory"] != "1" {
		t.Fatalf("config tier not carried forward: %+v", cur)
	}
	if cur.Hardening["selinux"] != "Permissive" || cur.Hardening["secureboot"] != "SecureBoot enabled" {
		t.Fatalf("hardening merge wrong: %v", cur.Hardening)
	}
	// a probe that ran the tier keeps its own result
	again := Parse("n1", "h", fullOut, time.Now())
	again.Certs = nil
	again.MergeConfig(prev)
	if again.Certs != nil {
		t.Fatal("merge overwrote a fresh config tier")
	}
}

func TestCPUFromPrevAndSampleFlag(t *testing.T) {
	if s := Script(Options{}); strings.Contains(s, "__CPUSAMPLE__") || !strings.Contains(s, `[ "0" = 1 ]; then sleep 1`) {
		t.Fatal("light script must not sleep")
	}
	if s := Script(Options{CPUSample: true}); !strings.Contains(s, `[ "1" = 1 ]; then sleep 1`) {
		t.Fatal("first-contact script must sample twice")
	}
	// one sample per probe: user nice system idle iowait irq softirq steal
	prev := Parse("n1", "h", "===STAT1\ncpu 1000 0 500 8000 500 0 0 0\n===END\n", time.Now())
	cur := Parse("n1", "h", "===STAT1\ncpu 1300 0 700 8400 600 0 0 0\n===END\n", time.Now())
	if prev.CPUPct != -1 || cur.CPUPct != -1 {
		t.Fatalf("single sample must leave CPUPct unknown: %v %v", prev.CPUPct, cur.CPUPct)
	}
	cur.CPUFromPrev(prev)
	// busy 500 of 1000 jiffies
	if cur.CPUPct < 49.9 || cur.CPUPct > 50.1 {
		t.Fatalf("CPUPct %.2f", cur.CPUPct)
	}
	// counter reset (reboot) or a failed previous probe: stays unknown
	reset := Parse("n1", "h", "===STAT1\ncpu 10 0 5 80 5 0 0 0\n===END\n", time.Now())
	reset.CPUFromPrev(prev)
	if reset.CPUPct != -1 {
		t.Fatal("counter reset must not produce a value")
	}
	two := Parse("n1", "h", "===STAT1\ncpu 100 0 0 900 0 0 0 0\n===STAT2\ncpu 110 0 0 990 0 0 0 0\n===END\n", time.Now())
	two.CPUFromPrev(prev)
	if two.CPUPct < 9.9 || two.CPUPct > 10.1 {
		t.Fatalf("own two-sample value must win: %.2f", two.CPUPct)
	}
	// NTP from chrony in the light tier, carried forward on light cycles when only timedatectl knows
	full := Parse("n1", "h", "===NTP\nNTPSynchronized=yes\nNTP=yes\n===HARDENING\nconfig_probed=yes\n===END\n", time.Now())
	light := Parse("n1", "h", "===NTP\n===END\n", time.Now())
	light.MergeConfig(full)
	if light.NTPSynced == nil || !*light.NTPSynced {
		t.Fatal("NTP state not carried forward")
	}
}

func TestKubeletPIDReuse(t *testing.T) {
	if s := Script(Options{}); !strings.Contains(s, "p=0\n") {
		t.Fatal("no pid should render as 0")
	}
	if s := Script(Options{KubeletPID: 4242}); !strings.Contains(s, "p=4242\n") {
		t.Fatal("kubelet pid not substituted")
	}
	info := Parse("n1", "h", "===KUBELETCMD\npid=4242\n/usr/bin/kubelet\n--anonymous-auth=false\n===END\n", time.Now())
	if info.KubeletPID != 4242 || info.KubeletFlags["anonymous-auth"] != "false" {
		t.Fatalf("pid/flags: %d %v", info.KubeletPID, info.KubeletFlags)
	}
}

func TestRegProbeParseImplicitAndSkipped(t *testing.T) {
	info := Parse("n1", "h", "===MOUNTOPTS\n/|xfs|rw\n===REGPROBE\nharbor.local|https://harbor.local|200|0||yes|yes|false|\ndocker.io|https://registry-1.docker.io|000|6|||||yes\nskipped|quay.io|https://quay.io|airgap\n===END\n", time.Now())
	p := info.Preflight
	if len(p.RegProbes) != 3 {
		t.Fatalf("probes: %+v", p)
	}
	byHost := map[string]RegProbe{}
	for _, r := range p.RegProbes {
		byHost[r.Host] = r
	}
	if byHost["harbor.local"].Implicit || byHost["harbor.local"].Code != 200 || !byHost["harbor.local"].Auth {
		t.Fatalf("explicit: %+v", byHost["harbor.local"])
	}
	if !byHost["docker.io"].Implicit || byHost["docker.io"].Exit != 6 {
		t.Fatalf("implicit: %+v", byHost["docker.io"])
	}
	if byHost["quay.io"].Skipped != "airgap" || !byHost["quay.io"].Implicit {
		t.Fatalf("skipped: %+v", byHost["quay.io"])
	}
}
