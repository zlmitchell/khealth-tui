package nodeinfo

import (
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
		t.Errorf("unsafe since not sanitised")
	}
	if strings.Contains(Script(Options{}), "===JOURNAL") {
		t.Errorf("light script should not include journal")
	}
}
