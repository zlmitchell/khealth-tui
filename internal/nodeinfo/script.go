// Package nodeinfo collects host-level facts from cluster nodes over SSH:
// resources, disks, services, certificates, security settings, registries,
// images and (in heavy mode) journal logs.
package nodeinfo

import (
	"fmt"
	"regexp"
	"strings"
)

// Options controls what the node script collects.
type Options struct {
	Heavy         bool     // include images, tarball manifests and journal
	LogLines      int      // journalctl -n
	LogSince      string   // journalctl --since
	KnownTarballs []string // "path|size|mtime" entries whose manifests are already known
}

var safeSince = regexp.MustCompile(`^[-+0-9a-zA-Z: ]{1,40}$`)

// Script returns the POSIX sh script executed on each node.
func Script(o Options) string {
	since := o.LogSince
	if !safeSince.MatchString(since) {
		since = "-24h"
	}
	lines := o.LogLines
	if lines <= 0 || lines > 5000 {
		lines = 400
	}
	known := strings.Join(o.KnownTarballs, "|")
	known = strings.ReplaceAll(known, "'", "")

	var b strings.Builder
	b.WriteString(baseScript)
	if o.Heavy {
		h := strings.ReplaceAll(heavyScript, "__LINES__", fmt.Sprint(lines))
		h = strings.ReplaceAll(h, "__SINCE__", since)
		h = strings.ReplaceAll(h, "__KNOWN__", known)
		b.WriteString(h)
	}
	b.WriteString("\necho '===END'\n")
	return b.String()
}

const baseScript = `
sec() { printf '\n===%s\n' "$1"; }
export LC_ALL=C
RKE2_DD=/var/lib/rancher/rke2; K3S_DD=/var/lib/rancher/k3s
for f in /etc/rancher/rke2/config.yaml /etc/rancher/rke2/config.yaml.d/*.yaml; do
  [ -f "$f" ] || continue
  v=$(sed -nE 's/^[[:space:]]*data-dir:[[:space:]]*"?([^"#]+)"?.*/\1/p' "$f" | tail -1 | sed 's/[[:space:]]*$//')
  [ -n "$v" ] && RKE2_DD=$v
done
for f in /etc/rancher/k3s/config.yaml /etc/rancher/k3s/config.yaml.d/*.yaml; do
  [ -f "$f" ] || continue
  v=$(sed -nE 's/^[[:space:]]*data-dir:[[:space:]]*"?([^"#]+)"?.*/\1/p' "$f" | tail -1 | sed 's/[[:space:]]*$//')
  [ -n "$v" ] && K3S_DD=$v
done
mask() { sed -E 's/^([[:space:]]*(token|agent-token|password|secret-key|access-key|accessKey|secretKey|etcd-s3-access-key|etcd-s3-secret-key)[[:space:]]*:).*/\1 <masked>/' "$1"; }
sec DATADIR; echo "rke2=$RKE2_DD"; echo "k3s=$K3S_DD"
sec TIME; date +%s.%N 2>/dev/null || date +%s
sec HOST; hostname; uname -r; uname -m
sec UPTIME; cat /proc/uptime
sec LOAD; cat /proc/loadavg
sec NPROC; nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo
sec STAT1; head -1 /proc/stat
sleep 1
sec STAT2; head -1 /proc/stat
sec MEM; cat /proc/meminfo
sec DF; df -PkT -x tmpfs -x devtmpfs -x overlay -x squashfs -x nsfs -x efivarfs -x fuse.lxcfs -x shm 2>/dev/null || df -Pk
sec DFI; df -Pki -x tmpfs -x devtmpfs -x overlay -x squashfs -x nsfs -x efivarfs -x fuse.lxcfs -x shm 2>/dev/null
sec SVC
for s in kubelet containerd rke2-server rke2-agent k3s k3s-agent etcd docker crio rancher-system-agent chronyd chrony ntpd ntp systemd-timesyncd firewalld ufw nftables iptables apparmor; do
  st=$(systemctl show -p LoadState,ActiveState,SubState --value "$s" 2>/dev/null | tr '\n' ' ')
  case "$st" in loaded*) echo "$s $st";; esac
done
sec UNITS
for s in rke2-server rke2-agent k3s k3s-agent kubelet containerd rancher-system-agent etcd; do
  ls=$(systemctl show -p LoadState --value "$s" 2>/dev/null); [ "$ls" = loaded ] || continue
  echo "$s|$(systemctl show -p ActiveState,SubState,NRestarts,ExecMainStartTimestamp,Result --value "$s" 2>/dev/null | tr '\n' '|')"
done
sec NTP
timedatectl show -p NTPSynchronized --value 2>/dev/null
timedatectl show -p NTP --value 2>/dev/null
sec DIST
for d in /etc/rancher/rke2 /var/lib/rancher/rke2/server /var/lib/rancher/rke2/agent /etc/rancher/k3s /var/lib/rancher/k3s/server /etc/kubernetes/manifests /etc/kubernetes/pki /var/lib/etcd /var/lib/rancher/rke2/server/db/etcd; do
  [ -d "$d" ] && echo "$d"
done
sec CERTS
if command -v openssl >/dev/null 2>&1; then
  for f in /var/lib/rancher/rke2/server/tls/*.crt /var/lib/rancher/rke2/server/tls/etcd/*.crt /var/lib/rancher/rke2/agent/*.crt /var/lib/rancher/k3s/server/tls/*.crt /var/lib/rancher/k3s/agent/*.crt /etc/kubernetes/pki/*.crt /etc/kubernetes/pki/etcd/*.crt /var/lib/kubelet/pki/kubelet.crt /var/lib/kubelet/pki/kubelet-client-current.pem /etc/ssl/etcd/ssl/*.pem; do
    [ -f "$f" ] || continue
    case "$f" in *-key.pem) continue;; esac
    e=$(openssl x509 -enddate -noout -in "$f" 2>/dev/null | sed 's/^notAfter=//')
    [ -n "$e" ] && echo "$f|$e"
  done
fi
sec KUBELETCMD
p=$(pidof kubelet 2>/dev/null | cut -d' ' -f1)
[ -n "$p" ] && tr '\0' '\n' < /proc/$p/cmdline
sec SYSCTL
for k in vm.overcommit_memory vm.panic_on_oom kernel.panic kernel.panic_on_oops kernel.keys.root_maxbytes kernel.keys.root_maxkeys net.ipv4.ip_forward net.bridge.bridge-nf-call-iptables fs.inotify.max_user_instances fs.inotify.max_user_watches; do
  echo "$k=$(sysctl -n $k 2>/dev/null)"
done
sec PERMS
for f in /etc/rancher/rke2/config.yaml /etc/rancher/rke2/registries.yaml /etc/rancher/rke2/rke2.yaml /etc/rancher/rke2/config.yaml.d /etc/rancher/k3s/config.yaml /etc/rancher/k3s/k3s.yaml /var/lib/rancher/rke2/server/db/etcd /var/lib/rancher/rke2/server/db /var/lib/rancher/rke2/agent/pod-manifests /var/lib/rancher/rke2/server/tls /var/lib/rancher/rke2/server/cred /var/lib/rancher/rke2/agent/etc/kubelet.conf.d /var/lib/rancher/rke2/agent/kubelet.kubeconfig /var/lib/rancher/rke2/agent/kubeproxy.kubeconfig /etc/kubernetes/manifests /etc/kubernetes/pki /etc/kubernetes/admin.conf /etc/kubernetes/scheduler.conf /etc/kubernetes/controller-manager.conf /etc/kubernetes/kubelet.conf /var/lib/kubelet/config.yaml /var/lib/kubelet/kubeconfig /var/lib/etcd /etc/cni/net.d /var/lib/rancher/rke2/agent/etc/cni/net.d /etc/rancher/rke2/audit-policy.yaml /etc/rancher/rke2/rke2-pss.yaml; do
  [ -e "$f" ] && stat -c '%a|%U|%G|%F|%n' "$f" 2>/dev/null
done
for d in /var/lib/rancher/rke2/agent/pod-manifests /etc/kubernetes/manifests /etc/rancher/rke2/config.yaml.d /etc/cni/net.d /var/lib/rancher/rke2/agent/etc/cni/net.d; do
  [ -d "$d" ] && stat -c '%a|%U|%G|%F|%n' "$d"/* 2>/dev/null
done
for d in /var/lib/rancher/rke2/server/tls /var/lib/rancher/rke2/server/tls/etcd /var/lib/rancher/rke2/agent /etc/kubernetes/pki /etc/kubernetes/pki/etcd; do
  [ -d "$d" ] && stat -c '%a|%U|%G|%F|%n' "$d"/*.key "$d"/*.crt 2>/dev/null
done
sec ETCDUSER; id etcd 2>/dev/null
sec SELINUX; getenforce 2>/dev/null
sec RKE2CFG
for f in /etc/rancher/rke2/config.yaml /etc/rancher/rke2/config.yaml.d/*.yaml /etc/rancher/k3s/config.yaml /etc/rancher/k3s/config.yaml.d/*.yaml; do
  [ -f "$f" ] || continue
  echo "--- $f"
  grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | mask /dev/stdin
done
sec RKE2EXTRA
for f in /etc/rancher/rke2/audit-policy.yaml /etc/rancher/rke2/rke2-pss.yaml /etc/rancher/rke2/psa.yaml /etc/rancher/rke2/rke2-cis-sysctl.conf /etc/rancher/rke2/rke2-cis.yaml /etc/rancher/k3s/audit-policy.yaml /etc/rancher/k3s/psa.yaml; do
  [ -f "$f" ] || continue
  echo "--- $f"
  head -c 16384 "$f" | mask /dev/stdin
done
for d in /etc/rancher/rke2 /etc/rancher/k3s /etc/rancher/agent /etc/rancher/node; do
  [ -d "$d" ] || continue
  echo "--- listing $d"
  ls -la "$d" 2>/dev/null | tail -n +2
done
sec MANIFESTS
for d in "$RKE2_DD/server/manifests" "$K3S_DD/server/manifests"; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    sz=$(stat -c %s "$f" 2>/dev/null); mt=$(stat -c %Y "$f" 2>/dev/null)
    kinds=$(grep -E '^kind:' "$f" 2>/dev/null | sed 's/kind:[[:space:]]*//' | sort | uniq -c | awk '{printf "%s x%s,", $2, $1}')
    echo "--- $f|$sz|$mt|$kinds"
    if [ "${sz:-0}" -le 65536 ] && ! grep -q 'chartContent:' "$f" 2>/dev/null; then
      mask "$f"
    else
      echo "(content omitted: bundled chart tarball / >64KB)"
    fi
  done
done
sec STATICPODS
for d in "$RKE2_DD/agent/pod-manifests" "$K3S_DD/agent/pod-manifests" /etc/kubernetes/manifests; do
  [ -d "$d" ] || continue
  for f in "$d"/*.yaml "$d"/*.yml; do
    [ -f "$f" ] || continue
    echo "--- $f|$(stat -c %s "$f" 2>/dev/null)|$(stat -c %Y "$f" 2>/dev/null)|"
    grep -E '^[[:space:]]*(image:|- --)' "$f" 2>/dev/null | sed 's/^[[:space:]]*//'
  done
done
sec RANCHER
echo "system-agent=$(systemctl show -p LoadState,ActiveState,SubState --value rancher-system-agent 2>/dev/null | tr '\n' ' ')"
[ -f /etc/rancher/agent/config.yaml ] && echo "agent-url=$(grep -E '^[[:space:]]*url:' /etc/rancher/agent/config.yaml 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*url:[[:space:]]*//')"
[ -f /etc/rancher/rke2/config.yaml.d/50-rancher.yaml ] && echo "rancher-provisioned=yes"
[ -f /etc/rancher/k3s/config.yaml.d/50-rancher.yaml ] && echo "rancher-provisioned=yes"
[ -f /var/lib/rancher/agent/rancher2_connection_info.json ] && echo "connection-info=yes"
[ -d /var/lib/rancher/agent/applied ] && echo "applied-plans=$(ls /var/lib/rancher/agent/applied 2>/dev/null | wc -l)"
sec CNI
for d in /var/lib/rancher/rke2/agent/etc/cni/net.d /var/lib/rancher/k3s/agent/etc/cni/net.d /etc/cni/net.d; do
  [ -d "$d" ] || continue
  for f in "$d"/*.conf "$d"/*.conflist; do [ -f "$f" ] || continue; echo "--- $f"; head -c 6000 "$f"; echo; done
done
sec REGISTRIES
for f in /etc/rancher/rke2/registries.yaml /etc/rancher/k3s/registries.yaml; do
  [ -f "$f" ] || continue
  echo "--- $f"
  sed -E 's/^([[:space:]]*(password|username|token|auth|identitytoken)[[:space:]]*:).*/\1 <masked>/' "$f"
done
sec CONTAINERDREG
for d in /var/lib/rancher/rke2/agent/etc/containerd/certs.d /var/lib/rancher/k3s/agent/etc/containerd/certs.d /etc/containerd/certs.d; do
  [ -d "$d" ] || continue
  for h in "$d"/*; do [ -d "$h" ] || continue; echo "--- $h/hosts.toml"; grep -viE 'password|username' "$h/hosts.toml" 2>/dev/null; done
done
for f in /var/lib/rancher/rke2/agent/etc/containerd/config.toml /var/lib/rancher/k3s/agent/etc/containerd/config.toml /etc/containerd/config.toml; do
  [ -f "$f" ] || continue
  echo "--- $f"
  grep -nE 'registry|mirrors|config_path|endpoint|sandbox_image|SystemdCgroup|snapshotter|default_runtime|disable_snapshot_annotations' "$f" 2>/dev/null | grep -viE 'password|username|auth' | head -80
done
`

const heavyScript = `
sec CRICTL
CRICTL=; CRI=
if [ -x /var/lib/rancher/rke2/bin/crictl ]; then CRICTL=/var/lib/rancher/rke2/bin/crictl; CRI=unix:///run/k3s/containerd/containerd.sock
elif command -v k3s >/dev/null 2>&1 && [ -S /run/k3s/containerd/containerd.sock ]; then CRICTL="k3s crictl"; CRI=
elif command -v crictl >/dev/null 2>&1; then CRICTL=$(command -v crictl)
  for s in /run/containerd/containerd.sock /var/run/crio/crio.sock /run/cri-dockerd.sock; do [ -S "$s" ] && { CRI="unix://$s"; break; }; done
fi
echo "crictl=$CRICTL cri=$CRI"
runcri() { if [ -n "$CRI" ]; then $CRICTL -r "$CRI" "$@"; else $CRICTL "$@"; fi; }
sec IMAGES
[ -n "$CRICTL" ] && runcri images -o json 2>/dev/null
sec CONTAINERS
[ -n "$CRICTL" ] && runcri ps -o json 2>/dev/null
sec TARBALLS
KNOWN='|__KNOWN__|'
for IMGDIR in /var/lib/rancher/rke2/agent/images /var/lib/rancher/k3s/agent/images; do
  [ -d "$IMGDIR" ] || continue
  for f in "$IMGDIR"/*; do
    [ -f "$f" ] || continue
    sz=$(stat -c %s "$f" 2>/dev/null); mt=$(stat -c %Y "$f" 2>/dev/null)
    echo "--- $f|$sz|$mt"
    case "$KNOWN" in *"|$f|$sz|$mt|"*) echo "(cached)"; continue;; esac
    case "$f" in
      *.txt) cat "$f";;
      *.tar) tar -xOf "$f" manifest.json 2>/dev/null;;
      *.tar.zst) command -v zstd >/dev/null 2>&1 && zstd -dc "$f" 2>/dev/null | tar -xO manifest.json 2>/dev/null;;
      *.tar.gz|*.tgz) gzip -dc "$f" 2>/dev/null | tar -xO manifest.json 2>/dev/null;;
    esac
    echo
  done
done
sec JOURNAL
journalctl --no-pager -o short-iso -q -n __LINES__ --since '__SINCE__' -u rke2-server -u rke2-agent -u k3s -u k3s-agent -u kubelet -u containerd -u rancher-system-agent -u etcd 2>/dev/null
sec LOGFILES
for f in /var/lib/rancher/rke2/agent/logs/kubelet.log /var/lib/rancher/rke2/agent/containerd/containerd.log /var/lib/rancher/k3s/agent/containerd/containerd.log; do
  [ -f "$f" ] || continue
  echo "--- $f"
  tail -n 120 "$f" 2>/dev/null | grep -E ' [EW][0-9]{4} |level=(warn|error|fatal)|error|failed' | tail -n 80
done
`
