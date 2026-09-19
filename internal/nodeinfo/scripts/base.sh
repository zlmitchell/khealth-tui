# Light node probe: host, resources, disks, services, kubelet args, cheap
# hardening facts - every refresh. The sections inside the __CONFIG__ block
# (certs, sysctls, file modes, slow hardening commands, rke2/k3s config,
# manifests, registries) change rarely and cost most of the CPU, so they run
# on heavy cycles / first contact / R only and khealth carries the previous
# result forward (Info.MergeConfig). Parsed by nodeinfo.Parse (info.go).
#
# Every systemctl/timedatectl query is a D-Bus round trip (10-800 ms wall
# on a busy node): ask for all units in one call and never loop over them.
#
# Sent to nodes over SSH by khealth as `sudo sh -s`; POSIX sh only (dash on
# Ubuntu, busybox on Flatcar). Embedded into the Go binary with //go:embed -
# edit here, not in the .go file. Sections are delimited by `sec NAME`
# (===NAME lines) and parsed by the Go side; keep names in sync with the
# parser. Never print secrets: pass file dumps through `mask`.
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
# CPU utilisation is the delta between this and the previous probe's
# counters (Info.CPUFromPrev): no sleep on the node. Only the first contact
# has nothing to diff against and samples over one second here.
if [ "__CPUSAMPLE__" = 1 ]; then sleep 1; sec STAT2; head -1 /proc/stat; fi
sec MEM; cat /proc/meminfo
sec DF; df -PkT -x tmpfs -x devtmpfs -x overlay -x squashfs -x nsfs -x efivarfs -x fuse.lxcfs -x shm 2>/dev/null || df -Pk
sec PVMOUNTS; df -Pk 2>/dev/null | grep -E 'kubelet/(pods|plugins)/.*/volumes/' | awk '{print $2"|"$3"|"$4"|"$5"|"$6}'
sec DFI; df -Pki -x tmpfs -x devtmpfs -x overlay -x squashfs -x nsfs -x efivarfs -x fuse.lxcfs -x shm 2>/dev/null
# units() prints "name|LoadState|ActiveState|SubState|NRestarts|ExecMainStartTimestamp|Result|UnitFileState" per loaded unit
units() {
  systemctl show -p Id,LoadState,ActiveState,SubState,NRestarts,ExecMainStartTimestamp,Result,UnitFileState "$@" 2>/dev/null | awk -F= '
    /^Id=/{id=$2; sub(/\.service$/,"",id)} /^LoadState=/{l=$2} /^ActiveState=/{a=$2} /^SubState=/{ss=$2} /^NRestarts=/{n=$2}
    /^ExecMainStartTimestamp=/{t=$2} /^Result=/{r=$2} /^UnitFileState=/{u=$2}
    /^$/{if(id!="" && l=="loaded") print id"|"l"|"a"|"ss"|"n"|"t"|"r"|"u; id="";l="";a="";ss="";n="";t="";r="";u=""}
    END{if(id!="" && l=="loaded") print id"|"l"|"a"|"ss"|"n"|"t"|"r"|"u}'
}
UNITS_OUT=$(units kubelet containerd rke2-server rke2-agent k3s k3s-agent etcd docker crio rancher-system-agent chronyd chrony ntpd ntp systemd-timesyncd firewalld ufw nftables iptables apparmor fapolicyd auditd unattended-upgrades dnf-automatic.timer usbguard sssd cloud-init-local cloud-init cloud-config cloud-final)
sec SVC
echo "$UNITS_OUT" | awk -F'|' '$1=="kubelet"||$1=="containerd"||$1=="rke2-server"||$1=="rke2-agent"||$1=="k3s"||$1=="k3s-agent"||$1=="etcd"||$1=="docker"||$1=="crio"||$1=="rancher-system-agent"||$1=="chronyd"||$1=="chrony"||$1=="ntpd"||$1=="ntp"||$1=="systemd-timesyncd"||$1=="firewalld"||$1=="ufw"||$1=="nftables"||$1=="iptables"||$1=="apparmor"{print $1, $2, $3, $4}'
sec UNITS
echo "$UNITS_OUT" | awk -F'|' '$1=="rke2-server"||$1=="rke2-agent"||$1=="k3s"||$1=="k3s-agent"||$1=="kubelet"||$1=="containerd"||$1=="rancher-system-agent"||$1=="etcd"||$1=="cloud-init-local"||$1=="cloud-init"||$1=="cloud-config"||$1=="cloud-final"{print $1"|"$3"|"$4"|"$5"|"$6"|"$7"|"}'
sec NTP
# timedatectl activates systemd-timedated over D-Bus (~0.8 s wall); read the
# time daemon directly when it is chrony (6 ms) or timesyncd (a file) and
# only fall back to timedatectl on config cycles
if command -v chronyc >/dev/null 2>&1 && CT=$(chronyc -n tracking 2>/dev/null); then
  case "$CT" in *"Leap status"*Normal*) echo NTPSynchronized=yes;; *) echo NTPSynchronized=no;; esac
  echo NTP=yes
elif [ -d /run/systemd/timesync ]; then
  [ -f /run/systemd/timesync/synchronized ] && echo NTPSynchronized=yes || echo NTPSynchronized=no
  echo NTP=yes
elif [ "__CONFIG__" = 1 ]; then
  timedatectl show -p NTPSynchronized -p NTP 2>/dev/null
fi
sec DIST
for d in /etc/rancher/rke2 /var/lib/rancher/rke2/server /var/lib/rancher/rke2/agent /etc/rancher/k3s /var/lib/rancher/k3s/server /etc/kubernetes/manifests /etc/kubernetes/pki /var/lib/etcd /var/lib/rancher/rke2/server/db/etcd; do
  [ -d "$d" ] && echo "$d"
done
# kubeadm workers also have an (empty) manifests dir: the apiserver manifest marks a control-plane node
[ -f /etc/kubernetes/manifests/kube-apiserver.yaml ] && echo /etc/kubernetes/manifests/kube-apiserver.yaml
if [ "__CONFIG__" = 1 ]; then
sec CERTS
if command -v openssl >/dev/null 2>&1; then
  for f in /var/lib/rancher/rke2/server/tls/*.crt /var/lib/rancher/rke2/server/tls/etcd/*.crt /var/lib/rancher/rke2/agent/*.crt /var/lib/rancher/k3s/server/tls/*.crt /var/lib/rancher/k3s/agent/*.crt /etc/kubernetes/pki/*.crt /etc/kubernetes/pki/etcd/*.crt /var/lib/kubelet/pki/kubelet.crt /var/lib/kubelet/pki/kubelet-client-current.pem /etc/ssl/etcd/ssl/*.pem; do
    [ -f "$f" ] || continue
    case "$f" in *-key.pem) continue;; esac
    e=$(openssl x509 -enddate -noout -in "$f" 2>/dev/null | sed 's/^notAfter=//')
    [ -n "$e" ] && echo "$f|$e"
  done
fi
sec APISERVERCERT
# serving cert PEM: its SANs decide which names/VIPs a kubeconfig may use
for c in /var/lib/rancher/rke2/server/tls/serving-kube-apiserver.crt /var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt /etc/kubernetes/pki/apiserver.crt; do
  [ -f "$c" ] || continue
  echo "--- $c"; cat "$c"; break
done
fi
sec KUBELETCMD
# pidof walks all of /proc (~40 ms); reuse the pid from the previous probe
# while it is still the kubelet
p=__KPID__
{ [ "$p" -gt 0 ] && [ "$(cat /proc/$p/comm 2>/dev/null)" = kubelet ]; } 2>/dev/null || p=$(pidof kubelet 2>/dev/null | cut -d' ' -f1)
[ -n "$p" ] && { echo "pid=$p"; tr '\0' '\n' < /proc/$p/cmdline; }
if [ "__CONFIG__" = 1 ]; then
sec SYSCTL
for k in vm.overcommit_memory vm.panic_on_oom kernel.panic kernel.panic_on_oops kernel.keys.root_maxbytes kernel.keys.root_maxkeys net.ipv4.ip_forward net.bridge.bridge-nf-call-iptables fs.inotify.max_user_instances fs.inotify.max_user_watches kernel.randomize_va_space kernel.dmesg_restrict kernel.kptr_restrict kernel.yama.ptrace_scope kernel.core_pattern fs.protected_symlinks fs.protected_hardlinks net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route net.ipv4.icmp_echo_ignore_broadcasts; do
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
fi
sec ETCDUSER; id etcd 2>/dev/null
sec SELINUX; getenforce 2>/dev/null
sec OSREL; grep -E '^(ID|VERSION_ID|PRETTY_NAME|ID_LIKE)=' /etc/os-release 2>/dev/null
sec HARDENING
# live, all reads of /proc, /sys and small files
echo "selinux=$(getenforce 2>/dev/null)"
echo "selinux_config=$(grep -E '^SELINUX=' /etc/selinux/config 2>/dev/null | cut -d= -f2)"
echo "fips=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)"
[ -f /sys/module/apparmor/parameters/enabled ] && echo "apparmor=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)"
echo "$UNITS_OUT" | awk -F'|' '$1=="fapolicyd"||$1=="auditd"||$1=="firewalld"||$1=="ufw"||$1=="apparmor"||$1=="unattended-upgrades"||$1=="dnf-automatic.timer"||$1=="usbguard"||$1=="sssd"||$1=="chronyd"||$1=="chrony"||$1=="systemd-timesyncd"{print "svc_"$1"="$2" "$3" "$8" "}'
echo "cmdline=$(cat /proc/cmdline 2>/dev/null)"
[ -f /sys/kernel/security/lockdown ] && echo "lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null)"
[ -f /var/run/reboot-required ] && echo "reboot_required=yes"
[ -f /etc/crypto-policies/config ] && echo "crypto_policy=$(cat /etc/crypto-policies/config 2>/dev/null)"
[ -f /proc/sys/kernel/randomize_va_space ] && echo "aslr=$(cat /proc/sys/kernel/randomize_va_space)"
if [ "__CONFIG__" = 1 ]; then
# slow: needs-restarting is a python/dnf plugin (~0.3 s CPU), the others spawn tools
command -v fips-mode-setup >/dev/null 2>&1 && echo "fips_setup=$(fips-mode-setup --check 2>/dev/null | head -1)"
command -v aa-status >/dev/null 2>&1 && echo "apparmor_enforced=$(aa-status --enforced 2>/dev/null)"
grep -qsE '\bfips=1\b' /etc/default/grub /boot/loader/entries/*.conf /boot/grub2/grubenv /boot/grub/grub.cfg /etc/kernel/cmdline 2>/dev/null && echo "fips_boot=yes" || echo "fips_boot=no"
[ -f /etc/ufw/ufw.conf ] && echo "ufw_config=$(grep -E '^ENABLED=' /etc/ufw/ufw.conf 2>/dev/null | cut -d= -f2)"
[ -f /etc/apparmor.d ] || [ -d /etc/apparmor.d ] && echo "apparmor_installed=yes"
[ -d /etc/fapolicyd/rules.d ] && echo "fapolicyd_rules=$(ls /etc/fapolicyd/rules.d 2>/dev/null | wc -l)"
command -v mokutil >/dev/null 2>&1 && echo "secureboot=$(mokutil --sb-state 2>/dev/null | head -1)"
if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1 || echo "reboot_required=yes"; fi
command -v ufw >/dev/null 2>&1 && echo "ufw=$(ufw status 2>/dev/null | head -1 | sed 's/^Status: //')"
command -v pro >/dev/null 2>&1 && echo "ubuntu_pro=$(pro status 2>/dev/null | grep -iE '^(fips|fips-updates|esm-infra|usg) ' | tr -s ' ' | tr '\n' ';')"
command -v auditctl >/dev/null 2>&1 && echo "audit_rules=$(auditctl -l 2>/dev/null | grep -vc 'No rules')"
echo "config_probed=yes"
fi
if [ "__CONFIG__" = 1 ]; then
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
fi
sec RANCHER
sa=$(echo "$UNITS_OUT" | awk -F'|' '$1=="rancher-system-agent"{print $2" "$3" "$4" "}')
echo "system-agent=${sa:-not-found inactive dead }"
[ -f /etc/rancher/agent/config.yaml ] && echo "agent-url=$(grep -E '^[[:space:]]*url:' /etc/rancher/agent/config.yaml 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*url:[[:space:]]*//')"
[ -f /etc/rancher/rke2/config.yaml.d/50-rancher.yaml ] && echo "rancher-provisioned=yes"
[ -f /etc/rancher/k3s/config.yaml.d/50-rancher.yaml ] && echo "rancher-provisioned=yes"
[ -f /var/lib/rancher/agent/rancher2_connection_info.json ] && echo "connection-info=yes"
[ -d /var/lib/rancher/agent/applied ] && echo "applied-plans=$(ls /var/lib/rancher/agent/applied 2>/dev/null | wc -l)"
if [ "__CONFIG__" = 1 ]; then
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
fi
