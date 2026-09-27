# Node half of the log bundle (khealth --gather): journals, kernel log,
# container and pod logs, runtime state, network state and masked config
# of one node, as a gzipped tar on stdout. Parsed by gather.readNodeTar.
#
# Runs after nodeinfo.Prelude (asyaml, sec, mask, maskreg, RKE2_DD,
# K3S_DD, runcri) as `sudo sh -s`; POSIX sh only. Stdout is the tar stream
# and nothing else: every other byte goes to stderr (fd 1 is moved to 2
# below, the archive is written to the saved fd 3).
#
# Outputs are staged in a private directory under /var/tmp or /tmp. When
# neither has room (a full disk is a usual reason to gather) tmpfs (/run,
# /dev/shm) is used, but only with four times the budget in MemAvailable:
# filling RAM on a node that is already short of it would make the OOM
# killer part of the incident.
# Every file is capped at __FILE_BYTES__ bytes (the newest end is kept,
# logs are oldest-first) and the staging dir at __BUDGET_KB__ KiB: items
# are collected most useful first and the rest are listed in
# _gather/skipped. Nothing that holds a private key or a kubeconfig is
# read; config dumps pass through mask/maskreg.
exec 3>&1 1>&2
umask 077
BUDGET_KB=__BUDGET_KB__
FILECAP=__FILE_BYTES__
PODCAP=__POD_BYTES__
MIN=__MINUTES__
SINCE="-${MIN}min"
PODGLOBS='__PODGLOBS__'
TO=; command -v timeout >/dev/null 2>&1 && TO="timeout 120"
command -v tar >/dev/null 2>&1 || { echo "gather: tar is not installed on this node" >&2; exit 3; }

# stale staging dirs of runs that were killed (the trap below never ran)
find /run /dev/shm /var/tmp /tmp -maxdepth 1 -name 'khealth-gather.*' -mmin +120 -exec rm -rf {} + 2>/dev/null
D=
MEMAVAIL=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
for base in /var/tmp /tmp /run /dev/shm; do
  [ -d "$base" ] && [ -w "$base" ] || continue
  avail=$(df -Pk "$base" 2>/dev/null | awk 'NR==2{print $4}')
  [ -n "$avail" ] && [ "$avail" -gt $((BUDGET_KB + 65536)) ] || continue
  if [ "$(stat -f -c %T "$base" 2>/dev/null)" = tmpfs ]; then
    [ "${MEMAVAIL:-0}" -gt $((BUDGET_KB * 4)) ] || continue
  fi
  D=$(mktemp -d "$base/khealth-gather.XXXXXX" 2>/dev/null) && break
done
[ -n "$D" ] || { echo "gather: no staging directory with $((BUDGET_KB/1024 + 64)) MiB free in /var/tmp, /tmp, /run or /dev/shm (tmpfs also needs 4x that in MemAvailable); lower --gather-node-mb" >&2; exit 4; }
trap 'rm -rf "$D"' EXIT INT TERM HUP
S=$D/_gather
mkdir -p "$S"
START=$(date +%s)

room() { [ "$(du -sk "$D" 2>/dev/null | cut -f1)" -lt "$BUDGET_KB" ]; }
# capt FILE [CAP]: keep the newest CAP bytes of stdin; a cut is noted and
# the partial first line dropped
capt() {
  c=${2:-$FILECAP}
  tail -c $((c + 1)) > "$1"
  if [ "$(wc -c < "$1")" -gt "$c" ]; then
    sed -i '1d' "$1" 2>/dev/null
    echo "${1#"$D"/}" >> "$S/truncated"
  fi
}
prep() { room || { echo "$1" >> "$S/skipped"; return 1; }; pf=$D/$1; mkdir -p "${pf%/*}"; }
# put NAME CMD...: an external command's output (with a timeout)
put() { n=$1; shift; prep "$n" || return 0; $TO "$@" 2>&1 | capt "$D/$n"; }
# putf NAME FUNC...: a shell function's output (functions time out inside)
putf() { n=$1; shift; prep "$n" || return 0; "$@" 2>&1 | capt "$D/$n"; }
# copyf NAME SRC [CAP]: the tail of a file
# logs pass through scrublog (base.sh): the kubelet dumps container specs
# with their env values into its errors
copyf() { [ -f "$2" ] || return 0; prep "$1" || return 0; scrublog < "$2" | capt "$D/$1" "${3:-$FILECAP}"; }
jctl() { { $TO journalctl --no-pager -o short-iso-precise "$@" 2>/dev/null || $TO journalctl --no-pager -o short-iso "$@"; } | scrublog; }
# args of any flag naming a token or password, and TOKEN=/PASSWORD= env
# lines (unit files, env files), on top of mask's YAML keys
maskargs() { sed -E 's/(--?[A-Za-z0-9_-]*(token|password|secret)[A-Za-z0-9_-]*[= ])[^ ",]+/\1<masked>/Ig; s/^([A-Za-z0-9_]*(TOKEN|PASSWORD|SECRET)[A-Za-z0-9_]*=).*/\1<masked>/I'; }
masktoml() { sed -E 's/^([[:space:]]*(password|username|auth|identitytoken|token|registrytoken)[[:space:]]*=).*/\1 "<masked>"/'; }
exists() { [ -e "$1" ]; }

# --- what this node is --------------------------------------------------
IS_RKE2=; IS_K3S=; IS_KUBEADM=
[ -d /etc/rancher/rke2 ] || [ -d "$RKE2_DD/agent" ] && IS_RKE2=1
[ -d /etc/rancher/k3s ] || [ -d "$K3S_DD/agent" ] && IS_K3S=1
[ -f /etc/kubernetes/kubelet.conf ] || [ -f /var/lib/kubelet/kubeadm-flags.env ] && IS_KUBEADM=1
UNITS_ALL=$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{sub(/\.service$/,"",$1); print $1}')
has_unit() { echo "$UNITS_ALL" | grep -qx "$1"; }
K8S_UNITS=
for u in rke2-server rke2-agent k3s k3s-agent kubelet containerd docker cri-docker crio etcd rancher-system-agent; do
  has_unit "$u" && K8S_UNITS="$K8S_UNITS $u"
done
HOST_UNITS=
for u in NetworkManager systemd-networkd firewalld ufw nftables fapolicyd auditd chronyd chrony ntpd systemd-timesyncd iscsid multipathd sshd ssh cloud-init; do
  has_unit "$u" && HOST_UNITS="$HOST_UNITS $u"
done

# --- 1. the node at a glance (small, always) -----------------------------
sysinfo() {
  echo "hostname: $(hostname)"; echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ) (local $(date))"
  # klog lines (rke2's kubelet.log) carry local time without a zone: the
  # timeline reads them with this offset
  echo "tz: $(date +%z)"
  uname -a; cat /proc/uptime; cat /proc/loadavg; nproc 2>/dev/null
  cat /etc/os-release 2>/dev/null
  echo "rke2=$IS_RKE2 k3s=$IS_K3S kubeadm=$IS_KUBEADM units:$K8S_UNITS"
}
putf system/node.txt sysinfo
versions() {
  for c in rke2 k3s kubelet kubeadm containerd runc crictl; do
    command -v "$c" >/dev/null 2>&1 || continue
    printf '%s: ' "$c"
    case $c in kubeadm) $TO kubeadm version -o short;; crictl) runcri --version;; *) $TO "$c" --version 2>&1 | head -2 | tr '\n' ' '; echo;; esac
  done
  [ -d "$RKE2_DD/data" ] && ls -1 "$RKE2_DD/data"
}
putf system/versions.txt versions
put system/meminfo.txt cat /proc/meminfo
psi() { for f in /proc/pressure/*; do [ -f "$f" ] && { echo "== ${f##*/}"; cat "$f"; }; done; }
putf system/pressure.txt psi
put system/df.txt timeout 15 df -PhT
put system/df-inodes.txt timeout 15 df -Pi
put system/mounts.txt cat /proc/mounts
put system/lsblk.txt lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,RO
procs() { ps -eo pid,ppid,user,stat,pcpu,pmem,rss,etime,args --sort=-pcpu 2>/dev/null || ps aux; }
putf system/ps.txt procs
put system/top.txt top -b -n 1 -w 512
limits() {
  echo "file-nr: $(cat /proc/sys/fs/file-nr)"; echo "pid_max: $(cat /proc/sys/kernel/pid_max)"
  for f in /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max /proc/sys/fs/inotify/max_user_watches /proc/sys/fs/inotify/max_user_instances; do
    [ -f "$f" ] && echo "${f##*/}: $(cat "$f")"
  done
}
putf system/limits.txt limits
failed() { systemctl --failed --no-pager --no-legend; echo; systemctl status --no-pager -l -n 0 $K8S_UNITS $HOST_UNITS; }
putf system/units.txt failed
unitfiles() { systemctl cat --no-pager $K8S_UNITS 2>&1 | maskargs; for u in $K8S_UNITS; do for e in /etc/default/$u /etc/sysconfig/$u; do [ -f "$e" ] && { echo "== $e"; maskargs < "$e"; }; done; done; }
putf system/unit-files.txt unitfiles
timesync() {
  command -v chronyc >/dev/null 2>&1 && { chronyc -n tracking; chronyc -n sources; }
  $TO timedatectl 2>/dev/null
}
putf system/time.txt timesync
secstate() {
  command -v getenforce >/dev/null 2>&1 && { echo "selinux: $(getenforce)"; sestatus 2>/dev/null; }
  command -v aa-status >/dev/null 2>&1 && aa-status 2>/dev/null | head -20
  command -v fapolicyd-cli >/dev/null 2>&1 && systemctl is-active fapolicyd
  echo "fips: $(cat /proc/sys/crypto/fips_enabled 2>/dev/null)"
}
putf system/security.txt secstate

# --- 2. the logs of the kubernetes units -----------------------------------
put journal/boots.txt journalctl --list-boots --no-pager
for u in $K8S_UNITS; do
  putf "journal/$u.log" jctl -u "$u" --since "$SINCE"
done
if [ -n "$IS_RKE2" ] || [ -n "$IS_K3S" ]; then
  for dd in "$RKE2_DD" "$K3S_DD"; do
    [ -d "$dd/agent" ] || continue
    for f in "$dd"/agent/logs/*.log "$dd"/agent/containerd/containerd.log; do
      [ -f "$f" ] && copyf "files/${dd##*/}/${f#"$dd"/}" "$f"
    done
  done
fi
putf journal/kernel.log jctl -k --since "$SINCE"
dmesgt() { dmesg -T 2>/dev/null || dmesg; }
putf system/dmesg.txt dmesgt

# --- 3. container runtime and pod logs -------------------------------------
if [ -n "$CRICTL" ]; then
  putf runtime/ps.txt runcri ps -a
  putf runtime/pods.txt runcri pods
  putf runtime/ps.json runcri ps -a -o json
  putf runtime/pods.json runcri pods -o json
  putf runtime/images.txt runcri images
  crinfo() { runcri info | maskreg /dev/stdin; }
  putf runtime/info.json crinfo
fi
kubelethealth() { command -v curl >/dev/null 2>&1 && curl -s -m 5 http://127.0.0.1:10248/healthz; echo; }
putf runtime/kubelet-healthz.txt kubelethealth
# pod logs on disk: /var/log/pods/<ns>_<pod>_<uid>/<container>/<restart>.log,
# the two newest restarts of each container (the one before a crash is
# the lower number) written within the window, for the pods PODGLOBS names
# (the static control plane always; with the API down, every system
# namespace; the gathered workload's pods)
podlogs() {
  find /var/log/pods -mindepth 3 -maxdepth 3 -name '[0-9]*.log' -mmin -"$MIN" 2>/dev/null |
    awk -F/ '{n=$NF; sub(/\.log$/,"",n); print $5"/"$6"|"n"|"$0}' | sort -t'|' -k1,1 -k2,2nr |
    awk -F'|' 'c[$1]++<2{print $3}'
}
set -f
for f in $(podlogs); do
  pd=${f#/var/log/pods/}; pd=${pd%%/*}
  ok=
  for g in $PODGLOBS; do
    case $pd in $g) ok=1; break;; esac
  done
  [ -n "$ok" ] && copyf "pods/${f#/var/log/pods/}" "$f" "$PODCAP"
done
set +f

# --- 4. network -----------------------------------------------------------
put network/addr.txt ip -d addr
put network/route.txt ip route show table all
put network/rule.txt ip rule
put network/neigh.txt ip neigh
put network/link-stats.txt ip -s link
put network/listen.txt ss -tulpn
put network/ss-summary.txt ss -s
command -v iptables-save >/dev/null 2>&1 && put network/iptables.txt iptables-save -c
command -v ip6tables-save >/dev/null 2>&1 && put network/ip6tables.txt ip6tables-save -c
command -v nft >/dev/null 2>&1 && put network/nftables.txt nft list ruleset
command -v ipvsadm >/dev/null 2>&1 && put network/ipvs.txt ipvsadm -Ln
command -v firewall-cmd >/dev/null 2>&1 && put network/firewalld.txt firewall-cmd --list-all-zones
command -v ufw >/dev/null 2>&1 && put network/ufw.txt ufw status verbose
command -v nmcli >/dev/null 2>&1 && put network/nmcli.txt nmcli -t dev status
dnsfiles() { for f in /etc/resolv.conf /run/systemd/resolve/resolv.conf /etc/hosts /etc/nsswitch.conf; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; done; }
putf network/dns.txt dnsfiles
# only .conf/.conflist: calico-kubeconfig in the same dir holds a token
cniconf() { for f in /etc/cni/net.d/*.conf /etc/cni/net.d/*.conflist /run/flannel/subnet.env; do [ -f "$f" ] && { echo "== $f"; maskargs < "$f"; }; done; ls -la /etc/cni/net.d /opt/cni/bin 2>/dev/null; }
putf network/cni.txt cniconf

# --- 5. configuration (masked) and certificates ----------------------------
rancherconf() {
  for f in /etc/rancher/rke2/config.yaml /etc/rancher/rke2/config.yaml.d/*.yaml /etc/rancher/k3s/config.yaml /etc/rancher/k3s/config.yaml.d/*.yaml; do
    [ -f "$f" ] && { echo "== $f"; asyaml "$f" | mask /dev/stdin; }
  done
  for f in /etc/rancher/rke2/registries.yaml /etc/rancher/k3s/registries.yaml; do
    [ -f "$f" ] && { echo "== $f"; asyaml "$f" | maskreg /dev/stdin; }
  done
}
[ -n "$IS_RKE2$IS_K3S" ] && putf config/rancher.yaml rancherconf
containerdconf() {
  for f in "$RKE2_DD/agent/etc/containerd/config.toml" "$K3S_DD/agent/etc/containerd/config.toml" /etc/containerd/config.toml /etc/crio/crio.conf; do
    [ -f "$f" ] && { echo "== $f"; masktoml < "$f"; }
  done
  for f in "$RKE2_DD"/agent/etc/containerd/certs.d/*/hosts.toml /etc/containerd/certs.d/*/hosts.toml; do
    [ -f "$f" ] && { echo "== $f"; masktoml < "$f"; }
  done
}
putf config/containerd.toml containerdconf
kubeletconf() {
  for f in /var/lib/kubelet/config.yaml /var/lib/kubelet/kubeadm-flags.env /etc/default/kubelet /etc/sysconfig/kubelet; do
    [ -f "$f" ] && { echo "== $f"; maskargs < "$f"; }
  done
}
putf config/kubelet.txt kubeletconf
manifests() {
  for f in /etc/kubernetes/manifests/*.yaml "$RKE2_DD"/agent/pod-manifests/*.yaml "$K3S_DD"/agent/pod-manifests/*.yaml; do
    [ -f "$f" ] && { echo "== $f"; mask "$f" | maskargs; }
  done
}
putf config/static-pods.yaml manifests
certs() {
  command -v openssl >/dev/null 2>&1 || { echo "no openssl"; return; }
  for f in "$RKE2_DD"/server/tls/*.crt "$RKE2_DD"/server/tls/etcd/*.crt "$RKE2_DD"/agent/*.crt \
           "$K3S_DD"/server/tls/*.crt "$K3S_DD"/server/tls/etcd/*.crt "$K3S_DD"/agent/*.crt \
           /etc/kubernetes/pki/*.crt /etc/kubernetes/pki/etcd/*.crt /var/lib/kubelet/pki/*.crt /var/lib/kubelet/pki/kubelet-client-current.pem; do
    [ -f "$f" ] || continue
    echo "== $f"
    openssl x509 -in "$f" -noout -subject -issuer -startdate -enddate -ext subjectAltName 2>&1
  done
}
putf config/certs.txt certs
sysctls() { sysctl -a 2>/dev/null | grep -Ev '^(dev\.cdrom|kernel\.random\.(uuid|boot_id))'; lsmod; }
putf system/sysctl-lsmod.txt sysctls

# --- 6. wider logs, most expensive last ------------------------------------
for u in $HOST_UNITS; do
  putf "journal/host/$u.log" jctl -u "$u" --since "$SINCE"
done
putf journal/warnings.log jctl -p warning --since "$SINCE"
if [ "$(journalctl --list-boots --no-pager 2>/dev/null | grep -c .)" -gt 1 ]; then
  putf journal/previous-boot.log jctl -b -1 -n 5000
fi
if command -v ausearch >/dev/null 2>&1; then
  TS=yesterday; [ "$MIN" -gt 1440 ] && TS=week-ago
  put system/denials.txt ausearch -m AVC,USER_AVC,SELINUX_ERR,FANOTIFY -ts "$TS" -i
fi
for f in /var/log/messages /var/log/syslog; do
  copyf "files/${f##*/}" "$f"
done

# --- done -----------------------------------------------------------------
{
  echo "staging=$D"; echo "budget_kb=$BUDGET_KB"; echo "file_cap=$FILECAP"; echo "minutes=$MIN"
  echo "used_kb=$(du -sk "$D" | cut -f1)"; echo "seconds=$(( $(date +%s) - START ))"
  echo "rke2=$IS_RKE2"; echo "k3s=$IS_K3S"; echo "kubeadm=$IS_KUBEADM"; echo "units=$K8S_UNITS"
  times
} > "$S/node.env" 2>&1
cd "$D" || exit 5
# the reader skips to this line: a login banner or profile output that
# reaches stdout (USG/STIG images print one) cannot corrupt the archive
printf '\n===KHEALTH-GATHER-TAR\n' >&3
if command -v gzip >/dev/null 2>&1; then
  tar -cf - . 2>/dev/null | gzip -1 >&3
else
  tar -cf - . 2>/dev/null >&3
fi
