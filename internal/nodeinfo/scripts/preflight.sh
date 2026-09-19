# Preflight probe: host facts that stop rke2/k3s from running or from being
# (re)provisioned even though the OS looks healthy - swap that came back,
# fapolicyd without the rke2 rules, auditd configured to halt the node when
# /var/log/audit fills, noexec on the data-dir, expired admin passwords or
# faillock lockouts, proxies without NO_PROXY, a blacklisted CD-ROM driver on
# a vSphere VM that boots from a cloud-init ISO, private registries whose
# credentials are rejected. Parsed by nodeinfo.parsePreflight (preflight.go);
# findings in checks/preflight.go.
#
# The SWAPS and PFUNITS sections run every refresh (reads of /proc and /run);
# everything inside __CONFIG__ runs with the config tier (heavy cycles, first
# contact, R) and is carried forward by Info.MergeConfig; FAPDENY (ausearch)
# runs with the heavy tier. The registry probe is the only network activity:
# parallel curls capped at 6 s each.
#
# Runs after base.sh in the same shell: sec, mask, RKE2_DD and K3S_DD are
# defined there. Sent to nodes over SSH by khealth as `sudo sh -s`; POSIX sh
# only (dash on Ubuntu, busybox on Flatcar). Embedded into the Go binary
# with //go:embed - edit here, not in the .go file. Never print secrets:
# /etc/shadow is reduced to set/locked/none plus the ages, proxy URLs lose
# their userinfo, registry passwords only ever go to curl's stdin.
sec SWAPS
tail -n +2 /proc/swaps 2>/dev/null
sec PFUNITS
# /run/systemd/units/invocation:<unit> exists while a unit runs and the
# *.wants symlinks say whether it starts at boot: no D-Bus round trip, so
# this is cheap enough for every refresh
for u in NetworkManager.service nm-cloud-setup.service nm-cloud-setup.timer vmtoolsd.service open-vm-tools.service cloud-init.service cloud-final.service multipathd.service fapolicyd.service auditd.service firewalld.service; do
  a=inactive; [ -e "/run/systemd/units/invocation:$u" ] && a=active
  e=disabled; ls /etc/systemd/system/*.wants/"$u" >/dev/null 2>&1 && e=enabled
  echo "$u|$a|$e"
done
if [ "__CONFIG__" = 1 ]; then
sec FSTABSWAP
grep -E '^[^#]*[[:space:]]swap[[:space:]]' /etc/fstab 2>/dev/null
sec KUBELETSWAP
# rke2/k3s write failSwapOn: false into their kubelet defaults; kubeadm and
# a kubelet-arg override keep the upstream default (true)
grep -hsE '^[[:space:]]*(failSwapOn|swapBehavior):' "$RKE2_DD"/agent/etc/kubelet.conf.d/*.conf "$K3S_DD"/agent/etc/kubelet.conf.d/*.conf /var/lib/kubelet/config.yaml /etc/rancher/rke2/kubelet-config.yaml 2>/dev/null | tr -d ' '
sec MOUNTOPTS
# real filesystems only, without the per-pod bind mounts: mountpoint|fstype|options
awk '($1 ~ /^\// || $3 ~ /^(nfs|nfs4|cifs|zfs|fuse\.|fuse$)/) && $2 !~ /^\/(var\/lib\/kubelet\/(pods|plugins)|run\/k3s|sys\/|proc\/|dev\/)/ {print $2"|"$3"|"$4}' /proc/mounts 2>/dev/null
sec MODPROBE
grep -HsE '^[[:space:]]*(install|blacklist)[[:space:]]+(cdrom|sr_mod|isofs|udf|usb.storage|vsock|vmw_vsock_vmci_transport|vmw_vmci|vmw_balloon|vmxnet3|vmw_pvscsi|br_netfilter|overlay|nf_conntrack|vxlan|ipip|wireguard|ip_tables|ip6_tables|nf_tables|xt_[a-zA-Z_]*)([[:space:]]|$)' /etc/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf /run/modprobe.d/*.conf 2>/dev/null
sec MODULES
awk '{print $1}' /proc/modules 2>/dev/null | grep -xE 'sr_mod|cdrom|isofs|br_netfilter|overlay|nf_conntrack|vxlan|ipip|wireguard|vsock|vmw_vsock_vmci_transport|vmw_balloon|vmxnet3|vmw_pvscsi'
sec VIRT
echo "vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
echo "product=$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
command -v vmtoolsd >/dev/null 2>&1 && echo "vmtoolsd=yes"
command -v cloud-init >/dev/null 2>&1 && echo "cloud_init=yes"
[ -f /etc/cloud/cloud-init.disabled ] && echo "cloud_init_disabled=yes"
echo "datasource_list=$(grep -rhs '^datasource_list' /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.d/ 2>/dev/null | tail -1 | sed 's/^datasource_list:[[:space:]]*//')"
[ -f /var/lib/cloud/instance/datasource ] && echo "datasource=$(head -c 200 /var/lib/cloud/instance/datasource 2>/dev/null | tr '\n' ' ')"
[ -f /run/cloud-init/status.json ] && echo "status=$(tr -d '\n' < /run/cloud-init/status.json 2>/dev/null | head -c 4000)"
echo "srdev=$(ls /dev/sr[0-9]* 2>/dev/null | tr '\n' ' ')"
command -v blkid >/dev/null 2>&1 && echo "cidata=$(blkid -L cidata 2>/dev/null; blkid -L CIDATA 2>/dev/null)"
sec FAPOLICYD
if [ -d /etc/fapolicyd ]; then
  echo "present=yes"
  echo "permissive=$(sed -nE 's/^[[:space:]]*permissive[[:space:]]*=[[:space:]]*([0-9]).*/\1/p' /etc/fapolicyd/fapolicyd.conf 2>/dev/null | tail -1)"
  echo "rules_files=$(ls /etc/fapolicyd/rules.d 2>/dev/null | tr '\n' ' ')"
  echo "compiled_mtime=$(stat -c %Y /etc/fapolicyd/compiled.rules 2>/dev/null)"
  echo "rulesd_mtime=$(stat -c %Y /etc/fapolicyd/rules.d/* 2>/dev/null | sort -n | tail -1)"
  echo "deny_file=$(grep -lE '^[[:space:]]*deny(_audit|_syslog|_log)?[[:space:]]+perm=(execute|any)[[:space:]]+all[[:space:]]*:[[:space:]]*all' /etc/fapolicyd/rules.d/*.rules 2>/dev/null | head -1 | sed 's|.*/||')"
  echo "compiled_k8s=$(grep -cE 'rancher|k3s|kubelet|/opt/cni|containerd' /etc/fapolicyd/compiled.rules 2>/dev/null)"
  # every allow rule with a dir= or path= object: the Go side matches them
  # against the rke2 data-dir and the CSI host directories
  grep -HsE '^[[:space:]]*allow[^#]*(dir|path)=' /etc/fapolicyd/rules.d/*.rules 2>/dev/null | sed 's|^/etc/fapolicyd/rules.d/|rule=|'
fi
sec CSI
# CSI node plugins registered with the kubelet, and the host directories
# storage drivers execute from (fapolicyd must allow them too)
ls /var/lib/kubelet/plugins_registry 2>/dev/null | sed -E 's/-reg\.sock$/|/; s/\.sock$/|/' | sed 's/^/driver=/'
for d in /var/lib/longhorn/engine-binaries /var/lib/longhorn /opt/pwx/bin /var/lib/kubelet/volumeplugins /usr/libexec/kubernetes/kubelet-plugins/volume/exec /var/lib/rook /var/lib/trident /var/openebs; do [ -d "$d" ] && echo "dir=$d"; done
[ -e /run/systemd/units/invocation:iscsid.service ] && echo "iscsid=active"
[ -f /etc/multipath.conf ] && echo "multipath_blacklist=$(grep -c '^[[:space:]]*blacklist' /etc/multipath.conf 2>/dev/null)"
sec AUDITD
grep -hsE '^[[:space:]]*(log_file|max_log_file|max_log_file_action|num_logs|space_left|space_left_action|admin_space_left|admin_space_left_action|disk_full_action|disk_error_action)[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null | tr -d ' \t'
sec ACCOUNTS
echo "sudo_user=${SUDO_USER:-}"
echo "today=$(( $(date +%s) / 86400 ))"
grep -hsE '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)[[:space:]]' /etc/login.defs 2>/dev/null | awk '{print "login_defs_"$1"="$2}'
echo "default_inactive=$(useradd -D 2>/dev/null | sed -n 's/^INACTIVE=//p')"
# root, the ssh user, the etcd user and every account with a login shell.
# The hash is reduced to set/locked/none; the rest are the shadow ages:
# user|name|uid|shell|pw|lastchange|min|max|warn|inactive|expire
awk -F: -v su="${SUDO_USER:-}" 'NR==FNR{if($7 !~ /(nologin|false|sync|halt|shutdown)$/ || $1=="root" || $1==su || $1=="etcd") keep[$1]=$3"|"$7; next} ($1 in keep){h=$2; s=(h==""||h=="*"||h=="!!"||h=="!*"||h=="!"?"none":(h ~ /^!/?"locked":"set")); print "user|"$1"|"keep[$1]"|"s"|"$3"|"$4"|"$5"|"$6"|"$7"|"$8}' /etc/passwd /etc/shadow 2>/dev/null
if command -v faillock >/dev/null 2>&1; then
  echo "faillock_deny=$(grep -hsE '^[[:space:]]*deny[[:space:]]*=' /etc/security/faillock.conf 2>/dev/null | tail -1 | sed 's/.*=[[:space:]]*//')"
  for u in root ${SUDO_USER:-}; do
    echo "faillock|$u|$(faillock --user "$u" 2>/dev/null | grep -c ' V$')"
  done
fi
sec PROXY
for f in /etc/default/rke2-server /etc/default/rke2-agent /etc/sysconfig/rke2-server /etc/sysconfig/rke2-agent /etc/systemd/system/rke2-server.service.env /etc/systemd/system/rke2-agent.service.env /etc/systemd/system/k3s.service.env /etc/systemd/system/k3s-agent.service.env /etc/systemd/system/rke2-server.service.d/*.conf /etc/systemd/system/rke2-agent.service.d/*.conf /etc/systemd/system/k3s.service.d/*.conf /etc/systemd/system/k3s-agent.service.d/*.conf /etc/systemd/system/containerd.service.d/*.conf /etc/environment; do
  [ -f "$f" ] || continue
  grep -hsiE '^[[:space:]]*(export[[:space:]]+)?(Environment=)?"?(HTTP_PROXY|HTTPS_PROXY|NO_PROXY|CONTAINERD_HTTP_PROXY|CONTAINERD_HTTPS_PROXY|CONTAINERD_NO_PROXY)=' "$f" 2>/dev/null | sed -E 's#://[^/@[:space:]"]+@#://<masked>@#g' | sed "s#^#$f|#"
done
sec IPTABLES
echo "iptables=$(iptables --version 2>/dev/null)"
sec SEPKG
command -v rpm >/dev/null 2>&1 && rpm -q rke2-selinux k3s-selinux container-selinux 2>/dev/null
sec NMCONF
grep -hsE '^[[:space:]]*unmanaged-devices' /etc/NetworkManager/conf.d/*.conf /etc/NetworkManager/NetworkManager.conf /usr/lib/NetworkManager/conf.d/*.conf 2>/dev/null
sec REGPROBE
# registries.yaml: the mirror endpoints and configs keys are probed with
# curl (GET /v2/, then the bearer token endpoint the registry names) using
# the configured credentials and TLS files, so "keys not working" shows up
# here instead of as ImagePullBackOff later. One line per endpoint:
# host|url|http|curlexit|tokenhttp|auth|ca|insecure
# and F|key|kind|path|ok/missing for every TLS file the configs section names.
# fields are separated by the unit separator (0x1f): `read` collapses runs
# of tab/space so empty fields would shift, and passwords may contain '|'
T=$(printf '\037')
regyaml() {
  awk '
    function cflush() { if (top=="configs" && reg!="") printf "C\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n", reg, u, p, ca, ce, ke, ins; u=p=ca=ce=ke=ins="" }
    function mflush() { if (top=="mirrors" && reg!="" && reg!="*" && neps==0) print "M\037" reg "\037" }
    function val(s,  i) { i=index(s,":"); s=substr(s,i+1); sub(/^[[:space:]]+/,"",s); sub(/[[:space:]]+#.*$/,"",s); sub(/[[:space:]]+$/,"",s); gsub(/^["'\'']|["'\'']$/,"",s); return s }
    /^[[:space:]]*(#|$)/ {next}
    /^[^[:space:]]/ { cflush(); mflush(); top=$1; sub(/:.*/,"",top); reg=""; neps=0; next }
    top=="mirrors" && /^  [^[:space:]]/ { mflush(); reg=$0; sub(/^  /,"",reg); sub(/:[[:space:]]*$/,"",reg); gsub(/["'\'']/,"",reg); neps=0; next }
    top=="mirrors" && /^[[:space:]]+endpoint:[[:space:]]*\[/ { s=$0; sub(/^[^[]*\[/,"",s); sub(/\].*$/,"",s); n=split(s,a,","); for(i=1;i<=n;i++){e=a[i]; gsub(/["'\'' ]/,"",e); if(e!=""){print "M\037" reg "\037" e; neps++}} next }
    top=="mirrors" && reg!="" && /^[[:space:]]*-[[:space:]]*/ { e=$0; sub(/^[[:space:]]*-[[:space:]]*/,"",e); gsub(/["'\'' ]/,"",e); if (e!="") {print "M\037" reg "\037" e; neps++} next }
    top=="configs" && /^  [^[:space:]]/ { cflush(); reg=$0; sub(/^  /,"",reg); sub(/:[[:space:]]*$/,"",reg); gsub(/["'\'']/,"",reg); next }
    top=="configs" && reg!="" { l=$0; sub(/^[[:space:]]+/,"",l); k=l; sub(/:.*/,"",k)
      if (k=="username") u=val(l); else if (k=="password") p=val(l); else if (k=="ca_file") ca=val(l); else if (k=="cert_file") ce=val(l); else if (k=="key_file") ke=val(l); else if (k=="insecure_skip_verify") ins=val(l); next }
    END { cflush(); mflush() }' "$1"
}
probe() { # url host user pass ca cert key insecure
  url=$1; host=$2; user=$3; pass=$4; ca=$5; cert=$6; key=$7; ins=$8
  opts() {
    [ -n "$user" ] && printf 'user = "%s:%s"\n' "$user" "$pass"
    [ -n "$ca" ] && printf 'cacert = "%s"\n' "$ca"
    [ -n "$cert" ] && printf 'cert = "%s"\n' "$cert"
    [ -n "$key" ] && printf 'key = "%s"\n' "$key"
    [ "$ins" = true ] && echo insecure
    echo silent
  }
  out=$(opts | curl -m 6 -o /dev/null -D - -w '\n%{http_code}' -K - "$url/v2/" 2>/dev/null); rc=$?
  code=$(printf '%s' "$out" | tail -1); code2=
  if [ "$code" = 401 ]; then
    # token auth (Docker Hub, Harbor, GHCR, Quay): a 401 on /v2/ only says
    # "get a token"; the token endpoint is what rejects bad credentials. A
    # pull scope is required: Harbor answers 401 to an unscoped anonymous
    # request even when its projects are public
    realm=$(printf '%s' "$out" | grep -i '^www-authenticate: *bearer' | sed -nE 's/.*realm="([^"]+)".*/\1/p' | head -1)
    service=$(printf '%s' "$out" | grep -i '^www-authenticate: *bearer' | sed -nE 's/.*service="([^"]+)".*/\1/p' | head -1)
    [ -n "$realm" ] && code2=$(opts | curl -m 6 -o /dev/null -w '%{http_code}' -K - "$realm?service=$service&scope=repository:library/busybox:pull" 2>/dev/null)
  fi
  echo "$host|$url|${code:-000}|$rc|$code2|${user:+yes}|${ca:+yes}|$ins"
}
if ! command -v curl >/dev/null 2>&1; then echo "curl=missing"; else
for f in /etc/rancher/rke2/registries.yaml /etc/rancher/k3s/registries.yaml; do
  [ -f "$f" ] || continue
  R=$(regyaml "$f")
  printf '%s\n' "$R" | grep '^C' | while IFS="$T" read -r _ k _ _ ca ce ke _; do
    for pair in "ca_file|$ca" "cert_file|$ce" "key_file|$ke"; do
      p=${pair#*|}; [ -n "$p" ] || continue
      if [ -f "$p" ]; then echo "F|$k|${pair%%|*}|$p|ok"; else echo "F|$k|${pair%%|*}|$p|missing"; fi
    done
  done
  # every endpoint (or the registry itself when a mirror lists none) plus
  # every configs key that is not an endpoint; probes run in parallel and
  # the subshell waits for them so their lines stay inside this section
  EPS=$(printf '%s\n' "$R" | grep '^M' | while IFS="$T" read -r _ reg e; do
      # (pattern) form: bash 5.1 cannot parse an unparenthesised case pattern inside $( )
      [ -z "$e" ] && { case "$reg" in (docker.io) e=https://registry-1.docker.io;; (*) e=https://$reg;; esac; }
      echo "$e"
    done | sed 's|/*$||')
  EPHOSTS=" $(printf '%s\n' "$EPS" | sed -E 's#^[a-z]+://##; s#/.*##' | tr '\n' ' ')"
  { printf '%s\n' "$EPS"
    printf '%s\n' "$R" | grep '^C' | while IFS="$T" read -r _ k _; do
      case "$k" in \**) continue;; esac
      case "$EPHOSTS" in *" $k "*) ;; *) echo "https://$k";; esac
    done
  } | grep . | sort -u | head -8 | {
    while read -r url; do
      host=$(printf '%s' "$url" | sed -E 's#^[a-z]+://##; s#/.*##')
      c=$(printf '%s\n' "$R" | grep "^C${T}${host}${T}" | head -1)
      [ -z "$c" ] && c=$(printf '%s\n' "$R" | grep "^C${T}${host%%:*}${T}" | head -1)
      u=; p=; ca=; ce=; ke=; ins=
      [ -n "$c" ] && IFS="$T" read -r _ _ u p ca ce ke ins <<EOF
$c
EOF
      probe "$url" "$host" "$u" "$p" "$ca" "$ce" "$ke" "${ins:-false}" &
    done
    wait
  }
done
fi
fi
if [ "__HEAVY__" = 1 ]; then
sec FAPDENY
# fapolicyd denials land in the audit log as FANOTIFY records (resp=2); the
# SYSCALL/PATH records of the same event name the program and the file.
# count|last_epoch|exe|path, most frequent first.
if [ -e /run/systemd/units/invocation:fapolicyd.service ] && command -v ausearch >/dev/null 2>&1; then
  timeout 20 ausearch -m FANOTIFY -ts today --raw 2>/dev/null | awk '
    { if (match($0,/audit\([0-9.]+:[0-9]+\)/)) { id=substr($0,RSTART+6,RLENGTH-7); split(id,tt,":"); ts=tt[1]; sn=tt[2] } else next }
    /^type=FANOTIFY/ { if (match($0,/resp=[0-9]+/) && substr($0,RSTART+5,RLENGTH-5)=="2") { deny[sn]=1; when[sn]=ts } }
    /^type=SYSCALL/ { if (match($0,/exe="[^"]*"/)) exe[sn]=substr($0,RSTART+5,RLENGTH-6) }
    /^type=PATH/ { if (!(sn in path) && match($0,/name="[^"]*"/)) path[sn]=substr($0,RSTART+6,RLENGTH-7) }
    END { for (s in deny) { k=exe[s] "|" path[s]; n[k]++; if (when[s]>last[k]) last[k]=when[s] } for (k in n) print n[k] "|" int(last[k]) "|" k }' | sort -t'|' -k1,1nr | head -20
fi
fi
