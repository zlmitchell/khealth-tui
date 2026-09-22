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
# everything inside __CONFIG__ runs with the config tier (first contact, R,
# the RKE2/Security tabs) and is carried forward by Info.MergeConfig;
# REGPULL (crictl pull dry run) rides on the images tier and FAPDENY
# (ausearch) on the journal tier (docs/ARCHITECTURE.md §7). The registry
# probe and the pull dry run are the only network activity: parallel curls
# capped at 6 s each, parallel pulls capped at 20 s each.
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
# this is cheap enough for every refresh. The entry is a symlink to the
# invocation ID, dangling by design, so test with -L (-e follows it)
WANTS=" $(ls /etc/systemd/system/*.wants/ 2>/dev/null | tr '\n' ' ') "
for u in NetworkManager.service nm-cloud-setup.service nm-cloud-setup.timer vmtoolsd.service open-vm-tools.service cloud-init.service cloud-final.service multipathd.service fapolicyd.service auditd.service firewalld.service; do
  a=inactive; { [ -L "/run/systemd/units/invocation:$u" ] || [ -e "/run/systemd/units/invocation:$u" ]; } && a=active
  e=disabled; case "$WANTS" in *" $u "*) e=enabled;; esac
  echo "$u|$a|$e"
done
# registries.yaml parser, field separator and the airgap marker are shared
# by the curl probe (config tier) and the crictl pull dry run (heavy tier)
T=$(printf '\037')
regyaml() {
  asyaml "$1" | awk '
    function cflush() { if (top=="configs" && reg!="") printf "C\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n", reg, u, p, ca, ce, ke, ins; u=p=ca=ce=ke=ins="" }
    function mflush() { if (top=="mirrors" && reg!="" && reg!="*" && neps==0) print "M\037" reg "\037" }
    function val(s,  i) { i=index(s,":"); s=substr(s,i+1); sub(/^[[:space:]]+/,"",s); sub(/[[:space:]]+#.*$/,"",s); sub(/[[:space:]]+$/,"",s); gsub(/^["'\'']|["'\'']$/,"",s); return s }
    /^[[:space:]]*(#|$)/ {next}
    /^[^[:space:]]/ { cflush(); mflush(); top=$1; sub(/:.*/,"",top); reg=""; neps=0; next }
    top=="mirrors" && /^  [^[:space:]]/ { mflush(); reg=$0; sub(/^  /,"",reg); sub(/:[[:space:]]*(\{\})?[[:space:]]*$/,"",reg); gsub(/["'\'']/,"",reg); neps=0; next }
    top=="mirrors" && /^[[:space:]]+endpoint:[[:space:]]*\[/ { s=$0; sub(/^[^[]*\[/,"",s); sub(/\].*$/,"",s); n=split(s,a,","); for(i=1;i<=n;i++){e=a[i]; gsub(/["'\'' ]/,"",e); if(e!=""){print "M\037" reg "\037" e; neps++}} next }
    top=="mirrors" && reg!="" && /^[[:space:]]*-[[:space:]]*/ { e=$0; sub(/^[[:space:]]*-[[:space:]]*/,"",e); gsub(/["'\'' ]/,"",e); if (e!="") {print "M\037" reg "\037" e; neps++} next }
    top=="configs" && /^  [^[:space:]]/ { cflush(); reg=$0; sub(/^  /,"",reg); sub(/:[[:space:]]*$/,"",reg); gsub(/["'\'']/,"",reg); next }
    top=="configs" && reg!="" { l=$0; sub(/^[[:space:]]+/,"",l); k=l; sub(/:.*/,"",k)
      if (k=="username") u=val(l); else if (k=="password") p=val(l); else if (k=="ca_file") ca=val(l); else if (k=="cert_file") ce=val(l); else if (k=="key_file") ke=val(l); else if (k=="insecure_skip_verify") ins=val(l); next }
    END { cflush(); mflush() }'
}
AIRGAP=; for d in "$RKE2_DD"/agent/images "$K3S_DD"/agent/images; do ls "$d"/*.tar* >/dev/null 2>&1 && AIRGAP=yes; done
if [ "__CONFIG__" = 1 ]; then
sec FSTABSWAP
grep -E '^[^#]*[[:space:]]swap[[:space:]]' /etc/fstab 2>/dev/null
sec KUBELETSWAP
# rke2/k3s write failSwapOn: false into their kubelet defaults; kubeadm and
# a kubelet-arg override keep the upstream default (true)
{ cat "$RKE2_DD"/agent/etc/kubelet.conf.d/*.conf "$K3S_DD"/agent/etc/kubelet.conf.d/*.conf /var/lib/kubelet/config.yaml /etc/rancher/rke2/kubelet-config.yaml; [ -f "$KUBELET_CFG" ] && asyaml "$KUBELET_CFG"; } 2>/dev/null | grep -E '^[[:space:]]*(failSwapOn|swapBehavior):' | tr -d ' "'
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
# vSphere CSI needs disk.EnableUUID=TRUE on the VM: the disks then carry a
# WWN and show up under /dev/disk/by-id/wwn-*
echo "wwn=$(ls /dev/disk/by-id/ 2>/dev/null | grep -c '^wwn-')"
# AWS: the cloud controller and the EBS CSI read instance identity from IMDS
case "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)" in *Amazon*) command -v curl >/dev/null 2>&1 && echo "imds=$(curl -s -m 2 -o /dev/null -w '%{http_code}' -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 30' 2>/dev/null)";; esac
sec CLOUDINIT
# (the cloud-init units' state/Result come from the UNITS section of base.sh)
if command -v cloud-init >/dev/null 2>&1; then
  [ -f /run/cloud-init/result.json ] && echo "result=$(tr -d '\n' < /run/cloud-init/result.json 2>/dev/null | head -c 1000)"
  [ -f /var/log/cloud-init.log ] && grep -hE '\[(ERROR|CRITICAL)\]|Traceback' /var/log/cloud-init.log 2>/dev/null | tail -5 | cut -c1-300 | sed 's/^/log=/'
fi
sec VCENTER
# vCenter hosts from the vSphere CPI config (kube-system vsphere-cloud-config):
# the CPI and CSI on this node need to reach the SDK endpoint
if command -v curl >/dev/null 2>&1; then
  for vc in __VCENTERS__; do
    ( code=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://$vc/sdk" 2>/dev/null); rc=$?; echo "$vc|$code|$rc" ) &
  done
  wait
fi
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
{ [ -L /run/systemd/units/invocation:iscsid.service ] || [ -e /run/systemd/units/invocation:iscsid.service ]; } && echo "iscsid=active"
[ -f /etc/multipath.conf ] && echo "multipath_blacklist=$(grep -c '^[[:space:]]*blacklist' /etc/multipath.conf 2>/dev/null)"
# Trident iSCSI wants multipathd with find_multipaths no; NAS backends need mount.nfs
[ -f /etc/multipath.conf ] && echo "find_multipaths=$(grep -hsE '^[[:space:]]*find_multipaths' /etc/multipath.conf 2>/dev/null | tail -1 | awk '{print $2}' | tr -d '"')"
command -v mount.nfs >/dev/null 2>&1 && echo "mount_nfs=yes"
# block devices Longhorn still presents on this node and the iSCSI sessions
# behind them (the cluster's idea of where a volume is attached may differ)
for d in /dev/longhorn/*; do [ -b "$d" ] && echo "lhdev=${d##*/}"; done
for s in /sys/class/iscsi_session/session*; do [ -d "$s" ] && echo "iscsi=$(cat "$s/targetname" 2>/dev/null)|$(cat "$s/state" 2>/dev/null)"; done
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
# the provisioning user cloud-init created (Rancher's vSphere/AWS templates):
# named in /etc/sudoers.d/90-cloud-init-users, or the image's default_user
grep -hsE '^[^#]+ALL' /etc/sudoers.d/90-cloud-init-users 2>/dev/null | awk '{print "ci_user="$1}'
echo "ci_default=$(grep -hsA3 '^[[:space:]]*default_user:' /etc/cloud/cloud.cfg 2>/dev/null | sed -nE 's/^[[:space:]]*name:[[:space:]]*//p' | head -1)"
# sudo|user|nopasswd=yes/no|keys=N for the ssh user and the cloud-init users
for u in $( { echo "${SUDO_USER:-}"; grep -hsE '^[^#]+ALL' /etc/sudoers.d/90-cloud-init-users 2>/dev/null | awk '{print $1}'; } | grep . | sort -u); do
  np=no
  for g in "$u" $(id -Gn "$u" 2>/dev/null | sed 's/\([^ ][^ ]*\)/%\1/g'); do
    grep -hsE "^[[:space:]]*$g[[:space:]].*NOPASSWD" /etc/sudoers /etc/sudoers.d/* >/dev/null 2>&1 && np=yes
  done
  h=$(getent passwd "$u" 2>/dev/null | cut -d: -f6)
  keys=$(grep -cE '^(ssh|ecdsa)-' "$h/.ssh/authorized_keys" 2>/dev/null)
  echo "sudo|$u|nopasswd=$np|keys=${keys:-0}"
done
sec PROXY
for f in /etc/default/rke2-server /etc/default/rke2-agent /etc/sysconfig/rke2-server /etc/sysconfig/rke2-agent /etc/systemd/system/rke2-server.service.env /etc/systemd/system/rke2-agent.service.env /etc/systemd/system/k3s.service.env /etc/systemd/system/k3s-agent.service.env /etc/systemd/system/rke2-server.service.d/*.conf /etc/systemd/system/rke2-agent.service.d/*.conf /etc/systemd/system/k3s.service.d/*.conf /etc/systemd/system/k3s-agent.service.d/*.conf /etc/systemd/system/containerd.service.d/*.conf /etc/environment; do
  [ -f "$f" ] || continue
  grep -hsiE '^[[:space:]]*(export[[:space:]]+)?(Environment=)?"?(HTTP_PROXY|HTTPS_PROXY|NO_PROXY|CONTAINERD_HTTP_PROXY|CONTAINERD_HTTPS_PROXY|CONTAINERD_NO_PROXY)=' "$f" 2>/dev/null | sed -E 's#://[^/@[:space:]"]+@#://<masked>@#g' | sed "s#^#$f|#"
done
sec IPTABLES
echo "iptables=$(iptables --version 2>/dev/null)"
sec SEPKG
# rke2-selinux / k3s-selinux label the runtime; rancher-selinux labels
# rancher-system-agent on a Rancher-provisioned node
command -v rpm >/dev/null 2>&1 && rpm -q rke2-selinux k3s-selinux container-selinux rancher-selinux 2>/dev/null
sec NMCONF
grep -hsE '^[[:space:]]*unmanaged-devices' /etc/NetworkManager/conf.d/*.conf /etc/NetworkManager/NetworkManager.conf /usr/lib/NetworkManager/conf.d/*.conf 2>/dev/null
sec REGPROBE
# registries.yaml: the mirror endpoints and configs keys are probed with
# curl (GET /v2/, then the bearer token endpoint the registry names) using
# the configured credentials and TLS files, so "keys not working" shows up
# here instead of as ImagePullBackOff later. One line per endpoint:
# host|url|http|curlexit|tokenhttp|auth|ca|insecure|implicit
# and F|key|kind|path|ok/missing for every TLS file the configs section names.
# implicit=yes marks a registry registries.yaml only names (a mirror without
# endpoints, a configs key that is no endpoint): containerd goes to the
# registry itself. On an airgapped node - image tarballs in agent/images -
# the endpoint-less mirrors (upstream fallbacks such as docker.io) are not
# probed at all: no egress attempt, no "unreachable" finding; they are
# listed as skipped|host|url|airgap. configs-only keys are still probed.
# fields are separated by the unit separator (0x1f): `read` collapses runs
# of tab/space so empty fields would shift, and passwords may contain '|'
probe() { # url host user pass ca cert key insecure implicit
  url=$1; host=$2; user=$3; pass=$4; ca=$5; cert=$6; key=$7; ins=$8; impl=$9
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
  echo "$host|$url|${code:-000}|$rc|$code2|${user:+yes}|${ca:+yes}|$ins|$impl"
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
  # explicit endpoints first; a mirror that names a registry without endpoints
  # is tagged "~" (upstream fallback: skipped on airgap nodes), a configs-only
  # key "+" (referenced directly by image names: always probed, the
  # credential check is the point)
  EPS=$(printf '%s\n' "$R" | grep '^M' | while IFS="$T" read -r _ reg e; do
      # (pattern) form: bash 5.1 cannot parse an unparenthesised case pattern inside $( )
      [ -z "$e" ] && { case "$reg" in (docker.io) e=~https://registry-1.docker.io;; (*) e=~https://$reg;; esac; }
      echo "$e"
    done | sed 's|/*$||')
  EPHOSTS=" $(printf '%s\n' "$EPS" | sed -E 's#^~?[a-z]+://##; s#/.*##' | tr '\n' ' ')"
  { printf '%s\n' "$EPS"
    printf '%s\n' "$R" | grep '^C' | while IFS="$T" read -r _ k _; do
      case "$k" in \**) continue;; esac
      case "$EPHOSTS" in *" $k "*) ;; *) echo "+https://$k";; esac
    done
  } | grep . | sort -u | head -8 | {
    while read -r url; do
      impl=; up=; case "$url" in ('~'*) impl=yes; up=yes; url=${url#'~'};; ('+'*) impl=yes; url=${url#'+'};; esac  # '~' quoted: bare ~ in a pattern is tilde-expanded
      host=$(printf '%s' "$url" | sed -E 's#^[a-z]+://##; s#/.*##')
      if [ -n "$up" ] && [ -n "$AIRGAP" ]; then echo "skipped|$host|$url|airgap"; continue; fi
      c=$(printf '%s\n' "$R" | grep "^C${T}${host}${T}" | head -1)
      [ -z "$c" ] && c=$(printf '%s\n' "$R" | grep "^C${T}${host%%:*}${T}" | head -1)
      u=; p=; ca=; ce=; ke=; ins=
      [ -n "$c" ] && IFS="$T" read -r _ _ u p ca ce ke ins <<EOF
$c
EOF
      probe "$url" "$host" "$u" "$p" "$ca" "$ce" "$ke" "${ins:-false}" "$impl" &
    done
    wait
  }
done
fi
fi
if [ "__IMAGES__" = 1 ]; then
sec REGPULL
# crictl pull dry run: for every registry registries.yaml names (a mirrors:
# key, or a configs: key images reference directly), one image the node
# already holds from that registry (the pause image when there is one) is
# pulled again by digest through containerd. All of its content is
# local, so containerd only resolves the manifest - one HEAD per endpoint
# until one answers - nothing is downloaded and `crictl images` does not
# change. The curl probe above reads registries.yaml itself; this exercises
# what containerd actually runs, the hosts.toml rke2/k3s rendered from it
# (endpoint rewrite, auth header, CA bundle), so a registries.yaml the
# supervisor refused to render, a mirror that answers /v2/ but not the
# repository path, or a rewrite rule that misfires surface here. Pulls run
# in parallel, 20 s cap each. One line per registry:
# registry|image|endpoint hosts|ok/fail/skip|detail
# detail is containerd's error; the host it names is the one that failed:
# a mirror endpoint, or the upstream registry after every mirror answered
# 404 (containerd falls through to the registry itself). Same airgap rule
# as the curl probe: an endpoint-less mirror is not pulled when the node
# has image tarballs; a configs: key is (the credential/TLS check is the
# point).
CRIIMG=; R=
for f in /etc/rancher/rke2/registries.yaml /etc/rancher/k3s/registries.yaml; do [ -f "$f" ] && R=$(regyaml "$f"); done
if [ -z "$CRICTL" ]; then echo "crictl=missing"; elif [ -n "$R" ]; then
  CRIIMG=$(runcri images -o json 2>/dev/null)
  IMGS=$(printf '%s\n' "$CRIIMG" | grep -oE '"[^"@]+@sha256:[0-9a-f]{64}"' | tr -d '"')
  cripull() { if [ -n "$CRI" ]; then timeout 20 $CRICTL -r "$CRI" pull "$1"; else timeout 20 $CRICTL pull "$1"; fi; }
  # mirrors: keys, plus configs: keys that are neither a mirror nor one of
  # its endpoint hosts (those are exercised by the mirror's pull)
  printf '%s\n' "$R" | awk -F"$T" '
    $1=="M" && $3!="" { h=$3; sub(/^[a-z]+:\/\//,"",h); sub(/\/.*/,"",h); ep[h]=1 }
    $1=="M" { m[$2]=1 } $1=="C" { c[$2]=1 }
    END { for (r in m) if (r !~ /^\*/) print r; for (r in c) if (r !~ /^\*/ && !(r in m) && !(r in ep)) print r }' | sort -u | head -8 | {
    while read -r reg; do
      eps=$(printf '%s\n' "$R" | awk -F"$T" -v r="$reg" '$1=="M" && $2==r && $3!="" {print $3}' | sed -E 's#^[a-z]+://##; s#/.*##' | tr '\n' ',' | sed 's/,$//')
      # a mirror without endpoints sends containerd to the upstream registry
      upstream=$(printf '%s\n' "$R" | awk -F"$T" -v r="$reg" '$1=="M" && $2==r && $3=="" {print "yes"; exit}')
      if [ -n "$upstream" ] && [ -n "$AIRGAP" ]; then echo "$reg||$eps|skip|airgap"; continue; fi
      # images are stored under their registry host (docker.io/rancher/...)
      list=$(printf '%s\n' "$IMGS" | awk -v r="$reg/" 'index($0,r)==1')
      img=$(printf '%s\n' "$list" | grep pause | head -1); [ -z "$img" ] && img=$(printf '%s\n' "$list" | head -1)
      if [ -z "$img" ]; then echo "$reg||$eps|skip|no image from this registry on the node"; continue; fi
      { out=$(cripull "$img" 2>&1); rc=$?
        if [ $rc -eq 0 ]; then echo "$reg|$img|$eps|ok|"
        elif [ $rc -eq 124 ]; then echo "$reg|$img|$eps|fail|timed out after 20 s"
        else
          # crictl logs through logrus: FATA[0001] msg on a tty, time="..."
          # level=fatal msg="..." (inner quotes escaped) when piped, as here
          l=$(printf '%s\n' "$out" | grep -E '^FATA|level=fatal' | tail -1); [ -z "$l" ] && l=$(printf '%s\n' "$out" | grep . | tail -1)
          echo "$reg|$img|$eps|fail|$(printf '%s' "$l" | sed -E 's/^time="[^"]*" level=fatal msg="//; s/"$//; s/\\"/"/g; s/^FATA\[[^]]*\] //; s/^pulling image: //; s/.*rpc error: code = [A-Za-z]+ desc = //; s/failed to pull and unpack image "[^"]*": //; s/failed to resolve reference "[^"]*": //; s/\?ns=[^":[:space:]]*//' | cut -c1-240)"
        fi
      } &
    done
    wait
  }
fi
fi
if [ "__JOURNAL__" = 1 ]; then
sec FAPDENY
# fapolicyd denials land in the audit log as FANOTIFY records (resp=2); the
# SYSCALL/PATH records of the same event name the program and the file.
# count|last_epoch|exe|path, most frequent first.
if { [ -L /run/systemd/units/invocation:fapolicyd.service ] || [ -e /run/systemd/units/invocation:fapolicyd.service ]; } && command -v ausearch >/dev/null 2>&1; then
  # --input-logs and </dev/null: ausearch reads events from stdin when stdin
  # is a pipe, and this script arrives on stdin (sh -s) - it would swallow
  # the rest of the probe
  timeout 20 ausearch -m FANOTIFY -ts today --raw --input-logs </dev/null 2>/dev/null | awk '
    { if (match($0,/audit\([0-9.]+:[0-9]+\)/)) { id=substr($0,RSTART+6,RLENGTH-7); split(id,tt,":"); ts=tt[1]; sn=tt[2] } else next }
    /^type=FANOTIFY/ { if (match($0,/resp=[0-9]+/) && substr($0,RSTART+5,RLENGTH-5)=="2") { deny[sn]=1; when[sn]=ts } }
    /^type=SYSCALL/ { if (match($0,/exe="[^"]*"/)) exe[sn]=substr($0,RSTART+5,RLENGTH-6) }
    /^type=PATH/ { if (!(sn in path) && match($0,/name="[^"]*"/)) path[sn]=substr($0,RSTART+6,RLENGTH-7) }
    END { for (s in deny) { k=exe[s] "|" path[s]; n[k]++; if (when[s]>last[k]) last[k]=when[s] } for (k in n) print n[k] "|" int(last[k]) "|" k }' | sort -t'|' -k1,1nr | head -20
fi
fi
