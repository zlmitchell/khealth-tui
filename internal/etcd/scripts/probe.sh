# etcd probe: locates the local member (rke2 / k3s / kubeadm layouts), runs
# etcdctl member/endpoint/alarm queries, lists snapshots and measures the
# data dir. Placeholders __EXTRA_DIRS__, __EP__, __CA__, __CERT__, __KEY__
# are substituted by etcd.Script. Parsed by etcd.Parse.
#
# Sent to nodes over SSH by khealth as `sudo sh -s`; POSIX sh only (dash on
# Ubuntu, busybox on Flatcar). Embedded into the Go binary with //go:embed -
# edit here, not in the .go file. Sections are delimited by `sec NAME`
# (===NAME lines) and parsed by the Go side; keep names in sync with the
# parser. Never print secrets: pass file dumps through `mask`.
sec() { printf '\n===%s\n' "$1"; }
export LC_ALL=C
EXTRA_DIRS='__EXTRA_DIRS__'
EP_OVERRIDE='__EP__'; CA_OVERRIDE='__CA__'; CERT_OVERRIDE='__CERT__'; KEY_OVERRIDE='__KEY__'
DIST=unknown; CA=; CERT=; KEY=; EP=https://127.0.0.1:2379; CRICTL=; CRI_EP=; DATADIR=; SNAPDIR=; ETCDCTL=; SKIPPEERS=
H=$(hostname)
# rke2/k3s data-dir may be customized in config.yaml
RKE2_DD=/var/lib/rancher/rke2; K3S_DD=/var/lib/rancher/k3s
# (asyaml.sh is prepended: Rancher-delivered config.yaml.d files are JSON)
cfgkey() { # last value of a top-level key across the distro's config files
  for f in /etc/rancher/$1/config.yaml /etc/rancher/$1/config.yaml.d/*.yaml; do
    [ -f "$f" ] && asyaml "$f"
  done | sed -nE "s/^[[:space:]]*$2:[[:space:]]*\"?([^\"#]+)\"?.*/\1/p" | tail -1 | sed 's/[[:space:]]*$//'
}
v=$(cfgkey rke2 data-dir); [ -n "$v" ] && RKE2_DD=$v
v=$(cfgkey k3s data-dir); [ -n "$v" ] && K3S_DD=$v
if [ -d "$RKE2_DD/server/tls/etcd" ]; then
  DIST=rke2
  CA=$RKE2_DD/server/tls/etcd/server-ca.crt
  CERT=$RKE2_DD/server/tls/etcd/server-client.crt
  KEY=$RKE2_DD/server/tls/etcd/server-client.key
  CRICTL=$RKE2_DD/bin/crictl
  CRI_EP=unix:///run/k3s/containerd/containerd.sock
  DATADIR=$RKE2_DD/server/db/etcd
  SNAPDIR=$RKE2_DD/server/db/snapshots
  v=$(cfgkey rke2 etcd-snapshot-dir); [ -n "$v" ] && SNAPDIR=$v
elif [ -d "$K3S_DD/server/tls/etcd" ]; then
  DIST=k3s
  CA=$K3S_DD/server/tls/etcd/server-ca.crt
  CERT=$K3S_DD/server/tls/etcd/server-client.crt
  KEY=$K3S_DD/server/tls/etcd/server-client.key
  DATADIR=$K3S_DD/server/db/etcd
  SNAPDIR=$K3S_DD/server/db/snapshots
  v=$(cfgkey k3s etcd-snapshot-dir); [ -n "$v" ] && SNAPDIR=$v
elif [ -d /etc/kubernetes/pki/etcd ]; then
  DIST=kubeadm
  CA=/etc/kubernetes/pki/etcd/ca.crt
  if [ -f /etc/kubernetes/pki/etcd/healthcheck-client.crt ]; then
    CERT=/etc/kubernetes/pki/etcd/healthcheck-client.crt; KEY=/etc/kubernetes/pki/etcd/healthcheck-client.key
  elif [ -f /etc/kubernetes/pki/apiserver-etcd-client.crt ]; then
    CERT=/etc/kubernetes/pki/apiserver-etcd-client.crt; KEY=/etc/kubernetes/pki/apiserver-etcd-client.key
  fi
  CRICTL=$(command -v crictl 2>/dev/null)
  for s in /run/containerd/containerd.sock /var/run/crio/crio.sock /run/cri-dockerd.sock; do [ -S "$s" ] && { CRI_EP="unix://$s"; break; }; done
  DATADIR=/var/lib/etcd
  DD=$(grep -o -- '--data-dir=[^ "]*' /etc/kubernetes/manifests/etcd.yaml 2>/dev/null | head -1 | cut -d= -f2)
  [ -n "$DD" ] && DATADIR=$DD
elif [ -f /etc/ssl/etcd/ssl/ca.pem ]; then
  DIST=kubespray
  CA=/etc/ssl/etcd/ssl/ca.pem
  for n in "admin-$H" "node-$H" "member-$H"; do
    if [ -f "/etc/ssl/etcd/ssl/$n.pem" ]; then CERT="/etc/ssl/etcd/ssl/$n.pem"; KEY="/etc/ssl/etcd/ssl/$n-key.pem"; break; fi
  done
  DATADIR=/var/lib/etcd
fi
[ -n "$EP_OVERRIDE" ] && EP=$EP_OVERRIDE
[ -n "$CA_OVERRIDE" ] && CA=$CA_OVERRIDE
[ -n "$CERT_OVERRIDE" ] && CERT=$CERT_OVERRIDE
[ -n "$KEY_OVERRIDE" ] && KEY=$KEY_OVERRIDE
command -v etcdctl >/dev/null 2>&1 && ETCDCTL=$(command -v etcdctl)

sec DIST; echo "$DIST"
sec HOST; echo "$H"
sec PATHS
echo "ca=$CA"; echo "cert=$CERT"; echo "key=$KEY"; echo "endpoint=$EP"; echo "datadir=$DATADIR"
for f in "$CA" "$CERT" "$KEY"; do [ -n "$f" ] && [ ! -r "$f" ] && echo "missing=$f"; done
[ -n "$CRICTL" ] && [ ! -x "$CRICTL" ] && echo "missing=$CRICTL"
# Config sources, dumps, snapshot listings and backup hints change rarely:
# full cycles only (__FULL__=1); khealth carries them forward (Probe.Merge).
if [ "__FULL__" = 1 ]; then
sec SOURCE
[ -f "$RKE2_DD/agent/pod-manifests/etcd.yaml" ] && echo "static-pod $RKE2_DD/agent/pod-manifests/etcd.yaml"
[ -f /etc/kubernetes/manifests/etcd.yaml ] && echo "static-pod /etc/kubernetes/manifests/etcd.yaml"
if [ "$(systemctl show -p LoadState --value etcd 2>/dev/null)" = loaded ]; then echo "systemd etcd.service ($(systemctl is-active etcd 2>/dev/null))"; fi
[ "$DIST" = k3s ] && echo "embedded k3s etcd (in-process)"
for m in /etc/kubernetes/manifests/kube-apiserver.yaml "$RKE2_DD/agent/pod-manifests/kube-apiserver.yaml"; do
  [ -f "$m" ] && grep -o -- '--etcd-servers=[^ "]*' "$m" 2>/dev/null | head -1 | sed "s|^|apiserver $m: |"
done
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then
  for f in /etc/rancher/$DIST/config.yaml /etc/rancher/$DIST/config.yaml.d/*.yaml; do [ -f "$f" ] && echo "$DIST-config $f"; done
  [ -f "$DATADIR/config" ] && echo "etcd-config $DATADIR/config (generated by $DIST)"
fi
for f in /etc/etcd/etcd.conf /etc/etcd/etcd.conf.yml /etc/etcd/etcd.conf.yaml /etc/etcd.env /etc/default/etcd /etc/sysconfig/etcd; do [ -f "$f" ] && echo "etcd-config $f"; done
sec RKE2CONFIG
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then
  for f in /etc/rancher/$DIST/config.yaml /etc/rancher/$DIST/config.yaml.d/*.yaml; do
    [ -f "$f" ] || continue
    asyaml "$f" | grep -E '^[[:space:]]*(etcd-|cluster-init|disable-etcd|server:|profile:|secrets-encryption)' 2>/dev/null | grep -viE 'token' | sed -E -e "s/^([[:space:]]*[^:]*(access-key|secret-key)[^:]*:)[[:space:]]*(\"\"|'')[[:space:]]*$/\1/" -e 's/^([[:space:]]*[^:]*(access-key|secret-key)[^:]*:)[[:space:]]*[^[:space:]#].*/\1 <set>/' | sed "s|^|$f: |"
  done
fi
sec CONFIGDUMP
dump() { [ -f "$1" ] || return; echo "--- $1"; grep -viE 'token|password|secret-key|access-key' "$1" 2>/dev/null | head -200; }
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then dump "$DATADIR/config"; fi
if [ -f /etc/kubernetes/manifests/etcd.yaml ]; then echo "--- /etc/kubernetes/manifests/etcd.yaml (args)"; grep -E '^[[:space:]]*- --|image:' /etc/kubernetes/manifests/etcd.yaml; fi
if [ -f "$RKE2_DD/agent/pod-manifests/etcd.yaml" ]; then echo "--- $RKE2_DD/agent/pod-manifests/etcd.yaml (args)"; grep -E '^[[:space:]]*- --|image:' "$RKE2_DD/agent/pod-manifests/etcd.yaml"; fi
for f in /etc/etcd/etcd.conf /etc/etcd/etcd.conf.yml /etc/etcd/etcd.conf.yaml /etc/etcd.env /etc/default/etcd /etc/sysconfig/etcd; do dump "$f"; done
if [ "$(systemctl show -p LoadState --value etcd 2>/dev/null)" = loaded ]; then echo "--- systemctl cat etcd"; systemctl cat etcd 2>/dev/null | grep -E '^(ExecStart|Environment|EnvironmentFile|User|WorkingDirectory)'; fi
fi
CURL="curl -sS -m 8"
[ -n "$CA" ] && CURL="$CURL --cacert $CA"
[ -n "$CERT" ] && CURL="$CURL --cert $CERT --key $KEY"
# /health and /metrics are also served on --listen-metrics-urls (rke2/k3s:
# http://127.0.0.1:2381), plain HTTP: no TLS handshake for etcd to do every
# refresh, and on etcd 3.6 the TLS client port hands curl's HTTP/2 request
# to gRPC (415) so the metrics URL is the one that actually answers.
MURL=
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then MURL=$(grep -E '^listen-metrics-urls:' "$DATADIR/config" 2>/dev/null | head -1 | sed -E 's/^listen-metrics-urls:[[:space:]]*//' | cut -d, -f1); fi
[ -z "$MURL" ] && [ -f /etc/kubernetes/manifests/etcd.yaml ] && MURL=$(grep -o -- '--listen-metrics-urls=[^ "]*' /etc/kubernetes/manifests/etcd.yaml 2>/dev/null | head -1 | cut -d= -f2 | cut -d, -f1)
case "$MURL" in http://*) ;; *) MURL=;; esac
sec HEALTH
HEALTH_OUT=curl-missing
if command -v curl >/dev/null 2>&1; then
  HEALTH_OUT=
  [ -n "$MURL" ] && HEALTH_OUT=$(curl -sS -m 8 "$MURL/health" 2>/dev/null)
  [ -n "$HEALTH_OUT" ] || HEALTH_OUT=$($CURL "$EP/health" 2>&1)
fi
echo "$HEALTH_OUT"
sec METRICS
METRICS_OUT=
if command -v curl >/dev/null 2>&1; then
  [ -n "$MURL" ] && METRICS_OUT=$(curl -sS -m 8 "$MURL/metrics" 2>/dev/null)
  [ -n "$METRICS_OUT" ] || METRICS_OUT=$($CURL "$EP/metrics" 2>/dev/null)
fi
[ -n "$METRICS_OUT" ] && echo "$METRICS_OUT" | grep -E '^(etcd_server_has_leader|etcd_server_is_leader|etcd_server_leader_changes_seen_total|etcd_mvcc_db_total_size_in_bytes|etcd_mvcc_db_total_size_in_use_in_bytes|etcd_server_quota_backend_bytes|etcd_disk_wal_fsync_duration_seconds_(sum|count)|etcd_disk_backend_commit_duration_seconds_(sum|count)|etcd_server_proposals_failed_total|etcd_server_proposals_pending|etcd_server_slow_apply_total|etcd_server_slow_read_indexes_total|etcd_server_version|etcd_cluster_version|etcd_debugging_mvcc_keys_total|etcd_server_snapshot_apply_in_progress_total|etcd_network_peer_round_trip_time_seconds_(sum|count)|etcd_server_health_failures|etcd_server_read_indexes_failed_total)'
if [ "__FULL__" = 1 ]; then
sec ENCCONFIG
# Encryption at rest: which providers the running apiserver uses, in order,
# and for which resources. Only the fixed token names are printed - never
# the key material in the file. Full cycles only (ps over every process);
# carried forward by Probe.Merge.
f=$(ps -eo args 2>/dev/null | grep -o -- '--encryption-provider-config=[^ ]*' | head -1 | cut -d= -f2)
if [ -n "$f" ]; then
  echo "file=$f"
  [ -r "$f" ] && echo "tokens=$(grep -oE '(aescbc|aesgcm|secretbox|kms|identity)|secrets|configmaps' "$f" 2>/dev/null | tr '\n' ' ')"
fi
fi
sec ETCDCTL
CID=; DIAG=
if [ "__CTL__" = 0 ]; then
  # the API-side kubectl-exec probe answered last cycle: member list /
  # endpoint status / alarms come from there, skip the three crictl execs
  echo "skipped=api"
else
if [ -z "$ETCDCTL" ] && [ -n "$CRICTL" ] && [ -x "$CRICTL" ] && [ -n "$CRI_EP" ]; then
  CID=$("$CRICTL" -r "$CRI_EP" ps -q --name '^etcd$' 2>/dev/null | head -1)
  if [ -z "$CID" ]; then
    PID=$("$CRICTL" -r "$CRI_EP" pods -q --name '^etcd-' 2>/dev/null | head -1)
    [ -n "$PID" ] && CID=$("$CRICTL" -r "$CRI_EP" ps -q --pod "$PID" 2>/dev/null | head -1)
  fi
  [ -z "$CID" ] && DIAG="no running etcd container found via $CRICTL -r $CRI_EP"
elif [ -z "$ETCDCTL" ]; then
  DIAG="no etcdctl on host and no usable crictl (crictl=$CRICTL cri=$CRI_EP)"
fi
run_ctl() {
  if [ -n "$ETCDCTL" ]; then ETCDCTL_API=3 "$ETCDCTL" --endpoints="$EP" --cacert="$CA" --cert="$CERT" --key="$KEY" "$@" 2>&1
  elif [ -n "$CID" ]; then "$CRICTL" -r "$CRI_EP" exec "$CID" etcdctl --endpoints="$EP" --cacert="$CA" --cert="$CERT" --key="$KEY" "$@" 2>&1
  fi
}
GW=
if [ -n "$ETCDCTL" ]; then echo "via=host $ETCDCTL"; elif [ -n "$CID" ]; then echo "via=crictl $CID"; else echo "via=grpc-gateway"; GW=1; fi
[ -n "$DIAG" ] && echo "diag=$DIAG"
if [ -z "$GW" ]; then
  echo "---MEMBERS"; run_ctl member list -w json
  echo; echo "---STATUS"; run_ctl endpoint status --cluster -w json
  echo; echo "---ALARMS"; run_ctl alarm list -w json
  echo; echo "---ENCSAMPLE"
  # one stored Secret, first 24 bytes only: "k8s:enc:<provider>:v1:<key>:" when
  # encrypted at rest, raw protobuf ("k8s..v1..Secret") when not
  k=$(run_ctl get /registry/secrets/ --prefix --keys-only --limit=1 2>/dev/null | grep '^/registry/' | head -1)
  if [ -n "$k" ]; then
    echo "key=$k"
    echo "prefix=$(run_ctl get "$k" --print-value-only 2>/dev/null | head -c 24 | tr -c '[:print:]' '.')"
  fi
  echo
fi
if [ -n "$GW" ] && command -v curl >/dev/null 2>&1; then
  # etcd gRPC gateway: same certs as /health, no etcdctl needed
  echo "---MEMBERS"; $CURL -X POST "$EP/v3/cluster/member/list" -H 'Content-Type: application/json' -d '{}' 2>&1
  echo; echo "---GWSTATUS"; $CURL -X POST "$EP/v3/maintenance/status" -H 'Content-Type: application/json' -d '{}' 2>&1
  echo; echo "---GWALARMS"; $CURL -X POST "$EP/v3/maintenance/alarm" -H 'Content-Type: application/json' -d '{"action":"GET"}' 2>&1
  echo
fi
fi
sec LEADERLOG
# Reading the whole etcd container log (tens of MB on a busy member) is the
# most expensive part of this probe, so it only runs when this member is
# unhealthy - election history is what quorum-loss triage needs - or on a
# full cycle (__FULL__=1, every heavy_every refreshes / R). khealth carries
# the previous result forward on the cycles that skip it.
LOGRE='became leader at term|elected leader|changed leader from'
ETCDLOGS=
case "$HEALTH_OUT" in *'"health":"true"'*) [ "__FULL__" = 1 ] || { echo "skipped=healthy"; LOGRE=; };; esac
[ -n "$LOGRE" ] && ETCDLOGS=$(ls -tr /var/log/pods/kube-system_etcd-*/etcd/* 2>/dev/null)
if [ -z "$LOGRE" ]; then :
elif [ -n "$ETCDLOGS" ]; then
  echo "source=/var/log/pods/kube-system_etcd-*/etcd"
  cat $ETCDLOGS 2>/dev/null | grep -oE '"local-member-id":"[0-9a-f]+"' | tail -1 | cut -d'"' -f4 | sed 's/^/local-member-id=/'
  cat $ETCDLOGS 2>/dev/null | grep -E "$LOGRE" | tail -30
elif [ "$DIST" = k3s ]; then
  echo "source=journalctl -u k3s"
  journalctl -u k3s -q --no-pager -n 50000 -o short-iso 2>/dev/null | grep -oE '"local-member-id":"[0-9a-f]+"|local-member-id=[0-9a-f]+' | tail -1 | grep -oE '[0-9a-f]{16}' | sed 's/^/local-member-id=/'
  journalctl -u k3s -q --no-pager -n 50000 -o short-iso 2>/dev/null | grep -E "$LOGRE" | tail -30
elif [ "$(systemctl show -p LoadState --value etcd 2>/dev/null)" = loaded ]; then
  echo "source=journalctl -u etcd"
  journalctl -u etcd -q --no-pager -n 50000 -o short-iso 2>/dev/null | grep -oE '"local-member-id":"[0-9a-f]+"' | tail -1 | cut -d'"' -f4 | sed 's/^/local-member-id=/'
  journalctl -u etcd -q --no-pager -n 50000 -o short-iso 2>/dev/null | grep -E "$LOGRE" | tail -30
fi
sec PEERS
# The cluster's members as this node's disk knows them - readable with etcd
# down, which is when it matters (rescue picker, apiserver unreachable):
# the members bucket of the bbolt db (json; freed pages may still hold
# entries of members removed since, so khealth keys them by peer address),
# the initial-cluster list of the generated config / static pod manifest,
# and this member's own name. Scanning the db costs a read of the whole
# file: full cycles and unhealthy members only, carried forward otherwise.
case "$HEALTH_OUT" in *'"health":"true"'*) [ "__FULL__" = 1 ] || { echo "skipped=healthy"; SKIPPEERS=1; };; esac
[ -z "$SKIPPEERS" ] && [ -f "$DATADIR/member/snap/db" ] && grep -ao '{"id":[0-9]*,"peerURLs":\[[^]]*\],"name":"[^"]*"' "$DATADIR/member/snap/db" 2>/dev/null | sort -u | sed 's/^/db: /'
if [ -z "$SKIPPEERS" ]; then
[ -f "$DATADIR/config" ] && grep -E '^initial-cluster:' "$DATADIR/config" 2>/dev/null | sed 's/^/config: /'
for m in /etc/kubernetes/manifests/etcd.yaml /etc/kubernetes/etcd.yaml.off; do [ -f "$m" ] && grep -o -- '--initial-cluster=[^ "]*' "$m" 2>/dev/null | head -1 | sed 's/^--initial-cluster=/config: initial-cluster: /'; done
[ -f "$DATADIR/name" ] && echo "self: $(cat "$DATADIR/name")"
fi
sec RAFT
[ -d "$DATADIR/member/snap" ] && ls "$DATADIR/member/snap"/*.snap 2>/dev/null | sort | tail -1 | sed 's|^|snap=|'
[ -d "$DATADIR/member/wal" ] && stat -c '%Y %n' "$DATADIR/member/wal"/*.wal 2>/dev/null | sort -n | tail -1 | sed 's|^|wal=|'
sec DATADIR
echo "$DATADIR"
[ -d "$DATADIR" ] && du -sk "$DATADIR" 2>/dev/null | cut -f1
[ -d "$DATADIR" ] && df -Pk "$DATADIR" 2>/dev/null | tail -1
if [ "__FULL__" = 1 ]; then
# Where does this host's own backup job write? On kubeadm there is no
# built-in scheduler, so the snapshots are wherever an operator's timer or
# cron puts them - which is nowhere khealth can guess. The command is read
# out of the unit or the crontab line and the destination taken from it, so
# the files below are found and graded like a distribution's own.
#
# Only paths are taken from an EnvironmentFile: those files hold S3
# credentials (see the kubeadm hardening's /etc/etcd-snapshot.env) and are
# never printed.
HINTS=
FOUND=
# paths out of a command line: `etcdctl snapshot save <path>` and the
# BACKUP_DIR-style variables a wrapper script reads
# One sed per rule on purpose: with several -e the expressions run in turn
# on the same pattern space, so the first match rewrites the line and the
# later rules never see the original. That hid BACKUP_DIR=${BACKUP_DIR:-/x},
# which is how a wrapper script usually states its default.
paths_in() {
  _t=$1
  {
    printf '%s\n' "$_t" | tr ' \t' '\n\n' | sed -n 's|^["'"'"']\{0,1\}\(/[^"'"'"']*\)["'"'"']\{0,1\}$|\1|p'
    printf '%s\n' "$_t" | sed -n 's|.*snapshot[ \t][ \t]*save[ \t][ \t]*["'"'"']\{0,1\}\([^ \t"'"'"']*\).*|\1|p'
    printf '%s\n' "$_t" | sed -n 's|.*:-\(/[^ \t"'"'"'}]*\)}.*|\1|p'
    for _k in BACKUP_DIR SNAPSHOT_DIR SNAP_DIR DEST_DIR; do
      printf '%s\n' "$_t" | sed -n "s|.*$_k=[\"']\{0,1\}\([^ \t\"'}:]*\).*|\1|p"
    done
  } | grep '^/' | sort -u
}
# record both the path and its parent: either may be the directory
keep() {
  for p in $1; do
    case "$p" in /*) ;; *) continue ;; esac
    FOUND="$FOUND $p $(dirname "$p")"
  done
}
# the directory to show for a job: a destination usually carries a date in
# its name ($(date +%F)), which is not worth printing half-expanded
shown_dir() {
  for p in $1; do
    case "$p" in
      /*'$'*) dirname "$(printf '%s' "$p" | sed 's|\$.*||')"; return ;;
      /*) printf '%s' "$p"; return ;;
    esac
  done
}
for unit in $(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $NF}' | grep -i 'etcd\|backup' | head -5); do
  svc=$(systemctl show -p Unit "$unit" 2>/dev/null | sed 's/^Unit=//')
  [ -n "$svc" ] || svc=$(echo "$unit" | sed 's/\.timer$/.service/')
  ex=$(systemctl show -p ExecStart "$svc" 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)
  args=$(systemctl show -p ExecStart "$svc" 2>/dev/null | sed -n 's/.*argv\[\]=\([^;]*\).*/\1/p' | head -1)
  env=$(systemctl show -p Environment "$svc" 2>/dev/null | sed 's/^Environment=//')
  when=$(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | grep -F "$unit" | head -1 | sed 's/  */ /g')
  cand=$(paths_in "$args $env")
  # the command is usually a wrapper: read it (bounded) for its own default
  if [ -n "$ex" ] && [ -r "$ex" ] && [ -f "$ex" ]; then
    cand="$cand $(paths_in "$(head -c 8000 "$ex" 2>/dev/null | grep -i 'snapshot save\|BACKUP_DIR=\|SNAPSHOT_DIR=')")"
  fi
  # an EnvironmentFile may name the directory; take only that key from it
  for f in $(systemctl show -p EnvironmentFiles "$svc" 2>/dev/null | sed 's/^EnvironmentFiles=//' | tr ' ' '\n' | sed 's/^-//' | grep '^/'); do
    [ -r "$f" ] && cand="$cand $(grep -hE '^[ \t]*(BACKUP_DIR|SNAPSHOT_DIR|SNAP_DIR)=' "$f" 2>/dev/null | head -3 | sed 's/.*=//' | tr -d '"'"'"'"')"
  done
  keep "$cand"
  HINTS="$HINTS
timer: $unit -> $svc${ex:+ exec=$ex}$(shown_dir "$cand" | sed 's|^| writes=|')${when:+ | $when}"
done
for f in $(grep -rlisE 'etcdctl|etcdutl|etcd.*snapshot' /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/crontab /var/spool/cron 2>/dev/null | head -5); do
  line=$(grep -hiE 'etcdctl|etcdutl|snapshot' "$f" 2>/dev/null | grep -v '^[ \t]*#' | head -1)
  cand=$(paths_in "$line")
  for s in $(printf '%s\n' "$line" | tr ' \t' '\n\n' | grep '^/' | head -3); do
    [ -f "$s" ] && [ -r "$s" ] && cand="$cand $(paths_in "$(head -c 8000 "$s" 2>/dev/null | grep -i 'snapshot save\|BACKUP_DIR=\|SNAPSHOT_DIR=')")"
  done
  keep "$cand"
  HINTS="$HINTS
cron: $f: $(printf '%s' "$line" | cut -c1-160)$(shown_dir "$cand" | sed 's|^| writes=|')"
done
sec SNAPSHOTS
SEEN=
for d in $SNAPDIR $EXTRA_DIRS $FOUND /var/lib/etcd-backup /var/lib/etcd/backup /var/backups/etcd /opt/etcd-backup /opt/etcd/backup /backup/etcd /var/lib/rancher/rke2/server/db/snapshots /var/lib/rancher/k3s/server/db/snapshots; do
  [ -d "$d" ] || continue
  case " $SEEN " in *" $d "*) continue ;; esac   # a discovered dir may repeat a known one
  SEEN="$SEEN $d"
  echo "--- $d"
  for f in "$d"/*; do [ -f "$f" ] && stat -c '%s|%Y|%n' "$f" 2>/dev/null; done
done
sec BACKUPHINTS
printf '%s\n' "$HINTS" | grep -v '^$'
fi
sec END
