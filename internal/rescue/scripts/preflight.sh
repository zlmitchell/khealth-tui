# Preflight: what the rescue needs to know about this node before anything
# is touched. Read-only. __ROLE__ is target|other; the target also checks
# the snapshot (__SNAP__, __S3__=1 for an S3 object name).
say "hostname=$(hostname)"
say "kind=$KIND"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
say "svc=$SVC"
say "svc_state=$(systemctl is-active $SVC 2>/dev/null)"
if [ -d "$DATADIR" ]; then
  say "datadir=$DATADIR"
  say "owner=$(stat -c '%U:%G' "$DATADIR" 2>/dev/null)"
  say "mode=$(stat -c '%a' "$DATADIR" 2>/dev/null)"
  say "size_kb=$(du -sk "$DATADIR" 2>/dev/null | cut -f1)"
  [ -d "$DATADIR/member/wal" ] && say "member=yes" || say "member=no"
else
  say "datadir=$DATADIR"
  say "member=missing"
fi
MP=no
if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$DATADIR" 2>/dev/null; then MP=yes; fi
say "mountpoint=$MP"
if [ "$MP" = yes ]; then
  case "$KIND" in rke2|k3s) die "$DATADIR is a mount point: $KIND cluster-reset moves the directory aside, which fails on a mount point; move the data off the mount first";; esac
  RESCUE=$DATADIR/rescue-$STAMP
fi
say "rescue_dir=$RESCUE"
say "avail_kb=$(df -Pk "$(dirname "$DATADIR")" 2>/dev/null | tail -1 | awk '{print $4}')"
say "etcd_container=$(etcd_cid)"
case "$KIND" in
  rke2|k3s)
    [ -n "$BIN" ] || die "$KIND binary not found (looked in PATH, /usr/local/bin, /opt/$KIND/bin, /usr/bin)"
    say "bin=$BIN"
    [ -f "$DD/server/db/reset-flag" ] && die "$DD/server/db/reset-flag exists: a previous cluster-reset was not followed by a normal start of $SVC (start it once, or remove the flag)"
    [ -d "$DD/server" ] || die "$DD/server missing: not a server node"
    # join URL and cluster-init decide how this node comes back (values only; tokens never printed)
    for f in $CONFDIR/config.yaml $CONFDIR/config.yaml.d/*.yaml; do
      [ -f "$f" ] || continue
      grep -E '^[[:space:]]*(server|cluster-init|profile|etcd-s3|etcd-s3-config-secret|data-dir)[[:space:]]*:' "$f" 2>/dev/null | sed -E 's/^[[:space:]]*//' | sed "s|^|config: |"
    done
    say "etcd_user=$(id -u etcd 2>/dev/null || echo none)"
    ;;
  *)
    M=$MANIFESTS/etcd.yaml; [ -f "$M" ] || M=$PARKED/etcd.yaml.off
    [ -f "$M" ] || die "no etcd static pod manifest ($MANIFESTS/etcd.yaml)"
    say "manifest=$M"
    say "name=$(grep -o -- '--name=[^ "]*' "$M" 2>/dev/null | head -1 | cut -d= -f2-)"
    say "peer=$(grep -o -- '--initial-advertise-peer-urls=[^ "]*' "$M" 2>/dev/null | head -1 | cut -d= -f2-)"
    say "image=$(grep -E '^[[:space:]]*image:' "$M" 2>/dev/null | head -1 | awk '{print $2}')"
    say "initial_cluster=$(grep -o -- '--initial-cluster=[^ "]*' "$M" 2>/dev/null | head -1 | cut -d= -f2-)"
    [ -f $MANIFESTS/kube-apiserver.yaml ] || [ -f $PARKED/kube-apiserver.yaml.off ] || die "no kube-apiserver manifest: not a control-plane node"
    # where kubectl, kube-proxy and the CNI pods reach the API: the
    # controlPlaneEndpoint (another node, a VIP, a load balancer) or this node
    say "api_endpoint=$(grep -m1 -E '^[[:space:]]*server:' /etc/kubernetes/admin.conf 2>/dev/null | awk '{print $2}')"
    for t in etcdutl etcdctl ctr podman; do command -v $t >/dev/null 2>&1 && say "tool=$t"; done
    [ -n "$CRICTL" ] || die "crictl not found"
    [ -n "$CRI_EP" ] || die "no CRI socket found (containerd, cri-o, cri-dockerd)"
    say "crictl=$CRICTL $CRI_EP"
    ;;
esac
if [ "__ROLE__" = target ]; then
  SNAP='__SNAP__'
  if [ "__S3__" = 1 ]; then
    say "snapshot=s3:$SNAP"
  else
    [ -r "$SNAP" ] || die "snapshot $SNAP is not readable on this node"
    say "snapshot=$SNAP"
    say "snapshot_size=$(stat -c %s "$SNAP" 2>/dev/null)"
    say "snapshot_mtime=$(stat -c %Y "$SNAP" 2>/dev/null)"
  fi
fi
say "preflight=ok"
