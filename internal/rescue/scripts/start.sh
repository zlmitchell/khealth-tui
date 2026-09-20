# Bring etcd back on this node. rke2/k3s: start the server unit without
# waiting (it becomes active only once the apiserver answers, minutes
# later; status.sh polls). kubeadm: put the etcd manifest back so kubelet
# starts the pod. A follower that has no `server:` in its config would
# bootstrap a brand-new cluster instead of joining, so __JOIN__ (the
# target's join URL, or empty) is written as a drop-in first; it is removed
# again once the node is a healthy member (join_cleanup.sh).
JOIN='__JOIN__'
case "$KIND" in
  rke2|k3s)
    if [ -n "$JOIN" ]; then
      mkdir -p $CONFDIR/config.yaml.d || die "cannot create $CONFDIR/config.yaml.d"
      D=$CONFDIR/config.yaml.d/99-khealth-rescue.yaml
      ( umask 077; printf 'server: %s\n' "$JOIN" > $D ) || die "cannot write the join drop-in"
      # joining needs the cluster token in the config; the first server never
      # had one there (it generated server/token, which every server still
      # holds - the rescue moves db/etcd only)
      if ! grep -qsE '^[[:space:]]*token[[:space:]]*:' $CONFDIR/config.yaml $CONFDIR/config.yaml.d/*.yaml; then
        [ -s "$DD/server/token" ] || die "no token: in the config and no $DD/server/token to join with"
        printf 'token: %s\n' "$(cat $DD/server/token)" >> $D
        say "added the cluster token from $DD/server/token to the drop-in"
      fi
      [ "$KIND" = k3s ] && printf 'cluster-init: false\n' >> $D
      say "wrote $D (server: $JOIN)"
    fi
    [ -d "$DATADIR/member/wal" ] && [ "__ROLE__" = other ] && die "$DATADIR still holds member data; the node would rejoin with its old identity"
    say "systemctl start --no-block $SVC"
    systemctl start --no-block $SVC 2>&1 || die "systemctl start $SVC failed"
    ;;
  *)
    # kubelet creates a missing data dir (hostPath DirectoryOrCreate) as
    # 0755; etcd and the CIS/STIG rules expect 0700, so create it first
    if [ ! -d "$DATADIR" ]; then
      mkdir -p "$DATADIR" && chmod 700 "$DATADIR" && say "created $DATADIR (0700)" || die "cannot create $DATADIR"
    fi
    if [ -f $PARKED/etcd.yaml.off ]; then
      mv $PARKED/etcd.yaml.off $MANIFESTS/etcd.yaml || die "cannot restore the etcd manifest"
      say "restored $MANIFESTS/etcd.yaml"
    elif [ -f $MANIFESTS/etcd.yaml ]; then
      say "etcd manifest already in place"
    else
      die "no etcd manifest to restore"
    fi
    systemctl is-active kubelet >/dev/null 2>&1 || { systemctl start kubelet 2>&1; say "started kubelet"; }
    ;;
esac
say "started=ok"
