# Bring etcd back on this node. rke2/k3s: start the server unit without
# waiting (it becomes active only once the apiserver answers, minutes
# later; status.sh polls). kubeadm: put the etcd manifest back so kubelet
# starts the pod. rke2/k3s get a drop-in first that decides where the node
# joins, whatever config.yaml, Rancher's 50-rancher.yaml or RKE2_URL say:
# a follower joins through __JOIN__ (the restored target) - its own server:
# may name a server that is still stopped, or be absent on the cluster-init
# node, which would then found a new cluster; the restored target itself
# starts with server: "" - with one (a VIP, another server, Rancher's init
# node) it would try to join instead of serving the restored data. rke2
# reads config.yaml.d in name order and the last value wins, so the drop-in
# must sort last. It is removed again once the node is a healthy member, or
# on the target once every follower is back (join_cleanup.sh).
JOIN='__JOIN__'
case "$KIND" in
  rke2|k3s)
    if [ -n "$JOIN" ] || [ "__ROLE__" = target ]; then
      mkdir -p $CONFDIR/config.yaml.d || die "cannot create $CONFDIR/config.yaml.d"
      N=zz-khealth-rescue.yaml; D=$CONFDIR/config.yaml.d/$N
      last=$(ls -1 $CONFDIR/config.yaml.d 2>/dev/null | grep -E '\.ya?ml$' | grep -vx "$N" | sort | tail -1)
      if [ -n "$last" ] && [ "$(printf '%s\n%s\n' "$last" "$N" | sort | tail -1)" != "$N" ]; then
        die "$CONFDIR/config.yaml.d/$last sorts after $N and would override the rescue's server: (rename it for the rescue)"
      fi
      if [ -n "$JOIN" ]; then
        ( umask 077; printf 'server: %s\n' "$JOIN" > $D ) || die "cannot write the join drop-in"
        # joining needs the cluster token in the config; the first server never
        # had one there (it generated server/token, which every server still
        # holds - the rescue moves db/etcd only)
        if ! grep -qsE '^[[:space:]]*token[[:space:]]*:|"token"[[:space:]]*:' $CONFDIR/config.yaml $CONFDIR/config.yaml.d/*.yaml; then
          [ -s "$DD/server/token" ] || die "no token: in the config and no $DD/server/token to join with"
          printf 'token: %s\n' "$(cat $DD/server/token)" >> $D
          say "added the cluster token from $DD/server/token to the drop-in"
        fi
        [ "$KIND" = k3s ] && printf 'cluster-init: false\n' >> $D
        say "wrote $D (server: $JOIN)"
      else
        ( umask 077; printf 'server: ""\n' > $D ) || die "cannot write the server: drop-in"
        say "wrote $D (server: \"\" - the restored node serves alone until every follower is back)"
      fi
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
