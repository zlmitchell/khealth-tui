# kubeadm: restore the snapshot into the (moved-aside) data dir as a new
# one-member cluster. etcdutl on the host when there is one, else etcdctl
# (etcd < 3.5), else the etcd image the static pod runs (ctr for containerd,
# podman for cri-o) with the data dir's parent and the snapshot's directory
# bind-mounted. __NAME__ / __PEER__ come from the node's etcd manifest.
SNAP='__SNAP__'; NAME='__NAME__'; PEER='__PEER__'; IMAGE='__IMAGE__'
[ -r "$SNAP" ] || die "snapshot $SNAP is not readable"
[ -n "$NAME" ] && [ -n "$PEER" ] || die "member name/peer URL unknown (no --name / --initial-advertise-peer-urls in the etcd manifest)"
[ -n "$(etcd_cid)" ] && die "an etcd container is still running"
TARGET=$DATADIR; TMP=
if [ -d "$DATADIR" ]; then
  # the data dir must not exist for the restore; on a mount point restore
  # inside it and move the member directory up afterwards
  TMP=$DATADIR/.rescue-restore-$STAMP; TARGET=$TMP; rm -rf "$TMP"
fi
SNAPDIR=$(dirname "$SNAP"); PARENT=$(dirname "$DATADIR")
ARGS="snapshot restore $SNAP --data-dir $TARGET --name $NAME --initial-cluster $NAME=$PEER --initial-advertise-peer-urls $PEER"
# under systemd where possible: a command run from an SSH session is
# unconfined_u under SELinux and the files it writes inherit that user,
# which the confined etcd container is then denied
runsys() {
  if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemd-run --quiet --wait --pipe --collect --unit "khealth-rescue-$STAMP-$$" "$@"
  else
    "$@"
  fi
}
rc=1; out=
if command -v etcdutl >/dev/null 2>&1; then
  say "via=etcdutl $(etcdutl version 2>/dev/null | head -1)"
  out=$(runsys etcdutl $ARGS 2>&1); rc=$?
elif command -v etcdctl >/dev/null 2>&1; then
  say "via=etcdctl"
  out=$(runsys env ETCDCTL_API=3 etcdctl $ARGS 2>&1); rc=$?
elif [ -n "$IMAGE" ] && command -v ctr >/dev/null 2>&1; then
  say "via=ctr $IMAGE"
  MOUNTS="--mount type=bind,src=$PARENT,dst=$PARENT,options=rbind:rw --mount type=bind,src=$SNAPDIR,dst=$SNAPDIR,options=rbind:ro"
  out=$(runsys ctr -n k8s.io run --rm $MOUNTS "$IMAGE" "khealth-rescue-$STAMP" etcdutl $ARGS 2>&1); rc=$?
  if [ $rc -ne 0 ] && echo "$out" | grep -qiE 'etcdutl.*(no such file|not found|executable)'; then
    say "no etcdutl in the image, retrying with etcdctl"
    out=$(runsys ctr -n k8s.io run --rm --env ETCDCTL_API=3 $MOUNTS "$IMAGE" "khealth-rescue-$STAMP" etcdctl $ARGS 2>&1); rc=$?
  fi
elif [ -n "$IMAGE" ] && command -v podman >/dev/null 2>&1; then
  say "via=podman $IMAGE"
  out=$(runsys podman run --rm -v "$PARENT:$PARENT" -v "$SNAPDIR:$SNAPDIR:ro" "$IMAGE" etcdutl $ARGS 2>&1); rc=$?
  if [ $rc -ne 0 ] && echo "$out" | grep -qiE 'etcdutl.*(no such file|not found|executable)'; then
    say "no etcdutl in the image, retrying with etcdctl"
    out=$(runsys podman run --rm -e ETCDCTL_API=3 -v "$PARENT:$PARENT" -v "$SNAPDIR:$SNAPDIR:ro" "$IMAGE" etcdctl $ARGS 2>&1); rc=$?
  fi
else
  die "no way to run 'snapshot restore': install etcdutl (or etcdctl) on this node, or ctr/podman with the etcd image $IMAGE available"
fi
echo "$out" | tail -n 20 | cut -c1-300
[ $rc -eq 0 ] || die "snapshot restore exited $rc"
if [ -n "$TMP" ]; then
  [ -d "$TMP/member" ] || die "restore produced no $TMP/member"
  mv "$TMP/member" "$DATADIR/member" || die "cannot move restored member dir into $DATADIR"
  rm -rf "$TMP"
fi
[ -d "$DATADIR/member/snap" ] && [ -d "$DATADIR/member/wal" ] || die "restored data dir $DATADIR has no member/snap + member/wal"
say "restore=ok"
