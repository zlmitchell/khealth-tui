# Fresh snapshot of the rebuilt cluster, so the next restore point is not
# the one that was just used. rke2/k3s: the built-in snapshot command
# (local, and S3 if configured). kubeadm: etcdctl on the host into
# __DIR__ (the directory the restored snapshot came from), through the
# etcd container's etcdctl when the host has none.
DIR='__DIR__'
case "$KIND" in
  rke2|k3s)
    out=$($BIN etcd-snapshot save --name "rescue-$STAMP" 2>&1); rc=$?
    echo "$out" | grep -iE 'snapshot|saved|error|fail' | tail -n 5 | cut -c1-300
    [ $rc -eq 0 ] || die "$KIND etcd-snapshot save exited $rc"
    ;;
  *)
    f=$DIR/rescue-$STAMP.db
    if command -v etcdctl >/dev/null 2>&1; then
      out=$(run_ctl snapshot save "$f") || die "snapshot save: $(echo "$out" | head -1)"
    else
      # the container's etcdctl only sees the data dir: save there, move out
      tmp=$DATADIR/.rescue-$STAMP.db
      out=$(run_ctl snapshot save "$tmp") || die "snapshot save: $(echo "$out" | head -1)"
      mkdir -p "$DIR" && mv "$tmp" "$f" || die "cannot move $tmp to $DIR"
      chmod 600 "$f"
    fi
    say "saved $f ($(stat -c %s "$f" 2>/dev/null) bytes)"
    ;;
esac
say "snapshot=ok"
