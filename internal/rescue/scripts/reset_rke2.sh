# rke2/k3s: reset cluster membership to this node only, restoring __SNAP__
# first when it is set (a local path, or an object name with __S3__=1; S3
# settings then come from config.yaml). Without a snapshot it is the plain
# second cluster-reset the rescue runs when the restored member did not come
# up alone (__FORCE__=1 also clears the reset-flag the first one left). The
# command reads config.yaml like the service does, exits by itself when done
# ("Managed etcd cluster membership has been reset") and can take minutes,
# so it runs detached from the SSH session; khealth polls its log and exit
# file (poll.sh). It runs as a transient systemd unit where systemd exists:
# an SSH session is unconfined_u under SELinux and every file the restore
# writes would carry that user, which the confined etcd container is then
# denied access to - the same command under systemd gets the context the
# rke2-server unit has.
SNAP='__SNAP__'
LOG=$RESCUE/cluster-reset.log; EXITF=$RESCUE/cluster-reset.exit
[ -z "$SNAP" ] && { LOG=$RESCUE/cluster-reset-2.log; EXITF=$RESCUE/cluster-reset-2.exit; }
mkdir -p "$RESCUE" || die "cannot create $RESCUE"
rm -f "$EXITF"
[ -n "$BIN" ] || die "$KIND binary not found"
st=$(systemctl is-active $SVC 2>/dev/null)
case "$st" in active|activating) die "$SVC is $st: stop it before the cluster-reset";; esac
RESTORE=
if [ -n "$SNAP" ]; then
  [ "__S3__" = 1 ] || [ -r "$SNAP" ] || die "snapshot $SNAP is not readable"
  RESTORE="--cluster-reset-restore-path='$SNAP'"
  if [ "__S3__" = 1 ]; then RESTORE="$RESTORE --etcd-s3"; else RESTORE="$RESTORE --etcd-s3=false"; fi
fi
if [ -f "$DD/server/db/reset-flag" ]; then
  [ "__FORCE__" = 1 ] || die "$DD/server/db/reset-flag exists: the previous cluster-reset was not followed by a normal start"
  rm -f "$DD/server/db/reset-flag" && say "removed $DD/server/db/reset-flag (deliberate second reset)"
fi
# rke2/k3s refuse a cluster-reset while the config carries a join URL
# (any server but the first one has server:); the flag on the command line
# overrides the file and leaves the file alone
SRVFLAG=
grep -qsE '^[[:space:]]*server[[:space:]]*:' $CONFDIR/config.yaml $CONFDIR/config.yaml.d/*.yaml 2>/dev/null && SRVFLAG=--server=
say "cmd=$BIN server --cluster-reset $RESTORE $SRVFLAG"
say "log=$LOG"
CMD="'$BIN' server --cluster-reset $RESTORE $SRVFLAG >'$LOG' 2>&1; echo \$? >'$EXITF'"
if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  UNIT=khealth-rescue-$STAMP-$$
  systemctl reset-failed "$UNIT" >/dev/null 2>&1
  systemd-run --quiet --collect --unit "$UNIT" -p KillMode=process /bin/sh -c "$CMD" || die "systemd-run failed to start the cluster-reset"
  say "via=systemd-run $UNIT"
else
  setsid nohup /bin/sh -c "$CMD" >/dev/null 2>&1 </dev/null &
  say "via=setsid"
fi
sleep 1
say "started=ok"
