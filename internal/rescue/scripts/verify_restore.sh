# rke2/k3s, after the cluster-reset: did it actually wipe and restore the
# data dir? The combined restore + reset has been seen to leave the old
# data in place. Evidence required: rke2 renamed the previous dir to
# etcd-old-<time> (newer than __SINCE__, the reset's start in epoch
# seconds), member/snap/db and member/wal were written after the reset,
# and the reset's own log says "restored snapshot". Sizes are printed for
# the record only: bbolt grows the db as soon as etcd runs, so it never
# matches the snapshot file.
SNAP='__SNAP__'; SINCE=__SINCE__
DB=$DATADIR/member/snap/db
LOG=$RESCUE/cluster-reset.log
old=$(ls -d "$(dirname "$DATADIR")"/etcd-old-* 2>/dev/null | while read -r d; do [ "$(stat -c %Y "$d")" -ge "$((SINCE - 5))" ] && echo "$d"; done | tr '\n' ' ')
say "old_dirs=$old"
if [ -f "$DB" ]; then
  say "snapdb_size=$(stat -c %s "$DB")"
  say "snapdb_mtime=$(stat -c %Y "$DB")"
fi
[ -d "$DATADIR/member/wal" ] && say "wal=yes" || say "wal=no"
[ "__S3__" = 0 ] && [ -f "$SNAP" ] && say "snapshot_size=$(stat -c %s "$SNAP")"
logged=no; grep -q '"restored snapshot"' "$LOG" 2>/dev/null && logged=yes
say "log_restored=$logged"
why=
if [ ! -f "$DB" ]; then why="no $DB after the reset"
elif [ "$(stat -c %Y "$DB")" -lt "$((SINCE - 5))" ]; then why="$DB is older than the reset (not rewritten)"
elif [ ! -d "$DATADIR/member/wal" ]; then why="no $DATADIR/member/wal"
elif [ -z "$old" ]; then why="no $(dirname "$DATADIR")/etcd-old-<time> created by the reset (previous data not moved aside)"
elif [ -f "$LOG" ] && [ "$logged" = no ]; then why="the reset log $LOG never says \"restored snapshot\""
fi
if [ -n "$why" ]; then say "restored=no $why"; else say "restored=yes"; fi
say "verify=ok"
