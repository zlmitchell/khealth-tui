# Give the restored data dir the owner the old one had (rke2 `profile: cis`
# runs etcd as the etcd user; kubeadm as root), the private mode etcd and
# the STIG both expect (0700, nothing readable by group/other underneath)
# and, on SELinux hosts, the labels the policy prescribes: files written
# by a restore started from an SSH session carry unconfined_u, which the
# confined etcd container is denied.
OWNER='__OWNER__'
[ -d "$DATADIR" ] || die "$DATADIR missing after the restore"
if [ -n "$OWNER" ] && [ "$OWNER" != "root:root" ]; then
  chown -R "$OWNER" "$DATADIR" 2>&1 && say "chown -R $OWNER $DATADIR" || say "warning: chown $OWNER failed"
fi
chmod 700 "$DATADIR" && say "chmod 700 $DATADIR"
[ -d "$DATADIR/member" ] && chmod -R go-rwx "$DATADIR/member" 2>/dev/null && say "chmod -R go-rwx $DATADIR/member"
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled 2>/dev/null && command -v restorecon >/dev/null 2>&1; then
  n=$(restorecon -RFv "$DATADIR" 2>/dev/null | grep -c Relabeled)
  say "restorecon -RF $DATADIR: $n relabeled"
  say "context=$(ls -dZ "$DATADIR" 2>/dev/null | awk '{print $1}')"
fi
say "owner=$(stat -c '%U:%G' "$DATADIR" 2>/dev/null)"
say "mode=$(stat -c '%a' "$DATADIR" 2>/dev/null)"
say "perms=ok"
