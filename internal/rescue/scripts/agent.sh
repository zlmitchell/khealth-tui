# rke2/k3s provisioned by Rancher: rancher-system-agent applies the machine
# plan whenever Rancher sends (or re-sends) one - it rewrites
# config.yaml.d/50-rancher.yaml and restarts or starts rke2-server. Mid-rescue
# that starts a stopped server against data that was moved aside (the
# cluster-init node would found a new cluster), or restarts the target with
# the plan's server: before the followers are back. __ACTION__ is stop
# (before anything is touched) or start (once every server is back and the
# rescue's drop-ins are gone).
U=rancher-system-agent
case '__ACTION__' in
  stop)
    systemctl stop $U 2>&1 || die "systemctl stop $U failed"
    st=$(systemctl is-active $U 2>/dev/null)
    case "$st" in active|activating|deactivating|reloading) die "$U is still $st";; esac
    say "stopped $U ($st)"
    ;;
  start)
    systemctl start $U 2>&1 || die "systemctl start $U failed"
    say "started $U ($(systemctl is-active $U 2>/dev/null))"
    ;;
  *) die "unknown action '__ACTION__'" ;;
esac
say "agent=ok"
