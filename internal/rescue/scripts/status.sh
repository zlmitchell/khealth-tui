# Cluster state as seen from this node: service state, the local member's
# /health, the apiserver's /readyz (__API__=1), then etcdctl member list /
# endpoint health / endpoint status for the whole cluster (parsed by
# etcd.ParseCtl). With __PROMOTE__=1 a learner that has caught up is
# promoted (kubeadm followers join as learners; etcd refuses the promotion
# until the learner is in sync, so it is simply retried every poll).
say "svc_state=$(systemctl is-active $SVC 2>/dev/null)"
say "etcd_container=$(etcd_cid)"
H=$(curl -sS -m 5 --cacert "$CA" --cert "$CERT" --key "$KEY" https://127.0.0.1:2379/health 2>/dev/null)
[ -n "$H" ] || H=$(curl -sS -m 5 http://127.0.0.1:2381/health 2>/dev/null)
say "health=$H"
if [ "__API__" = 1 ]; then
  say "readyz=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' https://127.0.0.1:6443/readyz 2>/dev/null)"
fi
if [ "__PROMOTE__" = 1 ]; then
  for id in $(run_ctl member list 2>/dev/null | awk -F', ' '$6=="true" {print $1}'); do
    say "promote $id: $(run_ctl member promote "$id" 2>&1 | head -1)"
  done
fi
say "---MEMBERS"; run_ctl member list -w json
say; say "---HEALTH"; run_ctl endpoint health --cluster -w json
say; say "---STATUS"; run_ctl endpoint status --cluster -w json
say; say "---ALARMS"; run_ctl alarm list -w json
say; say "---LOG"
case "$KIND" in
  rke2|k3s) journalctl -u $SVC -n 8 --no-pager -o cat 2>/dev/null | cut -c1-300;;
  *) [ -n "$(etcd_cid)" ] && "$CRICTL" -r "$CRI_EP" logs --tail 8 "$(etcd_cid)" 2>&1 | cut -c1-300;;
esac
