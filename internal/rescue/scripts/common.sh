# Prelude shared by every etcd rescue script (prepended by rescue.render).
# Sent to nodes over SSH by khealth as root via `sh -s`; POSIX sh only.
# Placeholders: __KIND__ (rke2|k3s|kubeadm), __DD__ (rke2/k3s data-dir),
# __DATADIR__ (etcd member data dir), __STAMP__ (rescue id), __RESCUE__
# (backup directory chosen by the preflight; empty until then).
export LC_ALL=C
PATH=$PATH:/usr/local/bin:/opt/rke2/bin:/usr/local/sbin:/usr/sbin:/sbin
KIND='__KIND__'; DD='__DD__'; DATADIR='__DATADIR__'; STAMP='__STAMP__'; RESCUE='__RESCUE__'
say() { printf '%s\n' "$*"; }
die() { say "ERROR: $*"; exit 1; }
BIN=; SVC=; CRICTL=; CRI_EP=; MANIFESTS=/etc/kubernetes/manifests; PARKED=/etc/kubernetes; JOINPORT=
case "$KIND" in
  rke2|k3s)
    SVC=rke2-server; JOINPORT=9345
    [ "$KIND" = k3s ] && { SVC=k3s; JOINPORT=6443; }
    BIN=$(command -v $KIND 2>/dev/null)
    [ -z "$BIN" ] && for b in /usr/local/bin/$KIND /opt/$KIND/bin/$KIND /usr/bin/$KIND; do [ -x "$b" ] && { BIN=$b; break; }; done
    CRICTL=$DD/bin/crictl; CRI_EP=unix:///run/k3s/containerd/containerd.sock
    [ -x "$CRICTL" ] || CRICTL=$(command -v crictl 2>/dev/null)
    CA=$DD/server/tls/etcd/server-ca.crt; CERT=$DD/server/tls/etcd/server-client.crt; KEY=$DD/server/tls/etcd/server-client.key
    [ -z "$RESCUE" ] && RESCUE=$DD/server/etcd-rescue-$STAMP
    # k3s embeds kubectl as a subcommand; rke2 ships it under its bin dir
    KUBECTL="$DD/bin/kubectl --kubeconfig /etc/rancher/$KIND/$KIND.yaml"
    [ "$KIND" = k3s ] && KUBECTL="$BIN kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml"
    CONFDIR=/etc/rancher/$KIND
    ;;
  *)
    SVC=kubelet
    CRICTL=$(command -v crictl 2>/dev/null)
    for s in /run/containerd/containerd.sock /var/run/crio/crio.sock /run/cri-dockerd.sock; do [ -S "$s" ] && { CRI_EP="unix://$s"; break; }; done
    CA=/etc/kubernetes/pki/etcd/ca.crt; CERT=/etc/kubernetes/pki/etcd/healthcheck-client.crt; KEY=/etc/kubernetes/pki/etcd/healthcheck-client.key
    [ -f "$CERT" ] || { CERT=/etc/kubernetes/pki/apiserver-etcd-client.crt; KEY=/etc/kubernetes/pki/apiserver-etcd-client.key; }
    [ -z "$RESCUE" ] && RESCUE=$(dirname "$DATADIR")/$(basename "$DATADIR")-rescue-$STAMP
    KUBECTL="kubectl --kubeconfig /etc/kubernetes/admin.conf"
    ;;
esac
# running etcd container id (static pod), if any
etcd_cid() { [ -n "$CRICTL" ] && [ -n "$CRI_EP" ] && "$CRICTL" -r "$CRI_EP" ps -q --name '^etcd$' 2>/dev/null | head -1; }
# etcdctl against the local member: host binary, else exec into the container
run_ctl() {
  if command -v etcdctl >/dev/null 2>&1; then
    ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert="$CA" --cert="$CERT" --key="$KEY" --command-timeout=10s "$@" 2>&1
  else
    cid=$(etcd_cid)
    [ -n "$cid" ] || { echo "no etcd container running"; return 1; }
    "$CRICTL" -r "$CRI_EP" exec "$cid" etcdctl --endpoints=https://127.0.0.1:2379 --cacert="$CA" --cert="$CERT" --key="$KEY" --command-timeout=10s "$@" 2>&1
  fi
}
