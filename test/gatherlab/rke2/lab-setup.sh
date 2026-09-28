#!/bin/sh
# Runs before rke2-server and sshd (lab-setup.service). systemd services do
# not inherit the container's environment, so the compose settings are
# read from PID 1's.
set -e
env1() { tr '\0' '\n' < /proc/1/environ | sed -n "s/^$1=//p" | head -1; }
HEADROOM=$(env1 LAB_EVICT_HEADROOM_MI); HEADROOM=${HEADROOM:-3584}

# a throwaway key pair in the shared out/: khealth logs in with out/id_lab
if [ ! -s /out/id_lab ]; then
  rm -f /out/id_lab /out/id_lab.pub
  ssh-keygen -q -t ed25519 -N '' -C khealth-gatherlab-rke2 -f /out/id_lab
  chmod 644 /out/id_lab # read by khealth from the host / the check container
fi
install -m 600 /out/id_lab.pub /root/.ssh/authorized_keys

# As in the k3s lab: the kubelet's memory.available threshold sits
# HEADROOM below the VM's memory (private cgroup namespace), so the 4 GiB
# noisy neighbour (manifests/noisy.yaml) crosses it. kube-proxy leaves the
# host's conntrack table alone.
avail=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
thr=$(( avail - HEADROOM * 1024 ))
{
  echo "node-name: lab-node"
  echo "tls-san: [127.0.0.1, rke2, lab-node]"
  echo "write-kubeconfig-mode: \"0644\""
  echo "kubelet-arg:"
  echo "  - \"eviction-hard=memory.available<${thr}Ki\""
  echo "  - \"eviction-pressure-transition-period=30s\""
  echo "kube-proxy-arg:"
  echo "  - \"conntrack-max-per-core=0\""
} > /etc/rancher/rke2/config.yaml
echo "gatherlab: rke2, eviction-hard memory.available<${thr}Ki (MemTotal ${avail}Ki)"

# rke2 applies whatever lands in its manifests directory
d=/var/lib/rancher/rke2/server/manifests
mkdir -p $d
cp /lab/manifests/rke2-ingress.yaml $d/lab-ingress.yaml
for m in shop incidents noisy; do cp /lab/manifests/$m.yaml $d/lab-$m.yaml; done
