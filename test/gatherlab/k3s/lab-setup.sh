#!/bin/sh
# Runs before k3s and sshd (lab-setup.service). systemd services do not
# inherit the container's environment, so the compose settings are read
# from PID 1's.
set -e
env1() { tr '\0' '\n' < /proc/1/environ | sed -n "s/^$1=//p" | head -1; }
DATASTORE=$(env1 LAB_DATASTORE); DATASTORE=${DATASTORE:-etcd}
HEADROOM=$(env1 LAB_EVICT_HEADROOM_MI); HEADROOM=${HEADROOM:-3584}

# a throwaway key pair in the shared out/: khealth logs in with out/id_lab
if [ ! -s /out/id_lab ]; then
  rm -f /out/id_lab /out/id_lab.pub
  ssh-keygen -q -t ed25519 -N '' -C khealth-gatherlab -f /out/id_lab
  chmod 644 /out/id_lab # read by khealth from the host / the check container
fi
install -m 600 /out/id_lab.pub /root/.ssh/authorized_keys

# In its private cgroup namespace the kubelet's memory.available is the
# VM's memory minus what this container uses: the threshold sits HEADROOM
# below the total. k3s and the lab use ~1.5 GiB; the 4 GiB noisy neighbour
# (manifests/noisy.yaml) takes the node below; other containers on the
# Docker VM do not count.
avail=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
thr=$(( avail - HEADROOM * 1024 ))
{
  echo "node-name: lab-node"
  echo "https-listen-port: 16443"
  echo "tls-san: [127.0.0.1, k3s, lab-node]"
  echo "write-kubeconfig: /out/kubeconfig.yaml"
  echo "write-kubeconfig-mode: \"0644\""
  echo "kubelet-arg:"
  echo "  - \"eviction-hard=memory.available<${thr}Ki\""
  echo "  - \"eviction-pressure-transition-period=30s\""
  [ "$DATASTORE" = etcd ] && echo "cluster-init: true"
} > /etc/rancher/k3s/config.yaml
echo "gatherlab: datastore $DATASTORE, eviction-hard memory.available<${thr}Ki (MemTotal ${avail}Ki)"
