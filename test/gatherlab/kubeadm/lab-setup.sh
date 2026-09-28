#!/bin/sh
# Runs before sshd and kubeadm (lab-setup.service). systemd services do
# not inherit the container's environment, so the compose settings are
# read from PID 1's.
set -e
env1() { tr '\0' '\n' < /proc/1/environ | sed -n "s/^$1=//p" | head -1; }
HEADROOM=$(env1 LAB_EVICT_HEADROOM_MI); HEADROOM=${HEADROOM:-3584}

# a throwaway key pair in the shared out/: khealth logs in with out/id_lab
if [ ! -s /out/id_lab ]; then
  rm -f /out/id_lab /out/id_lab.pub
  ssh-keygen -q -t ed25519 -N '' -C khealth-gatherlab-kubeadm -f /out/id_lab
  chmod 644 /out/id_lab # read by khealth from the host / the check container
fi
install -m 600 /out/id_lab.pub /root/.ssh/authorized_keys

# The kubeadm config, close to the one kind writes: the kubelet on the
# systemd cgroup driver under /kubelet, image and disk eviction off
# (the Docker VM's disk is not the lab's), kube-proxy leaving the host's
# conntrack table alone. As in the k3s lab, memory.available is the VM's
# memory minus this container's use (private cgroup namespace): the
# threshold sits HEADROOM below the total, and the 4 GiB noisy neighbour
# (manifests/noisy.yaml) takes the node below it.
avail=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
thr=$(( avail - HEADROOM * 1024 ))
ip=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -1)
cat > /etc/kubernetes/lab-kubeadm.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint: {advertiseAddress: "$ip", bindPort: 6443}
nodeRegistration:
  name: lab-node
  criSocket: unix:///run/containerd/containerd.sock
  kubeletExtraArgs:
  - {name: node-ip, value: "$ip"}
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: $(cat /kind/version)
clusterName: gatherlab-kubeadm
controlPlaneEndpoint: lab-node:6443
apiServer:
  certSANs: [127.0.0.1, localhost, lab-node, kubeadm]
networking: {podSubnet: 10.244.0.0/16, serviceSubnet: 10.96.0.0/16}
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
cgroupRoot: /kubelet
failSwapOn: false
imageGCHighThresholdPercent: 100
evictionHard:
  memory.available: "${thr}Ki"
  nodefs.available: "0%"
  nodefs.inodesFree: "0%"
  imagefs.available: "0%"
evictionPressureTransitionPeriod: 30s
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
conntrack: {maxPerCore: 0}
EOF
echo "gatherlab: kubeadm $(cat /kind/version) on $ip, eviction-hard memory.available<${thr}Ki (MemTotal ${avail}Ki)"
