# The rke2 lab node: rke2-server as a systemd unit from the release
# tarball, as the installer's tar method sets it up, with sshd beside it.
# rke2's layout, as on a server: its own containerd, the kubelet's log in
# agent/logs/kubelet.log, the control plane and etcd as static pods under
# agent/pod-manifests, Canal and the bundled ingress-nginx. systemd runs as
# PID 1 as in the k3s lab (compose.rke2.yaml). Built from gatherlab/ so it
# shares kubeadm/plant.sh.
FROM debian:12
ARG RKE2_VERSION=v1.35.8+rke2r1
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server iproute2 iptables procps curl ca-certificates kmod \
 && rm -rf /var/lib/apt/lists/* \
 && curl -sfL "https://github.com/rancher/rke2/releases/download/$(echo "$RKE2_VERSION" | sed 's/+/%2B/')/rke2.linux-amd64.tar.gz" | tar -xz -C /usr/local \
 && mkdir -p /root/.ssh /etc/rancher/rke2 /etc/systemd/system/rke2-server.service.d && chmod 700 /root/.ssh \
 && systemctl mask getty@tty1.service console-getty.service systemd-logind.service
COPY rke2/lab-setup.sh rke2/lab-ready.sh kubeadm/plant.sh /usr/local/bin/
COPY rke2/lab-setup.service rke2/lab-ready.service rke2/lab-plant.service /etc/systemd/system/
COPY rke2/lab.conf /etc/systemd/system/rke2-server.service.d/lab.conf
RUN chmod +x /usr/local/bin/lab-*.sh /usr/local/bin/plant.sh \
 && systemctl enable ssh rke2-server lab-setup lab-ready lab-plant
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
