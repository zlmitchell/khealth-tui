# The lab node: k3s as a systemd unit, as on a real server, with sshd, so
# khealth's SSH side reaches the node the API describes (journald, crictl
# and the image store, pod logs, embedded etcd). systemd runs as PID 1 the
# way kind's node image does: privileged, the host cgroup namespace, tmpfs
# /run (compose.yaml).
FROM debian:12
ARG K3S_VERSION=v1.33.4+k3s1
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server iproute2 procps curl ca-certificates kmod \
 && rm -rf /var/lib/apt/lists/* \
 && curl -sfL "https://github.com/k3s-io/k3s/releases/download/$(echo "$K3S_VERSION" | sed 's/+/%2B/')/k3s" -o /usr/local/bin/k3s \
 && chmod +x /usr/local/bin/k3s \
 && ln -s /usr/local/bin/k3s /usr/local/bin/kubectl \
 && ln -s /usr/local/bin/k3s /usr/local/bin/crictl \
 && mkdir -p /root/.ssh /etc/rancher/k3s && chmod 700 /root/.ssh \
 && systemctl mask getty@tty1.service console-getty.service systemd-logind.service
COPY lab-setup.sh plant.sh /usr/local/bin/
COPY k3s.service lab-setup.service lab-plant.service /etc/systemd/system/
RUN systemctl enable ssh k3s lab-setup lab-plant
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
