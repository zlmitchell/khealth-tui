# The lab's stand-in node: sshd for khealth's probes and gather.sh, with
# the log files of an etcd incident planted at start (plant.sh).
FROM debian:12
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server iproute2 procps curl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /root/.ssh \
 && chmod 700 /root/.ssh
COPY entrypoint.sh plant.sh /usr/local/bin/
ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
