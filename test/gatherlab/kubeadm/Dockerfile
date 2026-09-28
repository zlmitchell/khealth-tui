# The kubeadm lab node: kind's node image (what kind and Cluster API's
# Docker provider boot), with sshd added and our own `kubeadm init` unit in
# place of kind's external driver. kubeadm's layout, as on a server: the
# kubelet and containerd as systemd units, the control plane as static pods
# under /etc/kubernetes/manifests, etcd in /var/lib/etcd, pod logs in
# /var/log/pods. kind's entrypoint prepares the container (cgroups, mounts)
# before systemd starts.
ARG KIND_NODE=kindest/node:v1.35.8
FROM ${KIND_NODE}
ARG INGRESS_NGINX=controller-v1.15.1
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /root/.ssh /lab && chmod 700 /root/.ssh
ADD https://raw.githubusercontent.com/kubernetes/ingress-nginx/${INGRESS_NGINX}/deploy/static/provider/baremetal/deploy.yaml /lab/ingress-nginx.yaml
COPY lab-setup.sh lab-kubeadm.sh plant.sh /usr/local/bin/
COPY lab-setup.service lab-kubeadm.service lab-plant.service /etc/systemd/system/
RUN chmod +x /usr/local/bin/lab-*.sh /usr/local/bin/plant.sh \
 && systemctl enable ssh lab-setup lab-kubeadm lab-plant
