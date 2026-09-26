#!/bin/sh
# A throwaway key pair in the shared out/ directory: khealth logs in with
# out/id_lab, so nobody's own key is involved.
set -e
if [ ! -s /out/id_lab ]; then
  rm -f /out/id_lab /out/id_lab.pub
  ssh-keygen -q -t ed25519 -N '' -C khealth-gatherlab -f /out/id_lab
  chmod 644 /out/id_lab # read by khealth from the host / the check container
fi
cp /out/id_lab.pub /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
sh /usr/local/bin/plant.sh lab-node
exec /usr/sbin/sshd -D -e
