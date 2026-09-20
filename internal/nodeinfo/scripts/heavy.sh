# Heavy node probe: images, containers, tarball manifests, PV du, journal
# and log files. Runs every heavy_every refreshes or on R. Placeholders
# __LINES__, __SINCE__, __KNOWN__, __PVPATHS__ are substituted by
# nodeinfo.Script.
#
# Sent to nodes over SSH by khealth as `sudo sh -s`; POSIX sh only (dash on
# Ubuntu, busybox on Flatcar). Embedded into the Go binary with //go:embed -
# edit here, not in the .go file. Sections are delimited by `sec NAME`
# (===NAME lines) and parsed by the Go side; keep names in sync with the
# parser. Never print secrets: pass file dumps through `mask`.
sec CRICTL
# CRICTL, CRI and runcri come from base.sh
echo "crictl=$CRICTL cri=$CRI"
sec IMAGES
# preflight.sh already listed the images for the registry pull dry run
if [ -n "$CRIIMG" ]; then printf '%s\n' "$CRIIMG"; elif [ -n "$CRICTL" ]; then runcri images -o json 2>/dev/null; fi
sec CONTAINERS
[ -n "$CRICTL" ] && runcri ps -o json 2>/dev/null
sec TARBALLS
KNOWN='|__KNOWN__|'
for IMGDIR in /var/lib/rancher/rke2/agent/images /var/lib/rancher/k3s/agent/images; do
  [ -d "$IMGDIR" ] || continue
  for f in "$IMGDIR"/*; do
    [ -f "$f" ] || continue
    sz=$(stat -c %s "$f" 2>/dev/null); mt=$(stat -c %Y "$f" 2>/dev/null)
    echo "--- $f|$sz|$mt"
    case "$KNOWN" in *"|$f|$sz|$mt|"*) echo "(cached)"; continue;; esac
    case "$f" in
      *.txt) cat "$f";;
      *.tar) tar -xOf "$f" manifest.json 2>/dev/null;;
      *.tar.zst) command -v zstd >/dev/null 2>&1 && zstd -dc "$f" 2>/dev/null | tar -xO manifest.json 2>/dev/null;;
      *.tar.gz|*.tgz) gzip -dc "$f" 2>/dev/null | tar -xO manifest.json 2>/dev/null;;
    esac
    echo
  done
done
sec PVDU
# hostPath/local PVs (e.g. local-path-provisioner): the kubelet has no metrics
# for them, so measure the directories directly
for d in __PVPATHS__; do
  [ -d "$d" ] || continue
  u=$(timeout 60 du -skx "$d" 2>/dev/null | cut -f1)
  [ -n "$u" ] && echo "$u|$d"
done
sec JOURNAL
journalctl --no-pager -o short-iso -q -n __LINES__ --since '__SINCE__' -u rke2-server -u rke2-agent -u k3s -u k3s-agent -u kubelet -u containerd -u rancher-system-agent -u etcd 2>/dev/null
sec LOGFILES
# rke2 runs the kubelet and containerd as child processes that log to files,
# not to the journal: take the same tail as the journal so they classify alike
for f in /var/lib/rancher/rke2/agent/logs/kubelet.log /var/lib/rancher/rke2/agent/containerd/containerd.log /var/lib/rancher/k3s/agent/containerd/containerd.log; do
  [ -f "$f" ] || continue
  echo "--- $f"
  tail -n __LINES__ "$f" 2>/dev/null
done
