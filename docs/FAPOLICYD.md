# fapolicyd and Kubernetes installs on STIG-hardened RHEL

The RHEL 9 STIG (V-258019 / `service_fapolicyd_enabled`) requires `fapolicyd` running in enforcing mode. fapolicyd is an application allow-list: every `execve` (and every `open` of a script by an interpreter) is checked against `/etc/fapolicyd/rules.d/*.rules`, and the stock rule set boils down to *"root may run anything that is trusted; nothing untrusted executes."*

**Trusted** means one of:

1. the file is owned by an installed RPM (the rpmdb is a trust source), or
2. its path + size + SHA-256 is listed in `/etc/fapolicyd/trust.d/*` or `/etc/fapolicyd/fapolicyd.trust`.

Everything a Kubernetes distribution downloads, extracts or generates at runtime is neither, so it is denied — silently unless you know where to look. This doc lists what breaks per install method and the existing ways to fix it. Method A is what the STIG-hardened lab hosts use.

## What is and is not mediated

fapolicyd only watches the filesystems named in `watch_fs` in `/etc/fapolicyd/fapolicyd.conf` (`ext4,xfs,tmpfs,btrfs,ext2,ext3,zfs` by default). **`overlay` is not in the list**, so processes *inside containers* (whose rootfs is an overlay mount) are never checked. Only host-side binaries matter:

| Component | Path | Trusted? |
|---|---|---|
| `rke2` binary (RPM install) | `/usr/bin/rke2` | yes (rpm) |
| `rke2` binary (tarball / installer image) | `/usr/local/bin/rke2` or `/opt/rke2/bin/rke2` | **no** |
| RKE2 runtime: containerd, containerd-shim, runc, kubelet, kubectl, crictl | `/var/lib/rancher/rke2/data/<sha256>/bin/` — extracted from the `rke2-runtime` image on first start, new dir every upgrade | **no** |
| RKE2 CNI plugins | `/var/lib/rancher/rke2/data/<sha256>/bin/` and `/opt/cni/bin/` (populated by the CNI chart's init container) | **no** |
| kubeadm / kubelet / kubectl / containerd / runc (pkgs.k8s.io + docker-ce RPMs) | `/usr/bin/` | yes (rpm) |
| CNI plugins installed by Flannel / Calico / Cilium DaemonSets | `/opt/cni/bin/` | **no** |
| Helm, kubectl plugins, anything `curl | sh` puts in `/usr/local/bin` | `/usr/local/bin/` | **no** |
| kubelet ephemeral scripts, CSI node drivers writing helper binaries | `/var/lib/kubelet/` | **no** |

Symptom: `systemctl start rke2-server` fails with `Permission denied` on the binary; with the RPM install the binary starts but the node never becomes Ready because containerd/kubelet in `data/<sha>/bin` are denied; with kubeadm the API server comes up but pods stay `ContainerCreating` because the CNI plugin binary is denied. `journalctl -u fapolicyd` and `ausearch -m fanotify -ts recent` show the denials:

```
type=FANOTIFY msg=audit(...): resp=2   # 2 = deny
 ... exe="/var/lib/rancher/rke2/data/3f2.../bin/containerd" ...
```

Turn on `--debug-deny` for the full rule trace: `fapolicyd --debug-deny` in the foreground, or `sed -i 's/^#*\s*debug.*/debug = 2/' /etc/fapolicyd/fapolicyd.conf` (noisy — turn it off after).

## Method A — path rules (`rules.d`) — the usual choice

Rancher's RKE2 STIG guidance takes this route: allow execution from the directories the distribution owns, in a rule file that sorts **before** `90-deny-execute.rules`.

```sh
cat >/etc/fapolicyd/rules.d/81-rke2-local.rules <<'EOF'
# RKE2 / Kubernetes host-side binaries (Rancher STIG guidance). Everything under these
# trees is either the rke2 binary itself or extracted from images RKE2 pulled.
allow perm=any all : dir=/usr/local/bin/
allow perm=any all : dir=/opt/rke2/
allow perm=any all : dir=/var/lib/rancher/
allow perm=any all : dir=/opt/cni/
allow perm=any all : dir=/var/lib/kubelet/
allow perm=any all : dir=/run/k3s/
EOF
chmod 644 /etc/fapolicyd/rules.d/81-rke2-local.rules
fagenrules --check && fagenrules --load     # compiles rules.d/* into /etc/fapolicyd/compiled.rules
systemctl restart fapolicyd
```

**Why `81-rke2-local.rules` and not `80-rke2.rules`:** RKE2's own `install.sh` (`setup_fapolicy_rules`) writes `/etc/fapolicyd/rules.d/80-rke2.rules` itself on every run on a RHEL-family host with fapolicyd active — exactly four lines (`/var/lib/rancher/`, `/opt/cni/`, `/run/k3s/`, `/var/lib/kubelet/`), overwriting whatever was there. On a Rancher-provisioned node that installer runs again from the `system-agent-installer-rke2` image on **every plan apply** (any cluster-spec edit), with `INSTALL_RKE2_SKIP_RELOAD` set, so the file changes and `compiled.rules` goes stale until the next `fagenrules --load`. Observed 2026-09-21 on the `baremetal-a` lab node: the hardening's `/usr/local/bin/` and `/opt/rke2/` allows vanished after the first config change (root could still execute `/usr/local/bin/rke2`, an unprivileged user could not). Keep the additions in a file the installer does not own; treat `80-rke2.rules` as RKE2's.

For upstream kubeadm nodes drop the rke2/rancher lines and keep `/opt/cni/`, `/var/lib/kubelet/` and (if you install Helm or kubectl plugins there) `/usr/local/bin/`.

Pros: survives upgrades (new `data/<sha>` directories are covered), one-time. Cons: it is a path allow-list — anyone who can write to `/var/lib/rancher` or `/usr/local/bin` as root can execute there, which is what fapolicyd was meant to stop. Those paths are root-owned 0755 or stricter, so the trust boundary is unchanged for non-root, and root already gets `allow perm=any uid=0 trust=1 : all`. Document it as a deviation from the letter of the rule.

`fapolicyd-cli --check-config` validates the file; `fapolicyd-cli --list` shows the merged order — your rules must appear before `deny_audit perm=execute all : all`.

## Method B — trust file (hash allow-list)

Keeps the strict model: each binary is trusted by content hash.

```sh
# after install.sh / installer.sh, before first start
fapolicyd-cli --file add /usr/local/bin/rke2                 --trust-file rke2
# after first start (runtime extracted) — and again after EVERY upgrade
fapolicyd-cli --file add /var/lib/rancher/rke2/data/         --trust-file rke2
fapolicyd-cli --file add /opt/cni/bin/                       --trust-file cni
fapolicyd-cli --update                                       # reload trust db, no restart needed
fapolicyd-cli --check-trustdb                                # reports files whose hash no longer matches
```

Entries land in `/etc/fapolicyd/trust.d/rke2` as `path size sha256`. The catch is ordering: the runtime binaries do not exist until `rke2-server` has started once, and it cannot start its runtime while they are untrusted. Either start with Method A rules in place, trust the directory, then remove the rules; or pre-extract the runtime (`rke2 server --help` does not do it; there is no offline unpack command). In practice this is only workable if a config management tool re-runs `--file add` after each `rke2` upgrade, and CNI upgrades pushed by the chart replace `/opt/cni/bin` behind your back. Use it where the site policy forbids path-based allow rules.

## Method C — RPM install of everything

RPMs are trusted automatically. `curl https://get.rke2.io | sh -` on a host with `yum` defaults to the RPM method (`rke2-server`, `rke2-common`, `rke2-selinux` from `rpm.rancher.io`), and kubeadm/kubelet/containerd from `pkgs.k8s.io` and Docker's repo are RPMs.

This covers the launcher only. RKE2 still extracts its runtime into `/var/lib/rancher/rke2/data` and the CNI still writes `/opt/cni/bin`, so you need A or B for those anyway. An install from the system-agent installer image forces the *tar* method (`INSTALL_RKE2_ARTIFACT_PATH`), so there the launcher is untrusted too — install `rke2-selinux` from the RPM repo first (for the SELinux policy) and use Method A.

## Method D — disable fapolicyd (documented deviation)

GPU nodes are often run with fapolicyd masked: DKMS rebuilds produce new kernel modules and CUDA produces fresh ELF binaries that would need re-trusting on every driver update. That is a legitimate STIG deviation when documented for that node class; it is *not* applied on the STIG evaluation hosts here, since the point of those is to see what a compliant node looks like to `khealth`.

## Checklist for a new node

1. `rke2-selinux` / `container-selinux` from the RPM repo (SELinux policy — unrelated to fapolicyd but the same "install before first start" timing).
2. Write `81-rke2-local.rules` (or the kubeadm subset), `fagenrules --load`, `systemctl restart fapolicyd`.
3. Install the distribution (image export + `installer.sh`, or RPM, or kubeadm).
4. Start it. If it does not come up, `ausearch -m fanotify -ts recent -i | grep -E 'exe=|resp='` before anything else.
5. After upgrades with Method B: re-run `fapolicyd-cli --file add` and `--update`.

`khealth`'s Node tab shows fapolicyd state under hardening; the OS STIG tab evaluates `service_fapolicyd_enabled` and `package_fapolicyd_installed` — both still pass with Method A rules in place, and a masked daemon (Method D) fails both.
