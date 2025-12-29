<p align="center">
  <a href="https://github.com/sowrhoop/cipherblue">
    <img src="files/system/usr/share/plymouth/themes/spinner/watermark.png" alt="Cipherblue" width="200" />
  </a>
</p>

<h1 align="center">CIPHERBLUE</h1>

[![Build Status](https://github.com/sowrhoop/cipherblue/actions/workflows/build.yml/badge.svg)](https://github.com/sowrhoop/cipherblue/actions/workflows/build.yml)

Security- and privacy-hardened Fedora Silverblue derivative for desktops, built as an ostree container image. Cipherblue applies a defense-in-depth model inspired by GrapheneOS: strict system hardening, least-privilege defaults, privacy toggles, and verifiable supply-chain signing.

## Table of Contents

- Quick Start
- What You Get
- Security Model
- Accounts & Access
- Installation
- Kernel Parameter Hardening
- Privacy Mode
- VPN Killswitch
- USB Device Control
- GNOME & Portals
- Systemd & Logging
- Kernel & Sysctls
- Verification
- Notes & Opt-Outs
- Build Locally
- Troubleshooting
- Contributing & License

## Quick Start

- Rebase to the latest image (see Installation).
- First boot: existing USB devices are allow-listed; new devices are blocked (USBGuard).
- Privacy mode is enforced (camera/mic/radios blocked). VPN killswitch restricts egress to VPN interfaces.
- Verify hardening (see Verification) and adjust optional toggles as needed.

## What You Get

- Hardened allocator: preloads `libhardened_malloc.so` via `/etc/ld.so.preload`.
- Initramfs hardening: FireWire/Thunderbolt omitted (`/etc/dracut.conf.d/`).
- Module lockdown: `fs.binfmt_misc` disabled on load (`/etc/udev/rules.d/cipherblue.rules`).
- Network hardening: IPv4/IPv6 forwarding off; strict ICMP/TCP; IPv6 privacy; connectivity checks disabled.
- Kernel module policies: uncommon protocols and legacy filesystems denied (`/etc/modprobe.d/99-cipherblue-hardening.conf`, `cipherblue-blacklist.conf`).
- Journald privacy: in-memory logs with tight quotas (`/etc/systemd/journald.conf.d/60-cipherblue-privacy.conf`).
- Systemd sandboxing: curated hardening for core units; safe baseline drop-ins for others.
- USB control: first-boot allow-listing + default block (USBGuard).
- VPN killswitch: nftables default-deny egress except VPN interfaces.
- Kernel args: strong mitigations (apply locally; see Kernel Parameter Hardening).

## Security Model

GrapheneOS-inspired principles applied to Fedora:

- Minimize attack surface
  - Service masking, strict sysctls, USBGuard, kernel module blacklists (`/etc/modprobe.d/99-cipherblue-hardening.conf`).
- Strong sandboxing and least privilege
  - Enforcing SELinux with extra policy, systemd sandbox drop-ins, default-deny execution (fapolicyd), Flatpak/portal lockdowns.
- Hardened memory and mitigations
  - System‑wide hardened_malloc, strict kernel/runtime sysctls, aggressive SUID/SGID reduction.
- Verified system integrity
  - Image signature verification (cosign attachments), optional IMA measurement/appraisal (`/etc/ima/ima-policy`).
- Privacy controls and toggles
  - Cipher Privacy target blocks camera/mic/radios; MAC randomization; local DNS via Unbound tunneled through DNS-over-HTTPS; volatile logs.

Limitations vs GrapheneOS (Android-specific features):

- Hardware-backed keystore, per-app permissions, memory tagging (MTE), exec spawning are Android/Pixel specific. Cipherblue approximates with SELinux, Flatpak portals, hardened malloc, and default-deny execution.
- Verified boot quality depends on Secure Boot + TPM on your platform. Enable them. IMA appraisal is available and recommended.

## Accounts & Access (Zero‑Trust)

- Admin account: `sysadmin` is created at boot (home `/home/sysadmin`) with a minimal PolicyKit allowlist for rpm‑ostree maintenance.
- Other users: may log in locally for desktop use but cannot escalate (no `sudo`, `su`, `pkexec`); PolicyKit actions default to deny.
- PAM access: interactive logins are permitted for local users by default; system/service accounts without valid shells cannot log in.
- Root: direct logins are disabled; rescue media is required for emergencies.
- Rationale: treat all users as untrusted; grant `sysadmin` narrow administrative capabilities only.

Additional confinement:

- Sessions: user processes are killed on logout and IPC is cleaned (`/etc/systemd/logind.conf.d/50-killuser.conf`).
- Rootless containers: disabled by default via delegation restrictions on `user@.service`.
- Unprivileged user namespaces: disabled (`kernel.unprivileged_userns_clone=0`).
- Per-user resources: conservative nproc/nofile caps (`/etc/security/limits.d/60-cipherblue.conf`).
- SSH: remote login effectively limited to `sysadmin` (others receive `nologin`).

Minimal admin capability (sysadmin only):

- Allowed PolicyKit actions (auth required):
  - `org.projectatomic.rpmostree1.bootconfig`
  - `org.projectatomic.rpmostree1.cleanup`
  - `org.projectatomic.rpmostree1.rebase`
- All other PolicyKit actions denied for everyone.
- Root account locked with `cipher-lock-root.service` and restricted shells enforced.

Terminal access policy:

- Non-admin users: login shell is `nologin` by default and enforced at boot for existing accounts (UID >= 1000). Terminal emulators cannot spawn a shell.
- Admin user (`sysadmin`): restricted console allowing only `rpm-ostree` and `flatpak` (plus `exit`/`help`). Remote SSH permitted only for `sysadmin`.
- Virtual consoles: not restricted to a single TTY, but only `sysadmin` can authenticate into a shell. Others receive `nologin`.
- New users: `useradd` defaults to `SHELL=/usr/sbin/nologin`.
 - SSH server policy: `files/system/etc/ssh/sshd_config.d/99-cipherblue.conf` enforces key-only login, `AllowUsers sysadmin`, disables root login and forwarding, and tightens crypto/limits.

## Installation

Rebase an existing Fedora Atomic (e.g., Silverblue) installation to Cipherblue:

1) Upgrade Fedora first

```bash
rpm-ostree upgrade
systemctl reboot
```

2) Bootstrap signing policy (one-time): rebase to the unsigned tag

```bash
rpm-ostree rebase ostree-unverified-registry:ghcr.io/sowrhoop/cipherblue:latest
systemctl reboot
```

3) Rebase to the signed image

```bash
rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sowrhoop/cipherblue:latest
systemctl reboot
```

The `latest` tag points to the newest build. Future updates arrive via `rpm-ostree upgrade`.

To revert: rebase back to upstream Silverblue (adjust to your preferred upstream)

```bash
rpm-ostree rebase ostree-image-signed:docker://quay.io/fedora/fedora-silverblue:latest
systemctl reboot
```

## Kernel Parameter Hardening

Kernel args are included in-tree via bootc kargs (`/usr/lib/bootc/kargs.d/10-cipherblue.toml`) and applied when the image deploys. The snippet below remains for manual adjustment on existing systems or for additional toggles. They persist across deployments.

Option A - apply after install/rebase (recommended):

```bash
sudo bash -euo pipefail -c '
args=(
  amd_iommu=force_isolation
  debugfs=off
  efi=disable_early_pci_dma
  extra_latent_entropy
  gather_data_sampling=force
  ia32_emulation=0
  init_on_alloc=1
  init_on_free=1
  intel_iommu=on
  iommu.passthrough=0
  iommu.strict=1
  iommu=force
  ipv6.disable=1
  kvm.nx_huge_pages=force
  l1d_flush=on
  l1tf=full,force
  lockdown=confidentiality
  loglevel=0
  kvm-intel.vmentry_l1d_flush=always
  mds=full,nosmt
  mitigations=auto,nosmt
  module.sig_enforce=1
  nosmt=force
  oops=panic
  page_alloc.shuffle=1
  pti=on
  random.trust_bootloader=off
  random.trust_cpu=off
  randomize_kstack_offset=on
  reg_file_data_sampling=on
  slab_nomerge
  slub_debug=ZF
  spec_rstack_overflow=safe-ret
  spec_store_bypass_disable=on
  spectre_bhi=on
  spectre_v2=on
  tsx=off
  tsx_async_abort=full,nosmt
  vsyscall=none
  page_poison=1
  ftrace=off
  rd.shell=0
  rd.emergency=halt
  lsm=lockdown,yama,selinux,bpf
)
for a in "${args[@]}"; do
  rpm-ostree kargs --append-if-missing="$a" || true
done

# Optional toggles
if [ -f /etc/system-fips ] || [ -f /etc/cipherblue/fips.enabled ]; then
  rpm-ostree kargs --append-if-missing=fips=1 || true
fi
if [ -f /etc/cipherblue/ima.enforce ]; then
  rpm-ostree kargs --append-if-missing=ima_appraise=enforce || true
fi'

sudo systemctl reboot
```

Option B - apply before rebasing (optional): run the same snippet on your current rpm-ostree system, then rebase. Reboot to apply.

## Privacy Mode

Cipher Privacy is enforced at boot: blocks camera/mic drivers, disables Bluetooth/WWAN radios, and pulls in the VPN killswitch.

- Runtime-blacklists `uvcvideo`, `snd_usb_audio`, `snd_hda_intel`, `v4l2loopback` via `/run/modprobe.d/cipher-privacy.conf` (unloads if present).
- Runs `rfkill block bluetooth` and `rfkill block wwan`.
- Pulls in `cipher-killswitch.service`.

Disable temporarily by stopping `cipher-privacy.target` (not recommended); persistent enforcement is the default.

## VPN Killswitch

Default-deny outbound traffic except loopback and allowed VPN interfaces.

- Configure interfaces: edit `/etc/cipherblue/killswitch.conf` (default `ALLOWED_IFACES="wg0 tun0 tap0"`).
- Enable/disable: `systemctl enable --now cipher-killswitch.service` / `systemctl disable --now cipher-killswitch.service`.
- Verify rules: `nft list table inet cipher_ks`.

## USB Device Control

USBGuard initializes safely on first boot.

- First boot: `cipher-usbguard-setup.service` generates `/etc/usbguard/rules.conf` from present devices and enables `usbguard-daemon`.
- Regenerate rules: `rm -f /etc/usbguard/rules.conf && systemctl start cipher-usbguard-setup.service`.
- Inspect: `usbguard list-devices`, `usbguard list-rules`.

## GNOME & Portals

- Dconf defaults and locks: camera/mic disabled; immediate lock; no lock-screen notifications; external search providers disabled.
- Portals: GNOME ScreenCast / RemoteDesktop disabled (`/usr/share/xdg-desktop-portal/gnome-portals.conf`).
- NetworkManager: connectivity checks disabled (`/etc/NetworkManager/conf.d/99-disable-connectivity.conf`).
- Tracker indexer: disabled via dconf with locks. Rebuild dconf if adjusting locally: `sudo dconf update`.

## Systemd & Logging

- Global defaults: resource accounting, no core dumps, sane timeouts for system/user services.
- Curated hardening: drop-ins under `/etc/systemd/system/*/cipherblue.conf` for sensitive services; safe baseline for others generated at build.
- Journald: in-memory logs, strict quotas (`/etc/systemd/journald.conf.d/60-cipherblue-privacy.conf`).

Assess a service: `systemd-analyze security <unit>`.

## Kernel & Sysctls

- Kernel args: apply locally (see Kernel Parameter Hardening).
- Sysctls: strict ICMP/TCP, forwarding off, io_uring disabled, ptrace/perf restricted, `kernel.kexec_file_load_only=1`.
- `fs.binfmt_misc` disabled by udev rule when loaded.

## Verification

- Allocator: `cat /etc/ld.so.preload` should reference `libhardened_malloc.so`.
- Kargs: `rpm-ostree kargs | tr ' ' '\n' | sort`.
- Journald: `systemd-analyze cat-config systemd/journald.conf`.
- Sysctl: `sysctl kernel.io_uring_disabled`, `sysctl net.ipv4.ip_forward`, `sysctl net.ipv6.conf.all.forwarding`.
- USBGuard: `systemctl status usbguard-daemon`, `usbguard list-rules`.
- Killswitch: `nft list table inet cipher_ks`.
- Account policy: `grep -v '^#' /etc/security/access.conf`, `getent passwd sysadmin`, review `/etc/polkit-1/rules.d/`.

## Notes & Opt‑Outs

- Hardened allocator: rarely, apps may misbehave. To disable system-wide, edit `/etc/ld.so.preload` (remove hardened_malloc).
- Thunderbolt/FireWire: if needed at boot, remove dracut omissions in `/etc/dracut.conf.d/` and rebuild initramfs.
- Connectivity checks: re-enable by removing `/etc/NetworkManager/conf.d/99-disable-connectivity.conf`.

Flatpak hardening example:

```bash
flatpak remote-delete --system --force fedora || true
flatpak remote-delete --system --force fedora-testing || true
flatpak remote-delete --user --force fedora || true
flatpak remote-delete --user --force fedora-testing || true
flatpak remote-delete --system --force flathub || true
flatpak remote-delete --user --force flathub || true
flatpak uninstall --delete-data --all -y || true
rm -rf /var/lib/flatpak/.removed || true
```

Fstab hardening example:

```bash
sed -i 's/zstd:1/zstd/g' /etc/fstab

FILE="/etc/fstab"
if ! grep -q 'x-systemd.device-timeout=0,nosuid,noexec,nodev,noatime' "$FILE"; then
  sed -i -e 's/x-systemd.device-timeout=0/x-systemd.device-timeout=0,nosuid,noexec,nodev,noatime/' \
         -e 's/shortname=winnt/shortname=winnt,nosuid,noexec,nodev,noatime/' \
         -e 's/compress=zstd/compress=zstd,nosuid,noexec,nodev,noatime/' \
         -e 's/defaults/defaults,nosuid,noexec,nodev,noatime/' "$FILE"
fi
```

Microcode updates:

```bash
fwupdmgr refresh --force
fwupdmgr get-updates
fwupdmgr update
```

Other system tweaks (optional):

```bash
# Cleanup coredumps
ulimit -c 0
systemd-tmpfiles --clean 2>/dev/null || true
systemctl daemon-reload

# Disable system tracking identifiers
hostnamectl set-hostname host
new_machine_id="b08dfa6083e7567a1921a715000001fb"
echo "$new_machine_id" | tee /etc/machine-id >/dev/null
echo "$new_machine_id" | tee /var/lib/dbus/machine-id >/dev/null

# Block wireless devices (except Wi-Fi)
rfkill block all || true
rfkill unblock wifi || true

# Lock down root
passwd -l root || true

# GNOME and GRUB hardening helpers
dconf update || true
grub2-setpassword || true
```

Secure verified‑FOSS Flatpak repo:

```bash
flatpak remote-add --if-not-exists --user --subset=verified_floss \
  flathub-verified-floss https://dl.flathub.org/repo/flathub.flatpakrepo
```

SELinux confined users (experimental):

```bash
semanage login -a -s user_u -r s0 gdm
semanage login -m -s user_u -r s0 __default__
semanage login -m -s sysadm_u -r s0 root
semanage login -a -s sysadm_u -r s0 sysadmin
```

## Build Locally

This repository is built via GitHub Actions using the BlueBuild action. To build locally:

Prerequisites: Podman (or Docker), and the BlueBuild CLI.

```bash
# Example with bluebuild (see https://github.com/blue-build/cli)
bluebuild build recipes/cipherblue.yml
```

The recipe installs hardened_malloc, usbguard, unbound, and fapolicyd, removes unneeded packages, applies files under `files/system`, then signs the image with cosign metadata so rpm‑ostree can verify it.

## Troubleshooting

- App incompatibility with hardened_malloc: temporarily remove it from `/etc/ld.so.preload` to confirm; report upstream.
- USB device blocked: review `usbguard list-devices` and adjust `/etc/usbguard/rules.conf` (regenerate via `cipher-usbguard-setup.service`).
- No network egress: ensure your VPN interface matches `ALLOWED_IFACES` or temporarily disable `cipher-killswitch.service` for debugging.
- Rebase issues: bootstrap using the unsigned tag first, then switch to the signed tag as shown in Installation.

## Contributing & License

Issues and PRs are welcome. Keep changes minimal, focused, and aligned with the hardening strategy. Shell scripts should use `set -euo pipefail` and avoid unnecessary complexity.

Licensed under the GNU Affero General Public License v3. See `LICENSE`.

Security notice: this project hardens a general‑purpose system. Test on non‑production machines first. No warranty.