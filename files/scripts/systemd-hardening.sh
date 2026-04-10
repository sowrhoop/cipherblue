#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -oue pipefail

echo "CIPHERBLUE: Applying systemd unit state locks..."

# Operate on systemd units without a running init (Container Build Environment)
export SYSTEMD_OFFLINE=1

# ==============================================================================
# 1. DISABLE & MASK UPSTREAM BLOAT / ATTACK SURFACES
# ==============================================================================
services_to_disable=(
    abrt-journal-core.service
    abrt-oops.service
    abrt-pstoreoops.service
    abrt-vmcore.service
    abrt-xorg.service
    abrtd.service
    alsa-state.service
    atd.service
    avahi-daemon.service
    avahi-daemon.socket
    cups.service
    cups-browsed.service
    debug-shell.service
    emergency.service
    emergency.target
    geoclue.service
    gssproxy.service
    httpd.service
    iscsi-init.service
    iscsi.service
    iscsid.service
    iscsid.socket
    iscsiuio.service
    iscsiuio.socket
    kdump.service
    livesys-late.service
    livesys.service
    low-memory-monitor.service
    mcelog.service
    ModemManager.service
    multipathd.service
    multipathd.socket
    network-online.target
    nfs-idmapd.service
    nfs-mountd.service
    nfs-server.service
    nfsdcld.service
    passim.service
    pcscd.service
    pcscd.socket
    remote-fs.target
    rpc-gssd.service
    rpc-statd.service
    rpc-statd-notify.service
    rpcbind.service
    rpm-ostree-countme.service
    rpm-ostree-countme.timer
    getty@.service
    serial-getty@.service
    smartd.service
    sshd.service
    sssd.service
    sssd-kcm.service
    tailscaled.service
    thermald.service
    uresourced.service
    vboxservice.service
    vmtoolsd.service
    podman-auto-update.timer
    podman-auto-update.service
    systemd-remount-fs.service
)

for service in "${services_to_disable[@]}"; do
    # Suppress errors if the upstream package removed the service entirely
    systemctl disable "$service" >/dev/null 2>&1 || true
    systemctl mask "$service" >/dev/null 2>&1 || true
done

# ==============================================================================
# 2. ENABLE CIPHERBLUE ZERO-TRUST DAEMONS
# ==============================================================================
services_to_enable=(
    cipher-cleaner.service
    fstrim.timer
    rpm-ostreed-automatic.service
    rpm-ostreed-automatic.timer
    tlp.service
    cipher-mount-enforcer.service
    cipher-flatpak-vault.service
    cipher-secure-rebase.service
    cipherblue-sentinel.service
    cipher-cleanup.service
    cipher-cleanup.timer
    cipher-flatpak-update.service
    cipher-flatpak-update.timer
    #cipher-grub-lockdown.service
    cipher-kargs-reconciler.service
    cipher-audit-drift.service
    cipher-audit-drift.timer
    cipher-firmware-update.service
    cipher-firmware-update.timer
    cipher-firstboot-init.service
    #cipher-user-env-lockdown.service
)

for service in "${services_to_enable[@]}"; do
    echo " -> Enabling $service"
    systemctl enable "$service" >/dev/null 2>&1 || true
done

echo "CIPHERBLUE: Systemd states mathematically locked into immutable image."
exit 0
