#!/usr/bin/env bash

set -oue pipefail

# Operate on systemd units without a running init
export SYSTEMD_OFFLINE=1

services=(
    abrt-journal-core.service
    abrt-oops.service
    abrt-pstoreoops.service
    abrt-vmcore.service
    abrt-xorg.service
    abrtd.service
    alsa-state
    atd.service
    avahi-daemon.service
    avahi-daemon.socket
    cups
    cups-browsed
    debug-shell.service
    emergency.service
    emergency.target
    geoclue
    gssproxy
    httpd
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
    ModemManager
    multipathd.service
    multipathd.socket
    network-online.target
    nfs-idmapd
    nfs-mountd
    nfs-server
    nfsdcld
    passim.service
    pcscd.service
    pcscd.socket
    remote-fs.target
    rpc-gssd
    rpc-statd
    rpc-statd-notify
    rpcbind
    rpm-ostree-countme.service
    rpm-ostree-countme.timer
    getty@.service
    serial-getty@.service
    smartd.service
    sshd
    sssd
    sssd-kcm
    tailscaled
    thermald.service
    uresourced.service
    vboxservice.service
    vmtoolsd.service
)

for service in "${services[@]}"; do
        systemctl disable "$service" >/dev/null 2>&1 || true
        systemctl mask "$service" >/dev/null 2>&1 || true
done
 
services=(
    cipher-capabilities
    cipher-cleaner
    cipher-remount
    fstrim.timer
    rpm-ostreed-automatic.timer
    tlp
    fapolicyd
    dnscrypt-proxy
    unbound
    cipher-ima-keys.service
    cipher-privacy.target
    cipher-killswitch.service
)

for service in "${services[@]}"; do
        systemctl enable "$service" >/dev/null 2>&1 || true
done

# Start path unit to enforce /run/user/* noexec on creation
systemctl enable cipher-run-user-sweep.path >/dev/null 2>&1 || true

systemctl --global enable cipher-user-flatpak-updater.service 2>/dev/null || true