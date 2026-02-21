#!/usr/bin/env bash

set -oue pipefail

chmod 700 /usr/bin/cipher-capabilities
chmod 755 /usr/libexec/cipherblue/remount-run-user
chmod 755 /usr/libexec/cipherblue/immutable-lock.sh
chmod 755 /usr/libexec/cipherblue/lock-root.sh
chmod 755 /etc/profile.d/cipherblue_umask.sh
chmod 755 /usr/libexec/cipherblue/lockdown-shells.sh
chmod 755 /usr/libexec/cipherblue/sysadmin-shell
echo "" > /etc/securetty
echo 'UriSchemes=file;https' | tee -a /etc/fwupd/fwupd.conf >/dev/null

umask 077
sed -i 's/^UMASK.*/UMASK 077/g' /etc/login.defs || true
sed -i 's/^HOME_MODE/#HOME_MODE/g' /etc/login.defs || true
sed -i 's/umask 022/umask 077/g' /etc/bashrc || true
if [ -f /etc/pam.d/system-auth ]; then
  sed -i 's/\s\+nullok//g' /etc/pam.d/system-auth || true
fi
if [ -f /etc/firewalld/firewalld.conf ]; then
  sed -i 's@DefaultZone=FedoraWorkstation@DefaultZone=drop@g' /etc/firewalld/firewalld.conf || true
fi
if [ -f /usr/lib/systemd/system/dev-hugepages.mount ]; then
  sed -i 's/nosuid,nodev/nosuid,noexec,nodev/' /usr/lib/systemd/system/dev-hugepages.mount || true
fi
if [ -f /usr/lib/systemd/system/tmp.mount ]; then
  sed -i 's/nosuid,nodev/nosuid,noexec,nodev/' /usr/lib/systemd/system/tmp.mount || true
fi