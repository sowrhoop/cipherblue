#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# 1. Basic System Hardening
chmod 755 /etc/profile.d/cipherblue_umask.sh
echo "" > /etc/securetty
echo 'UriSchemes=file;https' | tee -a /etc/fwupd/fwupd.conf >/dev/null

# 2. Strict Umask & Login Defaults
umask 077
sed -i 's/^UMASK.*/UMASK 077/g' /etc/login.defs || true
sed -i 's/^HOME_MODE/#HOME_MODE/g' /etc/login.defs || true
sed -i 's/umask 022/umask 077/g' /etc/bashrc || true

# 3. Authentication & Firewall Hardening
if [ -f /etc/pam.d/system-auth ]; then
  sed -i 's/\s\+nullok//g' /etc/pam.d/system-auth || true
fi
if [ -f /etc/firewalld/firewalld.conf ]; then
  sed -i 's@DefaultZone=FedoraWorkstation@DefaultZone=drop@g' /etc/firewalld/firewalld.conf || true
fi

# ==============================================================================
# CIPHERBLUE INTERNAL LOGIC HARDENING
# Restricts access to sensitive automation scripts to root only.
# ==============================================================================
echo "CIPHERBLUE: Applying zero-trust permissions to internal libexec scripts..."

TARGETS=(
    "/usr/libexec/cipherblue/cipher-flatpak-vault.sh"
    "/usr/libexec/cipherblue/cipher-secure-rebase.sh"
    "/usr/libexec/cipherblue/verify-provenance.sh"
    "/usr/libexec/cipherblue/sentinel-daemon.sh"
    "/usr/libexec/cipherblue/cipher-cleanup.sh"
    "/usr/libexec/cipherblue/cipher-flatpak-update.sh"
    "/usr/libexec/cipherblue/cipher-grub-lockdown.sh"
    "/usr/libexec/cipherblue/cipher-kargs-reconciler.sh"
    "/usr/libexec/cipherblue/cipher-audit-drift.sh"
    "/usr/libexec/cipherblue/cipher-firmware-update.sh"
    "/usr/libexec/cipherblue/cipher-firstboot-init.sh"
    "/usr/libexec/cipherblue/cipher-core.sh"
    "/usr/libexec/cipherblue/cipher-user-env-lockdown.sh"
)

for script in "${TARGETS[@]}"; do
    if [[ -f "$script" ]]; then
        chmod 700 "$script"
        chown root:root "$script"
    fi
done

exit 0