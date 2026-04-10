#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# 1. Check if the lockdown is already active (to prevent regenerating on every boot)
if [ -f /boot/grub2/user.cfg ] || [ -f /boot/efi/EFI/fedora/user.cfg ]; then
    exit 0
fi

echo "CIPHERBLUE: Unsecured bootloader detected. Initiating GRUB Lockdown..."

# 2. Generate a 128-character mathematically unguessable password
# CRITICAL SRE FIX: Temporarily disable pipefail. 
# 'tr' reading from /dev/urandom is an infinite stream. 'head' closes the pipe after 128 bytes.
# This causes 'tr' to receive SIGPIPE and exit with code 141.
# With 'set -o pipefail' active, this instantly crashed the script!
set +o pipefail
while true; do
    RANDOM_PASS=$(tr -dc 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*' < /dev/urandom | head -c 128)
    
    # Mathematical verification of the minimum constraints
    if echo "$RANDOM_PASS" | grep -q '[abcdefghijkmnopqrstuvwxyz]' && \
       echo "$RANDOM_PASS" | grep -q '[ABCDEFGHJKLMNPQRSTUVWXYZ]' && \
       echo "$RANDOM_PASS" | grep -q '[23456789]' && \
       echo "$RANDOM_PASS" | grep -q '[!@#$%^&*]'; then
        break
    fi
done
# Re-enable strict pipe failure detection for the rest of the script
set -o pipefail

# 3. Feed the password directly into the native Fedora GRUB utility
# CRITICAL SRE FIX: Replaced 'echo -e' pipe with a Here-Doc.
# Systemd runs without a TTY. 'echo' pipes cause race conditions with interactive wrappers.
/usr/sbin/grub2-setpassword <<EOF
$RANDOM_PASS
$RANDOM_PASS
EOF

echo "CIPHERBLUE: GRUB successfully locked. rd.break root bypass is now mathematically impossible."
exit 0
