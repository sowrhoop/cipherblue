#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# 1. Check if the lockdown is already active (to prevent regenerating on every boot)
if [ -f /boot/grub2/user.cfg ] || [ -f /boot/efi/EFI/fedora/user.cfg ]; then
    exit 0
fi

echo "CIPHERBLUE: Unsecured bootloader detected. Initiating GRUB Lockdown..."

# 2. Generate a 128-character mathematically unguessable password
# - Length: 128
# - Includes: A-Z, a-z, 0-9, !@#$%^&*
# - Excludes ambiguous characters: l, 1, I, O, 0
# - Enforces at least 1 lowercase, 1 uppercase, 1 digit, and 1 special character
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

# 3. Feed the password directly into the native Fedora GRUB utility
# This securely hashes it using PBKDF2 and creates the /boot/grub2/user.cfg file
echo -e "$RANDOM_PASS\n$RANDOM_PASS" | /usr/sbin/grub2-setpassword

echo "CIPHERBLUE: GRUB successfully locked. rd.break root bypass is now mathematically impossible."
exit 0