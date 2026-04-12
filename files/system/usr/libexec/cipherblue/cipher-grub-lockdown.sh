#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# 1. Check if the lockdown is already active
if [ -f /boot/grub2/user.cfg ] || [ -f /boot/efi/EFI/fedora/user.cfg ]; then
    exit 0
fi

echo "CIPHERBLUE: Unsecured bootloader detected. Initiating GRUB Lockdown..."

# 2. Generate a 128-character mathematically unguessable password
set +o pipefail
while true; do
    # Added 2>/dev/null to cleanly silence the broken pipe warning from the infinite urandom stream
    RANDOM_PASS=$(tr -dc 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*' < /dev/urandom 2>/dev/null | head -c 128)
    
    if echo "$RANDOM_PASS" | grep -q '[abcdefghijkmnopqrstuvwxyz]' && \
       echo "$RANDOM_PASS" | grep -q '[ABCDEFGHJKLMNPQRSTUVWXYZ]' && \
       echo "$RANDOM_PASS" | grep -q '[23456789]' && \
       echo "$RANDOM_PASS" | grep -q '[!@#$%^&*]'; then
        break
    fi
done
set -o pipefail

echo "CIPHERBLUE: Hashing password securely (bypassing interactive stty trap)..."

# 3. Native Hash Generation
# We feed the password twice to the native C-binary and extract ONLY the resulting hash
RAW_OUTPUT=$(echo -e "$RANDOM_PASS\n$RANDOM_PASS" | /usr/bin/grub2-mkpasswd-pbkdf2)
GRUB_HASH=$(echo "$RAW_OUTPUT" | awk '/grub\.pbkdf2/ {print $NF}')

if [[ -z "$GRUB_HASH" ]]; then
    echo "CIPHERBLUE: FATAL: Failed to extract GRUB PBKDF2 hash."
    exit 1
fi

# 4. Write the immutable config natively
cat <<EOF > /boot/grub2/user.cfg
GRUB2_PASSWORD=$GRUB_HASH
EOF

# Lock permissions to root only
chmod 600 /boot/grub2/user.cfg

echo "CIPHERBLUE: GRUB successfully locked. rd.break root bypass is now mathematically impossible."
exit 0
