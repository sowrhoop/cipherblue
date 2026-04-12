#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

source /usr/libexec/cipherblue/cipher-core.sh

DRIFT=$(diff -r \
      --suppress-common-lines \
      --exclude="passwd*" --exclude="group*" --exclude="subgid*" \
      --exclude="subuid*" --exclude="machine-id" --exclude="adjtime" \
      --exclude="fstab" --exclude="system-connections" --exclude="shadow*" \
      --exclude="gshadow*" --exclude="ssh_host*" --exclude="cmdline" \
      --exclude="crypttab" --exclude="hostname" --exclude="localtime" \
      --exclude="locale*" --exclude="*lock" --exclude=".updated" \
      --exclude="*LOCK" --exclude="vconsole*" --exclude="00-keyboard.conf" \
      --exclude="grub" --exclude="system.control*" --exclude="cdi" \
      --exclude="default.target" --exclude="polkit-1" --exclude="cipherblue" \
      /usr/etc /etc 2>/dev/null | sed '/Binary\ files\ /d' || true)

if [[ -n "$DRIFT" ]]; then
    notify_ui "🚨 Configuration Drift Detected" "A critical system file in /etc has been modified from the immutable baseline! Potential tamper event." "dialog-error" "critical"
    cipher_log "DRIFT LOG: $DRIFT"
else
    exit 0
fi