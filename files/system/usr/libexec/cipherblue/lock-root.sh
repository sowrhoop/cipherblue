#!/usr/bin/env bash
set -euo pipefail

# Lock the root account for interactive auth and set nologin shell.

# Lock password and disable interactive login
passwd -l root 2>/dev/null || true

# Set shell to nologin (path may vary)
SHELL_BIN="/sbin/nologin"
[[ -x "$SHELL_BIN" ]] || SHELL_BIN="/usr/sbin/nologin"
usermod -s "$SHELL_BIN" root 2>/dev/null || true

# Expire the account to prevent password aging from re-enabling
chage -E 1 root 2>/dev/null || true

exit 0

