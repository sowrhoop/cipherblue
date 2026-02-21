#!/usr/bin/env bash
set -euo pipefail

# Set default shells for non-sysadmin human users to nologin to block terminals.
# Criteria: UID >= 1000, not sysadmin.

NOLOGIN="/usr/sbin/nologin"
[[ -x "$NOLOGIN" ]] || NOLOGIN="/sbin/nologin"

awk -F: '($3 >= 1000) && ($1 != "sysadmin") { print $1 ":" $7 }' /etc/passwd | while IFS=: read -r user shell; do
  # Skip if already nologin
  case "$shell" in
    */nologin) continue ;;
  esac
  usermod -s "$NOLOGIN" "$user" 2>/dev/null || true
done

exit 0

