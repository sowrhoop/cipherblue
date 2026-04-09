#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

source /usr/libexec/cipherblue/cipher-core.sh

# 1. Wait for true network connectivity
until curl -s https://dl.flathub.org > /dev/null; do sleep 5; done

cipher_log "Checking for cryptographically verified application updates..."

# 2. Unpin any manually pinned runtimes to enforce strict GitOps state
/usr/bin/flatpak pin 2>/dev/null | awk 'NR>1 {print $1}' | while read -r pattern; do
    if [[ -n "$pattern" ]]; then
        /usr/bin/flatpak pin --remove "$pattern" >/dev/null 2>&1 || true
    fi
done

# 3. Execute the maintenance chain silently
if /usr/bin/flatpak --system update -y --noninteractive && \
   /usr/bin/flatpak --system uninstall --unused -y --noninteractive --delete-data && \
   /usr/bin/flatpak --system repair; then
    cipher_log "Maintenance Complete. All applications updated and orphaned data destroyed."
    exit 0
else
    notify_ui "⚠️ Maintenance Alert" "An error occurred while updating applications in the background." "dialog-error" "critical"
    exit 1
fi