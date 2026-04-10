#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# CIPHERBLUE KERNEL IMMUTABILITY ENGINE (v4.0 - STRICT WHITELIST)
# Enforces a strict Default-Deny policy on the user's home directory.
# Purges all unapproved dotfiles/directories and mathematically freezes the 
# directory nodes to prevent any future creation of non-whitelisted paths.

set -euo pipefail
source /usr/libexec/cipherblue/cipher-core.sh

cipher_log "Engaging v4.0 Strict Whitelist Immutability Engine..."

mapfile -t HUMAN_USERS < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

for user in "${HUMAN_USERS[@]}"; do
    user_home="$(getent passwd "$user" | cut -d: -f6)"
    if [ ! -d "$user_home" ]; then continue; fi
    
    cipher_log "Executing Great Purge for user: $user"

    # 1. TEMPORARILY UNLOCK EVERYTHING FOR CLEANUP
    chattr -R -i "$user_home" 2>/dev/null || true

    # ========================================================================
    # 2. THE MASTER WHITELISTS
    # ========================================================================
    ALLOWED_HOME=("Aegis" "Documents" "Downloads" "Pictures" ".cache" ".config" ".local" ".pki" ".var" ".ssh" ".gnupg")
    ALLOWED_LOCAL=("share" "state")

    # ========================================================================
    # 3. PHASE 1: THE HOME DIRECTORY PURGE
    # ========================================================================
    # Iterate through ALL files and hidden files. If not on the whitelist, destroy it.
    find "$user_home" -mindepth 1 -maxdepth 1 | while read -r item; do
        basename_item=$(basename "$item")
        if [[ ! " ${ALLOWED_HOME[*]} " =~ " ${basename_item} " ]]; then
            rm -rf "$item"
        fi
    done

    # Reconstruct required whitelist directories with strict permissions
    for d in "${ALLOWED_HOME[@]}"; do
        install -d -o "$user" -g "$user" -m 700 "$user_home/$d"
    done

    # ========================================================================
    # 4. PHASE 2: THE .local DIRECTORY PURGE
    # ========================================================================
    find "$user_home/.local" -mindepth 1 -maxdepth 1 | while read -r item; do
        basename_item=$(basename "$item")
        if [[ ! " ${ALLOWED_LOCAL[*]} " =~ " ${basename_item} " ]]; then
            rm -rf "$item"
        fi
    done

    for d in "${ALLOWED_LOCAL[@]}"; do
        install -d -o "$user" -g "$user" -m 700 "$user_home/.local/$d"
    done

    # ========================================================================
    # 5. PHASE 3: SURGICAL BLACKLISTS INSIDE MUTABLE ZONES (.config)
    # ========================================================================
    # .config MUST remain mutable so GNOME and Wayland can function.
    # However, we must explicitly destroy and freeze the known execution vectors inside it.
    DANGEROUS_CONFIGS=("autostart" "systemd/user" "environment.d")
    for dc in "${DANGEROUS_CONFIGS[@]}"; do
        rm -rf "$user_home/.config/$dc"
        install -d -o "$user" -g "$user" -m 700 "$user_home/.config/$dc"
        chattr +i "$user_home/.config/$dc" 2>/dev/null || true
    done

    # Annihilate Flatseal overrides completely
    rm -rf "$user_home/.local/share/flatpak/overrides"
    install -d -o "$user" -g "$user" -m 700 "$user_home/.local/share/flatpak/overrides"
    chattr +i "$user_home/.local/share/flatpak/overrides" 2>/dev/null || true

    # Lock SSH configuration to prevent ProxyCommand hijacks
    install -D -o "$user" -g "$user" -m 600 /dev/null "$user_home/.ssh/config"
    install -D -o "$user" -g "$user" -m 600 /dev/null "$user_home/.ssh/authorized_keys"
    chattr +i "$user_home/.ssh/config" "$user_home/.ssh/authorized_keys" 2>/dev/null || true

    # ========================================================================
    # 6. PHASE 4: KERNEL DIRECTORY NODE LOCKDOWN
    # ========================================================================
    # We lock the directory nodes themselves. This means NO NEW FILES can be created 
    # directly inside ~ or ~/.local, but the whitelisted subdirectories remain functional.
    chattr +i "$user_home"
    chattr +i "$user_home/.local"

done

cipher_log "Strict Whitelist architecture successfully enforced."
exit 0
