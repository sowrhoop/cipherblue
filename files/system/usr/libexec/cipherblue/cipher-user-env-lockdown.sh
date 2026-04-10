#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# CIPHERBLUE KERNEL IMMUTABILITY ENGINE (v5.0 - DYNAMIC STRICT WHITELIST)
# Enforces a strict Default-Deny policy. Recursively unlocks and purges all
# unapproved files/dotfiles, guarantees the existence of whitelisted paths,
# and freezes directory nodes globally.

set -euo pipefail
source /usr/libexec/cipherblue/cipher-core.sh

cipher_log "Engaging v5.0 Dynamic Whitelist Immutability Engine..."

# ========================================================================
# 1. THE MASTER DECLARATIVE WHITELISTS
# ========================================================================
ALLOWED_HOME=("Aegis" "Documents" "Downloads" "Pictures" ".cache" ".config" ".local" ".pki" ".var")
ALLOWED_LOCAL=("share" "state")
ALLOWED_CONFIG=(
    "dconf" "menus" "gtk-3.0" "gtk-4.0" "pulse" "pipewire" 
    "user-dirs.dirs" "user-dirs.locale" "mimeapps.list" "ibus" 
    "gnome-initial-setup-done" "nautilus" "goa-1.0" "evolution" "trivalent" ".gsd-keyboard.settings-ported"
)
ALLOWED_LOCAL_SHARE=(
    "backgrounds" "evolution" "gnome-settings-daemon" "gnome-shell" 
    "gvfs-metadata" "ibus-data-booster" "icc" "icons" "keyrings" 
    "nautilus" "pki" "recently-used.xbel" "sounds" "Trash"
)
ALLOWED_LOCAL_STATE=(
    "lesshst" "wireplumber"
)

# ========================================================================
# 2. THE RECONCILIATION FUNCTION
# ========================================================================
enforce_whitelist() {
    local target_dir=$1
    shift
    local whitelist=("$@")

    if [ ! -d "$target_dir" ]; then return 0; fi

    cipher_log "Reconciling node: $target_dir"

    # Unlock the parent node to allow internal mutations
    chattr -i "$target_dir" 2>/dev/null || true

    # PHASE A: Detect and Obliterate Unapproved Entities
    while IFS= read -r -d '' item; do
        basename_item=$(basename "$item")
        
        is_allowed=false
        for allowed in "${whitelist[@]}"; do
            if [[ "$basename_item" == "$allowed" ]]; then 
                is_allowed=true
                break
            fi
        done

        if [[ "$is_allowed" == false ]]; then
            # Strip previous kernel locks before destroying
            chattr -R -i "$item" 2>/dev/null || true
            rm -rf "$item"
        fi
    done < <(find "$target_dir" -mindepth 1 -maxdepth 1 -print0)

    # PHASE B: Guarantee Existence of Whitelisted Entities
    for allowed in "${whitelist[@]}"; do
        local full_path="$target_dir/$allowed"
        if [ ! -e "$full_path" ]; then
            # Create files for specific extensions, directories for everything else
            if [[ "$allowed" == *.* && "$allowed" != .* ]]; then
                install -D -o "$user" -g "$user" -m 600 /dev/null "$full_path"
            else
                install -d -o "$user" -g "$user" -m 700 "$full_path"
            fi
        fi
    done

    # PHASE C: Freeze the Directory Node
    chattr +i "$target_dir" 2>/dev/null || true
}

# ========================================================================
# 3. EXECUTION ENGINE
# ========================================================================
mapfile -t HUMAN_USERS < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

for user in "${HUMAN_USERS[@]}"; do
    user_home="$(getent passwd "$user" | cut -d: -f6)"
    if [ ! -d "$user_home" ]; then continue; fi

    # Apply Whitelists
    enforce_whitelist "$user_home" "${ALLOWED_HOME[@]}"
    enforce_whitelist "$user_home/.local" "${ALLOWED_LOCAL[@]}"
    enforce_whitelist "$user_home/.config" "${ALLOWED_CONFIG[@]}"
    enforce_whitelist "$user_home/.local/share" "${ALLOWED_LOCAL_SHARE[@]}"
    enforce_whitelist "$user_home/.local/state" "${ALLOWED_LOCAL_STATE[@]}"

    # Secure permissions for the home directory root
    chmod 700 "$user_home"
done

cipher_log "Strict Whitelist architecture successfully enforced."
exit 0
