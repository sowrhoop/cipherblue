#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# CIPHERBLUE KERNEL IMMUTABILITY ENGINE (v8.4 - CASCADING NODE FREEZE)
# Mathematically freezes directory nodes and targeted configuration files.

set -euo pipefail
source /usr/libexec/cipherblue/cipher-core.sh

cipher_log "Engaging v8.4 Cascading Node Freeze Engine..."

# ========================================================================
# 1. THE MASTER DECLARATIVE WHITELISTS
# ========================================================================
ALLOWED_HOME_DIRS=("Backups" "Documents" "Downloads" "Pictures" ".cache" ".config" ".local" ".pki" ".var")
ALLOWED_HOME_FILES=()

ALLOWED_LOCAL_DIRS=("share" "state")
ALLOWED_LOCAL_FILES=()

ALLOWED_CONFIG_DIRS=("dconf" "menus" "gtk-3.0" "gtk-4.0" "pulse" "pipewire" "ibus" "nautilus" "goa-1.0" "evolution" "trivalent")
ALLOWED_CONFIG_FILES=("user-dirs.dirs" "user-dirs.locale" "mimeapps.list" "gnome-initial-setup-done" ".gsd-keyboard.settings-ported")

ALLOWED_LOCAL_SHARE_DIRS=("applications" "backgrounds" "evolution" "gnome-settings-daemon" "gnome-shell" "gvfs-metadata" "ibus-data-booster" "icc" "icons" "keyrings" "nautilus" "pki" "sounds" "Trash")
ALLOWED_LOCAL_SHARE_FILES=("recently-used.xbel")

ALLOWED_LOCAL_STATE_DIRS=("wireplumber")
ALLOWED_LOCAL_STATE_FILES=("lesshst")

ALLOWED_VAR_DIRS=("app")
ALLOWED_VAR_FILES=()

ALLOWED_APPLICATIONS_DIRS=()
ALLOWED_APPLICATIONS_FILES=("mimeapps.list")

# ========================================================================
# 2. THE RECONCILIATION FUNCTION
# ========================================================================
enforce_whitelist() {
    local target_dir=$1
    shift
    
    local dirs=()
    local files=()
    local is_file_mode=0

    for arg in "$@"; do
        if [[ "$arg" == "---FILES---" ]]; then
            is_file_mode=1
            continue
        fi
        if [[ $is_file_mode -eq 0 ]]; then
            dirs+=("$arg")
        else
            files+=("$arg")
        fi
    done

    if [ ! -d "$target_dir" ]; then return 0; fi
    cipher_log "Reconciling node: $target_dir"

    chattr -i "$target_dir" 2>/dev/null || true

    while IFS= read -r -d '' item; do
        basename_item=$(basename "$item")
        
        is_allowed=false
        for allowed in "${dirs[@]}" "${files[@]}"; do
            if [[ "$basename_item" == "$allowed" ]]; then 
                is_allowed=true
                break
            fi
        done

        if [[ "$is_allowed" == false ]]; then
            chattr -R -i "$item" 2>/dev/null || true
            rm -rf "$item"
        fi
    done < <(find "$target_dir" -mindepth 1 -maxdepth 1 -print0)

    for d in "${dirs[@]}"; do
        if [ ! -d "$target_dir/$d" ]; then
            install -d -o "$user" -g "$user" -m 700 "$target_dir/$d"
            restorecon -F "$target_dir/$d" 2>/dev/null || true
        fi
    done

    for f in "${files[@]}"; do
        if [ ! -f "$target_dir/$f" ]; then
            install -D -o "$user" -g "$user" -m 600 /dev/null "$target_dir/$f"
            restorecon -F "$target_dir/$f" 2>/dev/null || true
        fi
    done
    
    chattr +i "$target_dir" 2>/dev/null || true
}

# ========================================================================
# 3. EXECUTION ENGINE
# ========================================================================
mapfile -t HUMAN_USERS < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

for user in "${HUMAN_USERS[@]}"; do
    user_home="$(getent passwd "$user" | cut -d: -f6)"
    
    if [[ "$user_home" != "/home/"* && "$user_home" != "/var/home/"* ]]; then
        continue
    fi
    if [ ! -d "$user_home" ]; then continue; fi

    chattr -i "$user_home" 2>/dev/null || true
    chmod 700 "$user_home"

    # 1. ROOT LEVEL RECONCILIATION
    enforce_whitelist "$user_home" "${ALLOWED_HOME_DIRS[@]}" "---FILES---" "${ALLOWED_HOME_FILES[@]}"
    
    # 2. MID-TIER RECONCILIATION
    enforce_whitelist "$user_home/.local" "${ALLOWED_LOCAL_DIRS[@]}" "---FILES---" "${ALLOWED_LOCAL_FILES[@]}"
    enforce_whitelist "$user_home/.config" "${ALLOWED_CONFIG_DIRS[@]}" "---FILES---" "${ALLOWED_CONFIG_FILES[@]}"
    enforce_whitelist "$user_home/.var" "${ALLOWED_VAR_DIRS[@]}" "---FILES---" "${ALLOWED_VAR_FILES[@]}"
    
    # 3. DEEP RECONCILIATION
    enforce_whitelist "$user_home/.local/share" "${ALLOWED_LOCAL_SHARE_DIRS[@]}" "---FILES---" "${ALLOWED_LOCAL_SHARE_FILES[@]}"
    enforce_whitelist "$user_home/.local/state" "${ALLOWED_LOCAL_STATE_DIRS[@]}" "---FILES---" "${ALLOWED_LOCAL_STATE_FILES[@]}"
    
    # 4. SURGICAL APPLICATION RECONCILIATION
    # Unlock the file temporarily if it was frozen previously to allow pristine generation
    chattr -i "$user_home/.local/share/applications/mimeapps.list" 2>/dev/null || true
    
    enforce_whitelist "$user_home/.local/share/applications" "${ALLOWED_APPLICATIONS_DIRS[@]}" "---FILES---" "${ALLOWED_APPLICATIONS_FILES[@]}"
    
    # CRITICAL: Mathematically freeze the mimeapps.list file itself
    chattr +i "$user_home/.local/share/applications/mimeapps.list" 2>/dev/null || true

done

cipher_log "Cascading Node Freeze Architecture v8.4 successfully enforced."
exit 0