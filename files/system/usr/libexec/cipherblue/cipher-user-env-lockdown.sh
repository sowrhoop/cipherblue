#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# CIPHERBLUE KERNEL IMMUTABILITY ENGINE (v8.0 - ULTIMATE NODE FREEZE)
# Mathematically freezes directory nodes to prevent unapproved dotfile creation,
# perfectly curated to satisfy strict D-Bus, XDG, and Flatpak dependencies.

set -euo pipefail
source /usr/libexec/cipherblue/cipher-core.sh

cipher_log "Engaging v8.0 Ultimate Node Freeze Engine..."

# ========================================================================
# 1. THE MASTER DECLARATIVE WHITELISTS
# (Injected critical DBUS, XDG, and Malware Trap placeholders natively)
# ========================================================================
ALLOWED_HOME_DIRS=("Aegis" "Desktop" "Documents" "Downloads" "Music" "Pictures" "Public" "Templates" "Videos" ".cache" ".config" ".local" ".pki" ".var" ".dbus")
ALLOWED_HOME_FILES=(".Xauthority" ".ICEauthority" ".bashrc" ".bash_profile" ".profile" ".zshrc")

ALLOWED_LOCAL_DIRS=("share" "state" "bin")
ALLOWED_LOCAL_FILES=()

ALLOWED_CONFIG_DIRS=("dconf" "menus" "gtk-3.0" "gtk-4.0" "pulse" "pipewire" "ibus" "nautilus" "goa-1.0" "evolution" "trivalent" "dbus-1" "autostart" "systemd" "environment.d")
ALLOWED_CONFIG_FILES=("user-dirs.dirs" "user-dirs.locale" "mimeapps.list" "gnome-initial-setup-done" ".gsd-keyboard.settings-ported")

ALLOWED_LOCAL_SHARE_DIRS=("applications" "backgrounds" "dbus-1" "evolution" "flatpak" "gnome-settings-daemon" "gnome-shell" "gvfs-metadata" "ibus-data-booster" "icc" "icons" "keyrings" "nautilus" "pki" "sounds" "Trash")
ALLOWED_LOCAL_SHARE_FILES=("recently-used.xbel")

ALLOWED_LOCAL_STATE_DIRS=("wireplumber")
ALLOWED_LOCAL_STATE_FILES=("lesshst")

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

    # Unlock the parent node temporarily
    chattr -i "$target_dir" 2>/dev/null || true

    # PHASE A: Detect and Obliterate Unapproved Clutter
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

    # PHASE B: Guarantee Directories
    for d in "${dirs[@]}"; do
        if [ ! -d "$target_dir/$d" ]; then
            install -d -o "$user" -g "$user" -m 700 "$target_dir/$d"
            restorecon -F "$target_dir/$d" 2>/dev/null || true
        fi
    done

    # PHASE C: Guarantee Files
    for f in "${files[@]}"; do
        if [ ! -f "$target_dir/$f" ]; then
            install -D -o "$user" -g "$user" -m 600 /dev/null "$target_dir/$f"
            restorecon -F "$target_dir/$f" 2>/dev/null || true
        fi
    done
    
    # PHASE D: Freeze the Directory Node (The Absolute Zero-Trust Lock)
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

    # 1. Cleanse and freeze user space nodes
    enforce_whitelist "$user_home" "${ALLOWED_HOME_DIRS[@]}" "---FILES---" "${ALLOWED_HOME_FILES[@]}"
    enforce_whitelist "$user_home/.local" "${ALLOWED_LOCAL_DIRS[@]}" "---FILES---" "${ALLOWED_LOCAL_FILES[@]}"
    enforce_whitelist "$user_home/.config" "${ALLOWED_CONFIG_DIRS[@]}" "---FILES---" "${ALLOWED_CONFIG_FILES[@]}"
    enforce_whitelist "$user_home/.local/share" "${ALLOWED_LOCAL_SHARE_DIRS[@]}" "---FILES---" "${ALLOWED_LOCAL_SHARE_FILES[@]}"
    enforce_whitelist "$user_home/.local/state" "${ALLOWED_LOCAL_STATE_DIRS[@]}" "---FILES---" "${ALLOWED_LOCAL_STATE_FILES[@]}"

    # 2. Apply Surgical Malware Traps
    # Because they were natively created by Phase B & C, we can just freeze them directly
    # without triggering the 'Operation not permitted' kernel crash inside the frozen parent nodes.
    chattr +i "$user_home/.bashrc" "$user_home/.bash_profile" "$user_home/.profile" "$user_home/.zshrc" 2>/dev/null || true
    chattr +i "$user_home/.config/autostart" "$user_home/.config/systemd" "$user_home/.config/environment.d" 2>/dev/null || true
    chattr +i "$user_home/.local/bin" 2>/dev/null || true
    
    # Secure Flatpak overrides (.local/share/ is a mutable node, so this creates flawlessly)
    install -d -o "$user" -g "$user" -m 700 "$user_home/.local/share/flatpak/overrides"
    chattr +i "$user_home/.local/share/flatpak/overrides" 2>/dev/null || true

    chmod 700 "$user_home"
done

cipher_log "Ultimate Node Freeze Architecture v8.0 successfully enforced."
exit 0
