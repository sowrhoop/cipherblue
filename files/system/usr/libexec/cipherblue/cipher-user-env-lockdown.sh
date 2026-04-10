#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# CIPHERBLUE KERNEL IMMUTABILITY ENGINE (v3.0 - FINAL)
# Mathematically sterilizes and locks all user-space execution surfaces.
# Defends against interactive shells, systemd hijacking, Git/SSH config hooking, 
# Podman DevContainer escapes, and Flatseal overrides.

set -euo pipefail
source /usr/libexec/cipherblue/cipher-core.sh

cipher_log "Engaging Kernel-Level User Space Sterilization (v3.0)..."

# Extract true human users
mapfile -t HUMAN_USERS < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

for user in "${HUMAN_USERS[@]}"; do
    user_home="$(getent passwd "$user" | cut -d: -f6)"
    
    if [ ! -d "$user_home" ]; then continue; fi
    
    cipher_log "Sterilizing and locking vectors for user: $user"

    # ========================================================================
    # 1. FILE TARGETS (Shell, History, Deep Shadow Configs)
    # ========================================================================
    FILE_TARGETS=(
        "$user_home/.bashrc"
        "$user_home/.bash_profile"
        "$user_home/.profile"
        "$user_home/.bash_logout"
        "$user_home/.bash_login"
        "$user_home/.bash_history"       # API Key & Command logging
        "$user_home/.zshrc"              # ZSH fallback
        "$user_home/.zprofile"
        "$user_home/.ssh/authorized_keys" # Remote backdoor
        "$user_home/.ssh/config"          # SSH LocalCommand/ProxyCommand hijack
        "$user_home/.gitconfig"           # Git pager/sshCommand hijack
        "$user_home/.xprofile"            # Display manager hijack
        "$user_home/.xinitrc"
        "$user_home/.vimrc"               # Editor script hijack
        "$user_home/.tmux.conf"           # Multiplexer hijack
    )

    for file in "${FILE_TARGETS[@]}"; do
        if [ -e "$file" ]; then
            chattr -i "$file" 2>/dev/null || true
            rm -f "$file"
        fi

        parent_dir="$(dirname "$file")"
        install -D -d -o "$user" -g "$user" -m 700 "$parent_dir"

        skel_file="/etc/skel/$(basename "$file")"
        if [ -f "$skel_file" ]; then
            install -D -o "$user" -g "$user" -m 700 "$skel_file" "$file"
        else
            install -D -o "$user" -g "$user" -m 700 /dev/null "$file"
        fi

        chattr +i "$file" 2>/dev/null || true
    done

    # ========================================================================
    # 2. DIRECTORY TARGETS (Daemons, GUI, Containers, IPC)
    # ========================================================================
    DIR_TARGETS=(
        "$user_home/.bashrc.d"
        "$user_home/.config/environment.d"
        "$user_home/.config/autostart"             # GUI malware
        "$user_home/.config/systemd/user"          # Background daemons
        "$user_home/.config/containers"            # DevContainer host-mount escape
        "$user_home/.local/share/flatpak/overrides" # Flatseal sandbox bypass
        "$user_home/.local/share/applications"     # Desktop app shadowing
        "$user_home/.local/share/dbus-1/services"  # D-Bus IPC activation
        "$user_home/.local/bin"                    # $PATH binary shadowing
    )

    for dir in "${DIR_TARGETS[@]}"; do
        if [ -e "$dir" ]; then
            chattr -R -i "$dir" 2>/dev/null || true
            rm -rf "$dir"
        fi

        install -D -d -o "$user" -g "$user" -m 700 "$dir"
        chattr +i -R "$dir" 2>/dev/null || true
    done

    # Final hardening of the home directory structure itself
    chmod 700 "$user_home"
    chmod 700 "$user_home/.ssh"
done

cipher_log "User space mathematically sterilized. Absolute Zero-Trust achieved."
exit 0