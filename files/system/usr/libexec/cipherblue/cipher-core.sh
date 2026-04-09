#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 The Cipherblue Authors
# SPDX-License-Identifier: Apache-2.0
#
# CIPHERBLUE CORE API
# Sourced by all Cipherblue microservices. Do not execute directly.

set -uo pipefail

# ==============================================================================
# UNIFIED LOGGING ENGINE
# ==============================================================================
cipher_log() {
    echo "CIPHERBLUE: $1"
}

# ==============================================================================
# UNIFIED DBUS NOTIFICATION BROKER
# ==============================================================================
get_active_user() {
    if command -v loginctl >/dev/null 2>&1; then
        while read -r sess uid user seat; do
            if [[ "$user" == "gdm" || "$user" == "root" ]]; then continue; fi
            if [[ $(loginctl show-session "$sess" -p Active --value 2>/dev/null) == "yes" ]]; then
                printf "%s" "$user"
                return 0
            fi
        done < <(loginctl list-sessions --no-legend 2>/dev/null)
        loginctl list-sessions --no-legend 2>/dev/null | awk '$3 != "gdm" && $3 != "root" {print $3}' | head -n 1
    else
        who | awk '{print $1}' | grep -vE '^gdm$|^root$' | head -n 1
    fi
}

# Usage: notify_ui "Title" "Message" "icon-name" "urgency"
notify_ui() {
    local title="$1"
    local msg="$2"
    local icon="${3:-dialog-information}"
    local urgency="${4:-normal}"

    local target_user
    target_user=$(get_active_user || true)

    if [[ -z "$target_user" ]]; then return 0; fi

    local target_uid
    if ! target_uid=$(id -u "$target_user" 2>/dev/null); then return 1; fi

    local XDG_RUNTIME_DIR="/run/user/${target_uid}"
    local DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"

    timeout 5 runuser -u "$target_user" -- env \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
        DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS}" \
        DISPLAY=":0" \
        WAYLAND_DISPLAY="wayland-0" \
        notify-send -a "Cipherblue Sentinel" -u "$urgency" -i "$icon" "$title" "$msg" || true
}