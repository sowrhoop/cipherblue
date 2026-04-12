#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2025-2026 The Cipherblue Authors
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

# Import the Unified Core API
source /usr/libexec/cipherblue/cipher-core.sh

cipher_log "Starting Cipherblue Sentinel Daemon (Unified Tick Engine Architecture)..."

# ==============================================================================
# STATE VARIABLES
# ==============================================================================
staged_notified=false
prev_system_failed=""
prev_user_failed=""
selinux_alerted=false
boot_alerted=false

# ==============================================================================
# STATE CHECKERS (Stateless Functions)
# ==============================================================================
check_ostree() {
    local booted_id staged_id
    if booted_id=$(rpm-ostree status --json 2>/dev/null | jq -r '.deployments[] | select(.booted == true) | .id' 2>/dev/null); then
        staged_id=$(rpm-ostree status --json 2>/dev/null | jq -r '.deployments[0].id' 2>/dev/null)
        if [[ -n "$booted_id" && -n "$staged_id" && "$booted_id" != "$staged_id" ]]; then
            if [[ "$staged_notified" == "false" ]]; then
                notify_ui "🔄 OS Update Staged" "A new immutable image has been securely downloaded. Reboot to apply." "software-update-available" "normal"
                staged_notified=true
            fi
        else
            staged_notified=false
        fi
    fi
}

check_services() {
    local current_system_failed
    current_system_failed=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}' | sort | tr '\n' ' ')
    for unit in $current_system_failed; do
        if [[ ! " $prev_system_failed " =~ " $unit " ]]; then
            notify_ui "⚠️ System Service Crashed" "A critical background service failed:\n<b>$unit</b>" "dialog-warning" "critical"
        fi
    done
    prev_system_failed="$current_system_failed"

    local target_user=$(get_active_user || true)
    if [[ -n "$target_user" ]]; then
        local target_uid=$(id -u "$target_user" 2>/dev/null || true)
        if [[ -n "$target_uid" ]]; then
            local current_user_failed
            current_user_failed=$(timeout 5 runuser -u "$target_user" -- env XDG_RUNTIME_DIR="/run/user/${target_uid}" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${target_uid}/bus" systemctl --user list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}' | sort | tr '\n' ' ' || true)
            for unit in $current_user_failed; do
                if [[ ! " $prev_user_failed " =~ " $unit " ]]; then
                    notify_ui "⚠️ User Service Crashed" "A user-space service failed:\n<b>$unit</b>" "dialog-warning" "critical"
                fi
            done
            prev_user_failed="$current_user_failed"
        fi
    fi
}

check_selinux() {
    if command -v getenforce >/dev/null 2>&1; then
        local current_mode=$(getenforce)
        if [[ "$current_mode" != "Enforcing" ]]; then
            if [[ "$selinux_alerted" == "false" ]]; then
                notify_ui "🚨 MAC Subsystem Compromised" "SELinux dropped to: <b>$current_mode</b>. Security degraded!" "dialog-error" "critical"
                selinux_alerted=true
            fi
        else
            if [[ "$selinux_alerted" == "true" ]]; then
                cipher_log "✅ MAC Subsystem Restored to Enforcing mode."
                selinux_alerted=false
            fi
        fi
    fi
}

check_boot_integrity() {
    local compromised=false
    local alert_msg=""

    if [[ ! -f /boot/grub2/user.cfg ]] && [[ ! -f /boot/efi/EFI/fedora/user.cfg ]]; then
        compromised=true
        alert_msg="GRUB Lockdown key is missing! The bootloader is exposed."
    fi

    local cmdline=$(cat /proc/cmdline 2>/dev/null || true)
    if [[ "$cmdline" == *"rd.break"* || "$cmdline" == *"init=/bin/"* || "$cmdline" == *"single"* || "$cmdline" == *"emergency"* || "$cmdline" == *"rescue"* ]]; then
        compromised=true
        alert_msg="Malicious kernel overrides detected in /proc/cmdline!"
    fi

    if [[ "$compromised" == "true" ]]; then
        if [[ "$boot_alerted" == "false" ]]; then
            notify_ui "💀 Boot Integrity Compromised" "$alert_msg" "dialog-error" "critical"
            boot_alerted=true
        fi
    else
        if [[ "$boot_alerted" == "true" ]]; then
            cipher_log "✅ Boot Integrity Restored."
            boot_alerted=false
        fi
    fi
}

# ==============================================================================
# THREAD 1: Real-Time Event Engine (Blocking)
# ==============================================================================
monitor_polkit() {
    journalctl -f -n 0 | grep --line-buffered -E "CIPHERBLUE: .* ->" | while read -r line; do
        action_id=$(echo "$line" | awk -F'-> ' '{print $2}')
        if [[ "$line" == *"State mutation blocked"* ]]; then
            notify_ui "🛡️ Unauthorized State Mutation" "Polkit blocked an attempt to alter the OS.\nAction: <b>$action_id</b>" "security-high" "critical"
        else
            notify_ui "🔒 Zero-Trust Intervention" "UI action blocked by the security perimeter.\nAction: <b>$action_id</b>" "security-medium" "normal"
        fi
    done
}

# ==============================================================================
# THREAD 2: Unified Tick Engine (Non-Blocking)
# ==============================================================================
unified_tick_engine() {
    local tick=0
    while true; do
        if (( tick % 30 == 0 )); then check_services; fi
        if (( tick % 60 == 0 )); then check_selinux; check_boot_integrity; fi
        if (( tick % 300 == 0 )); then check_ostree; fi
        
        sleep 30
        tick=$((tick + 30))
        if (( tick >= 300 )); then tick=0; fi
    done
}

# Execute exactly two lightweight threads
monitor_polkit &
unified_tick_engine &
wait