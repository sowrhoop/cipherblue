#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CIPHERBLUE SENTINEL
# ==============================================================================
notify_ui() {
    local title="$1"
    local msg="$2"
    local icon="${3:-preferences-system}"
    local target_user=$(loginctl list-sessions --no-legend | awk '$3 != "gdm" && $3 != "root" {print $3}' | head -n 1)
    
    if [[ -n "$target_user" ]]; then
        local target_uid=$(id -u "$target_user")
        runuser -u "$target_user" -- env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${target_uid}/bus" \
            notify-send -a "Cipherblue Sentinel" -i "$icon" "$title" "$msg" || true
    fi
}

notify_ui "📡 Network Probe" "Waiting for Cipherblue encrypted DNS tunnel to establish..." "network-wireless"
until curl -s https://dl.flathub.org > /dev/null; do sleep 5; done

# DESKTOP SESSION GATE
while true; do
    active_user=$(loginctl list-sessions --no-legend | awk '$3 != "gdm" && $3 != "root" {print $3}' | head -n 1)
    if [[ -n "$active_user" ]]; then break; fi
    sleep 3
done

notify_ui "⚙️ Application State Sync" "Network active. Analyzing Flatpak Vault against GitHub Declarative State..." "software-update-available"

flatpak remote-add --if-not-exists --system --subset=verified_floss cipherblue-verified-floss https://dl.flathub.org/repo/flathub.flatpakrepo

mapfile -t SYSTEM_REMOTES < <(flatpak remote-list --system --columns=name 2>/dev/null || true)
for remote in "${SYSTEM_REMOTES[@]}"; do
    if [[ -n "$remote" && "$remote" != "cipherblue-verified-floss" ]]; then
        notify_ui "💥 Purging Remote" "Unauthorized system remote detected: $remote. Exterminating..." "user-trash"
        flatpak remote-delete --force --system "$remote" || true
    fi
done

if [[ -f /etc/cipherblue/flatpaks.list ]]; then
    mapfile -t DESIRED_APPS < <(grep -v '^#' /etc/cipherblue/flatpaks.list | grep -v '^[[:space:]]*$')
else
    DESIRED_APPS=()
fi

mapfile -t INSTALLED_APPS_INFO < <(flatpak list --system --app --columns=application,origin 2>/dev/null || true)

changes_made=false

for app_info in "${INSTALLED_APPS_INFO[@]}"; do
    app=$(echo "$app_info" | awk '{print $1}')
    origin=$(echo "$app_info" | awk '{print $2}')
    if [[ -z "$app" ]]; then continue; fi

    is_desired=false
    for desired in "${DESIRED_APPS[@]}"; do
        if [[ "$app" == "$desired" ]]; then is_desired=true; break; fi
    done
    
    if [[ "$is_desired" == false ]]; then
        notify_ui "🗑️ App Extermination" "Deprecated app detected: $app. Nuking binary and data..." "user-trash"
        flatpak uninstall --system -y --noninteractive --delete-data "$app" || true
        changes_made=true
    elif [[ "$origin" != "cipherblue-verified-floss" ]]; then
        notify_ui "🔄 Origin Migration" "Migrating $app from insecure origin ($origin) to verified FLOSS remote..." "system-software-update"
        flatpak uninstall --system -y --noninteractive "$app" || true
        changes_made=true
    fi
done

mapfile -t CURRENTLY_INSTALLED < <(flatpak list --system --app --columns=application 2>/dev/null || true)

for app in "${DESIRED_APPS[@]}"; do
    is_installed=false
    for installed in "${CURRENTLY_INSTALLED[@]}"; do
        if [[ "$app" == "$installed" ]]; then is_installed=true; break; fi
    done
    
    if [[ "$is_installed" == false ]]; then
        notify_ui "📦 Provisioning App" "Authorized application missing. Installing: $app..." "software-update-available"
        flatpak install --system -y --noninteractive cipherblue-verified-floss "$app" || true
        changes_made=true
    fi
done

notify_ui "🧹 Deep Cleaning" "Sweeping orphaned runtimes and leftover system cache..." "edit-clear-all"
flatpak uninstall --system --unused -y --noninteractive --delete-data || true

if [ "$changes_made" = true ]; then
    notify_ui "✅ Vault Synchronized" "Applications successfully aligned with your secure cloud state." "emblem-default"
else
    notify_ui "🛡️ System Secure" "Application state is mathematically perfect. No changes required." "security-high"
fi

exit 0