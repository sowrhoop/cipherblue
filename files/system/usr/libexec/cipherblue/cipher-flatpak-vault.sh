#!/usr/bin/env bash
set -euo pipefail

source /usr/libexec/cipherblue/cipher-core.sh

cipher_log "Waiting for encrypted DNS tunnel to establish..."
until curl -s https://dl.flathub.org > /dev/null; do sleep 5; done

cipher_log "Network active. Analyzing Flatpak Vault..."

flatpak remote-add --if-not-exists --system --subset=verified_floss cipherblue-verified-floss https://dl.flathub.org/repo/flathub.flatpakrepo

mapfile -t SYSTEM_REMOTES < <(flatpak remote-list --system --columns=name 2>/dev/null || true)
for remote in "${SYSTEM_REMOTES[@]}"; do
    if [[ -n "$remote" && "$remote" != "cipherblue-verified-floss" ]]; then
        notify_ui "💥 Purging Remote" "Unauthorized system remote detected: $remote. Exterminating..." "user-trash" "critical"
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
        notify_ui "🗑️ App Extermination" "Deprecated app detected: $app. Nuking binary and data..." "user-trash" "normal"
        flatpak uninstall --system -y --noninteractive --delete-data "$app" || true
        changes_made=true
    elif [[ "$origin" != "cipherblue-verified-floss" ]]; then
        notify_ui "🔄 Origin Migration" "Migrating $app from insecure origin ($origin) to verified FLOSS remote..." "system-software-update" "normal"
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
        notify_ui "📦 Provisioning App" "Authorized application missing. Installing: $app..." "software-update-available" "normal"
        flatpak install --system -y --noninteractive cipherblue-verified-floss "$app" || true
        changes_made=true
    fi
done

cipher_log "Sweeping orphaned system runtimes and leftover cache..."
flatpak uninstall --system --unused -y --noninteractive --delete-data || true

mapfile -t HUMAN_USERS < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

for u in "${HUMAN_USERS[@]}"; do
    if runuser -u "$u" -- flatpak list --user --columns=application 2>/dev/null | grep -q .; then
        notify_ui "🧹 User Space Purge" "Sterilizing unauthorized user-level Flatpaks for $u..." "user-trash" "critical"
        runuser -u "$u" -- flatpak uninstall --user --all -y --noninteractive --delete-data || true
        changes_made=true
    fi
    
    mapfile -t USER_REMOTES < <(runuser -u "$u" -- flatpak remote-list --user --columns=name 2>/dev/null || true)
    for r in "${USER_REMOTES[@]}"; do
        if [[ -n "$r" ]]; then
            runuser -u "$u" -- flatpak remote-delete --user --force "$r" || true
            changes_made=true
        fi
    done
done

if [ "$changes_made" = true ]; then
    notify_ui "✅ Vault Synchronized" "Applications successfully aligned with your secure cloud state." "emblem-default" "normal"
else
    cipher_log "🛡️ System Secure. Application state is mathematically perfect."
fi

exit 0