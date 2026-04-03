#!/usr/bin/env bash
set -euo pipefail

echo "Waiting for Cipherblue encrypted DNS tunnel to establish..."
until curl -s https://dl.flathub.org > /dev/null; do
    sleep 5
done

echo "DNS active. Enforcing Cipherblue Supply Chain..."

# 1. Add our custom restricted remote FIRST
# Enforcing the verified_floss subset to mathematically guarantee OSS supply chain integrity
flatpak remote-add --if-not-exists --system --subset=verified_floss cipherblue-verified-floss https://dl.flathub.org/repo/flathub.flatpakrepo

# 2. Dynamically exterminate ALL unauthorized SYSTEM remotes
mapfile -t SYSTEM_REMOTES < <(flatpak remote-list --system --columns=name 2>/dev/null || true)
for remote in "${SYSTEM_REMOTES[@]}"; do
    if [[ -n "$remote" && "$remote" != "cipherblue-verified-floss" ]]; then
        echo "CIPHERBLUE ENFORCER: Nuking unauthorized system remote -> $remote"
        flatpak remote-delete --force --system "$remote" || true
    fi
done

# 3. Read the Desired State injected by GitHub Actions
if [[ -f /etc/cipherblue/flatpaks.list ]]; then
    mapfile -t DESIRED_APPS < <(grep -v '^#' /etc/cipherblue/flatpaks.list | grep -v '^[[:space:]]*$')
else
    DESIRED_APPS=()
fi

# 4. Read Current State of the hard drive WITH ORIGIN REMOTES
mapfile -t INSTALLED_APPS_INFO < <(flatpak list --system --app --columns=application,origin 2>/dev/null || true)

# 5. The Exterminator & Origin Enforcer
for app_info in "${INSTALLED_APPS_INFO[@]}"; do
    # Extract the app name and its source origin
    app=$(echo "$app_info" | awk '{print $1}')
    origin=$(echo "$app_info" | awk '{print $2}')
    
    # Skip empty lines
    if [[ -z "$app" ]]; then continue; fi

    is_desired=false
    for desired in "${DESIRED_APPS[@]}"; do
        if [[ "$app" == "$desired" ]]; then
            is_desired=true
            break
        fi
    done
    
    if [[ "$is_desired" == false ]]; then
        echo "CIPHERBLUE ENFORCER: Deprecated application detected -> $app. Exterminating..."
        flatpak uninstall --system -y --noninteractive --delete-data "$app" || true
    elif [[ "$origin" != "cipherblue-verified-floss" ]]; then
        # THE STRANDED ORIGIN FIX
        echo "CIPHERBLUE ENFORCER: Origin Violation -> $app installed from '$origin'. Purging for secure migration..."
        # Notice we omit --delete-data here so your IDE settings and login sessions survive the migration!
        flatpak uninstall --system -y --noninteractive "$app" || true
    fi
done

# 6. Refresh the Current State Array after the purge
mapfile -t CURRENTLY_INSTALLED < <(flatpak list --system --app --columns=application 2>/dev/null || true)

# 7. The Provisioner (Installs missing apps from the correct remote)
for app in "${DESIRED_APPS[@]}"; do
    is_installed=false
    for installed in "${CURRENTLY_INSTALLED[@]}"; do
        if [[ "$app" == "$installed" ]]; then
            is_installed=true
            break
        fi
    done
    
    if [[ "$is_installed" == false ]]; then
        echo "CIPHERBLUE ENFORCER: Authorized application missing -> $app. Installing from secure remote..."
        flatpak install --system -y --noninteractive cipherblue-verified-floss "$app" || true
    fi
done

# 8. Deep Clean orphaned runtimes
flatpak uninstall --system --unused -y --noninteractive --delete-data || true

echo "Cipherblue Flatpak State mathematically enforced."
exit 0