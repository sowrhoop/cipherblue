#!/usr/bin/env bash
set -euo pipefail

echo "Waiting for Cipherblue encrypted DNS tunnel to establish..."
until curl -s https://dl.flathub.org > /dev/null; do
    sleep 5
done

echo "DNS active. Enforcing Cipherblue Supply Chain..."

# 1. Add our mathematically restricted remote FIRST so we don't break existing apps during transition
flatpak remote-add --if-not-exists --system --subset=verified_floss cipherblue-verified-floss https://dl.flathub.org/repo/flathub.flatpakrepo

# 2. Dynamically exterminate ALL unauthorized SYSTEM remotes
# (User-level remotes are handled by the physical deletion in cipher-cleaner.service)
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

# 4. Read Current State of the hard drive (System only)
mapfile -t INSTALLED_APPS < <(flatpak list --system --app --columns=application)

# 5. The Exterminator (Uninstall rogue, abandoned, or deprecated system apps)
for app in "${INSTALLED_APPS[@]}"; do
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
    fi
done

# 6. The Provisioner (Install missing authorized apps from our custom remote)
for app in "${DESIRED_APPS[@]}"; do
    is_installed=false
    for installed in "${INSTALLED_APPS[@]}"; do
        if [[ "$app" == "$installed" ]]; then
            is_installed=true
            break
        fi
    done
    
    if [[ "$is_installed" == false ]]; then
        echo "CIPHERBLUE ENFORCER: Authorized application missing -> $app. Installing..."
        flatpak install --system -y --noninteractive cipherblue-verified-floss "$app" || true
    fi
done

# 7. Deep Clean orphaned runtimes
flatpak uninstall --system --unused -y --noninteractive --delete-data || true

echo "Cipherblue Flatpak State mathematically enforced."
exit 0