#!/usr/bin/env bash
set -exuo pipefail

echo "Waiting for Cipherblue encrypted DNS tunnel to establish..."
until curl -s https://dl.flathub.org > /dev/null; do
    sleep 5
done

echo "DNS active. Hunting down and exterminating pre-installed Fedora ghost apps..."
# FIXED: Removed the invalid '--force-remove' flag that was crashing the command silently!
flatpak list --columns=application,origin | awk '$2=="fedora" || $2=="fedora-testing" {print $1}' | xargs -r flatpak uninstall --system -y --noninteractive --delete-data || true

echo "Nuking permissive Fedora remotes..."
flatpak remote-delete --force --system fedora || true
flatpak remote-delete --force --system fedora-testing || true

echo "Enforcing Verified FLOSS Flathub Vault..."
flatpak remote-add --if-not-exists --system --subset=verified_floss flathub https://dl.flathub.org/repo/flathub.flatpakrepo

echo "Installing Core App Store (Bazaar)..."
flatpak install --system -y --noninteractive flathub io.github.kolunmi.Bazaar

echo "Deep cleaning orphaned runtimes and leftover app data..."
flatpak uninstall --system --unused -y --noninteractive --delete-data || true

# Create the stamp so this script never runs again
touch /var/lib/cipherblue-flatpak.stamp
echo "Cipherblue Flatpak Vault successfully initialized."
exit 0