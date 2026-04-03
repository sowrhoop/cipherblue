#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CIPHERBLUE SENTINEL
# ==============================================================================
notify_ui() {
    local title="$1"
    local msg="$2"
    local icon="${3:-system-software-update}"
    local target_user=$(loginctl list-sessions --no-legend | awk '$3 != "gdm" && $3 != "root" {print $3}' | head -n 1)
    
    if [[ -n "$target_user" ]]; then
        local target_uid=$(id -u "$target_user")
        runuser -u "$target_user" -- env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${target_uid}/bus" \
            notify-send -a "Cipherblue Sentinel" -i "$icon" "$title" "$msg" || true
    fi
}

until rpm-ostree status >/dev/null 2>&1; do
    sleep 2
done

current_ref=$(rpm-ostree status --booted --json | jq -cr '.deployments[0]."container-image-reference"')

if [[ "$current_ref" != *"ostree-unverified-registry"* ]]; then
    touch /var/lib/cipherblue-signed-rebase.stamp
    exit 0
fi

notify_ui "🔒 Sentinel Bootstrap" "Unverified state detected. Initializing Cryptographic Rebase protocol..." "network-transmit-receive"

if [[ ! -f /etc/ostree/auth.json ]]; then
    notify_ui "⚠️ Security Alert" "Auth vault missing. Rebase aborted." "dialog-error"
    exit 1
fi

B64_AUTH=$(jq -r '.auths["ghcr.io"].auth // empty' /etc/ostree/auth.json)
if [[ -z "$B64_AUTH" || "$B64_AUTH" == "null" ]]; then
    notify_ui "⚠️ Security Alert" "Malformed authentication. Rebase aborted." "dialog-error"
    exit 1
fi

notify_ui "🌉 Bridging D-Bus Gap" "Sideloading private credentials into root OCI subsystems..." "preferences-system"

mkdir -p /etc/containers /run/containers/0
cp /etc/ostree/auth.json /etc/containers/auth.json
cp /etc/ostree/auth.json /run/containers/0/auth.json
chmod 600 /etc/containers/auth.json /run/containers/0/auth.json

until curl -sL -H "Authorization: Basic $B64_AUTH" --retry 3 https://ghcr.io > /dev/null; do
    sleep 5
done

notify_ui "⬇️ Executing Secure Pull" "Downloading immutable signed OS from GHCR. This process may take several minutes depending on network speed..." "software-update-available"

rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sowrhoop/cipherblue:latest || {
    notify_ui "❌ Rebase Failed" "The cryptographic rebase crashed. Ensure device has stable internet and check journalctl." "dialog-error"
    exit 1
}

touch /var/lib/cipherblue-signed-rebase.stamp

notify_ui "✅ Lockdown Complete" "Cipherblue Image verified and staged. The system will forcefully reboot in 10 seconds." "system-reboot"

sleep 10
systemctl reboot