#!/usr/bin/env bash
set -euo pipefail

source /usr/libexec/cipherblue/cipher-core.sh

until rpm-ostree status >/dev/null 2>&1; do
    sleep 2
done

current_ref=$(rpm-ostree status --booted --json | jq -cr '.deployments[0]."container-image-reference"')

if [[ "$current_ref" != *"ostree-unverified-registry"* ]]; then
    touch /var/lib/cipherblue-signed-rebase.stamp
    exit 0
fi

notify_ui "🔒 Sentinel Bootstrap" "Unverified state detected. Initializing Cryptographic Rebase protocol..." "network-transmit-receive" "normal"
sleep 3

if [[ ! -f /etc/ostree/auth.json ]]; then
    notify_ui "⚠️ Security Alert" "Auth vault missing. Rebase aborted." "dialog-error" "critical"
    exit 1
fi

B64_AUTH=$(jq -r '.auths["ghcr.io"].auth // empty' /etc/ostree/auth.json)
if [[ -z "$B64_AUTH" || "$B64_AUTH" == "null" ]]; then
    notify_ui "⚠️ Security Alert" "Malformed authentication. Rebase aborted." "dialog-error" "critical"
    exit 1
fi

cipher_log "Vault Verified. Probing network..."
until curl -sL -H "Authorization: Basic $B64_AUTH" --retry 3 https://ghcr.io > /dev/null; do
    sleep 5
done

notify_ui "⬇️ Executing Secure Pull" "Downloading immutable signed OS from GHCR. This process takes 15-30 minutes depending on network speed..." "software-update-available" "critical"

rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sowrhoop/cipherblue:latest > /var/log/cipherblue-rebase.log 2>&1 &
RPM_PID=$!

MINUTES_WAITED=0
while kill -0 $RPM_PID 2>/dev/null; do
    sleep 60
    ((MINUTES_WAITED++))
    if (( MINUTES_WAITED % 3 == 0 )); then
        notify_ui "⏳ Rebase In Progress ($MINUTES_WAITED min)" "Cipherblue is still mathematically extracting the OS layers in the background. Please wait..." "emblem-synchronizing" "normal"
    fi
done

wait $RPM_PID
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    ERROR_TXT=$(tail -n 2 /var/log/cipherblue-rebase.log | tr -d '"' | tr -d "'" | tr '\n' ' ')
    
    while true; do
        active_user=$(get_active_user || true)
        if [[ -n "$active_user" ]]; then break; fi
        sleep 5
    done
    
    notify_ui "❌ Rebase Failed" "Error: $ERROR_TXT" "dialog-error" "critical"
    exit 1
fi

touch /var/lib/cipherblue-signed-rebase.stamp

while true; do
    active_user=$(get_active_user || true)
    if [[ -n "$active_user" ]]; then break; fi
    sleep 5
done

notify_ui "✅ Lockdown Complete" "Cipherblue Image verified and staged. The system will forcefully reboot in 10 seconds." "system-reboot" "critical"

sleep 10
systemctl reboot --no-block