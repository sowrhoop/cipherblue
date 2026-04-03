#!/usr/bin/bash
# SPDX-FileCopyrightText: Copyright 2025-2026 The Cipherblue Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export HOME=${HOME:-~}

# ==============================================================================
# ASYNCHRONOUS TRANSIENT DISPATCHER
# Because this script runs before GNOME exists, it uses systemd-run to spawn
# independent, floating background tasks. They wait patiently in RAM (up to 10m) 
# and fire off the telemetry the exact second you log into your desktop.
# ==============================================================================
notify_ui() {
    local title="$1"
    local msg="$2"
    local icon="${3:-security-high}"
    
    systemd-run --quiet --collect \
        -p Environment="SENTINEL_TITLE=${title}" \
        -p Environment="SENTINEL_MSG=${msg}" \
        -p Environment="SENTINEL_ICON=${icon}" \
        /bin/bash -c '
            for i in {1..120}; do
                TARGET_USER=""
                while read -r session uid user seat tty rest; do
                    if [[ -n "$user" && "$user" != "root" && "$user" != "gdm" ]]; then
                        TARGET_USER="$user"
                        break
                    fi
                done <<< "$(loginctl list-sessions --no-legend)"
                
                if [[ -n "$TARGET_USER" ]]; then
                    TARGET_UID=$(id -u "$TARGET_USER")
                    runuser -u "$TARGET_USER" -- env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${TARGET_UID}/bus" notify-send -a "Cipherblue Sentinel" -i "$SENTINEL_ICON" "$SENTINEL_TITLE" "$SENTINEL_MSG"
                    break
                fi
                sleep 5
            done
        ' || true
}

raw_image_ref=$(rpm-ostree status --booted --json | jq -cr '.deployments[0]."container-image-reference"')

if [[ "$raw_image_ref" == *"ostree-unverified-registry"* ]]; then
    exit 1
fi

notify_ui "🔍 Provenance Engine Waking Up" "Analyzing current OSTree deployment reference..." "system-search"

image_ref=${raw_image_ref#*:docker://}
case "${image_ref}" in
    ghcr.io/sowrhoop/cipherblue*)
        source_uri='github.com/sowrhoop/cipherblue'
        ;;
    *)
        notify_ui "🚨 Provenance Alert" "Unknown OS image reference detected: ${image_ref}. System integrity at risk." "dialog-error"
        exit 1
        ;;
esac

image_tag="${image_ref##*:}"
case "${image_tag}" in
    latest) branch='main' ;;
    br-*) branch="${image_tag#br-}"; branch="${branch%-*}" ;;
    *)
        notify_ui "🚨 Provenance Alert" "Unknown image tag: ${image_tag}. Verification aborted." "dialog-error"
        exit 1
        ;;
esac

notify_ui "🔐 Unlocking GHCR Vault" "Extracting encrypted credentials for private registry authentication..." "dialog-password"

if [[ ! -f /etc/ostree/auth.json ]]; then
    notify_ui "🚨 Provenance Alert" "Authentication vault missing. Cannot verify private OS image." "dialog-error"
    exit 1
fi

B64_AUTH=$(jq -r '.auths["ghcr.io"].auth // empty' /etc/ostree/auth.json)
if [[ -z "$B64_AUTH" || "$B64_AUTH" == "null" ]]; then
    notify_ui "🚨 Provenance Alert" "Malformed authentication vault. Verification aborted." "dialog-error"
    exit 1
fi

notify_ui "📡 Establishing Secure Tunnel" "Probing GHCR for authenticated network routing..." "network-transmit-receive"

until curl -sL -H "Authorization: Basic $B64_AUTH" --retry 3 https://ghcr.io > /dev/null; do
    sleep 5
done

notify_ui "🔎 Fetching Image Digest" "Querying GitHub Registry for immutable SHA256 layer hashes..." "document-properties"

crane auth login ghcr.io -u "sowrhoop" -p "$(echo "$B64_AUTH" | base64 -d | cut -d: -f2)"
full_ref=$(crane digest --full-ref "${image_ref}")

export GITHUB_TOKEN="$(echo "$B64_AUTH" | base64 -d | cut -d: -f2)"

notify_ui "🛡️ Cryptographic Math Engine" "Running slsa-verifier against $full_ref..." "security-high"

if slsa-verifier verify-image --source-uri "${source_uri}" --source-branch "${branch}" "${full_ref}"; then
    notify_ui "✅ OS Integrity Verified" "Cryptographic signatures mathematically matched. Immutable state is secure." "emblem-default"
    exit 0
else
    notify_ui "💀 CRITICAL SECURITY ALERT" "OS Image Signature Verification FAILED! The update may be compromised." "dialog-error"
    exit 1
fi