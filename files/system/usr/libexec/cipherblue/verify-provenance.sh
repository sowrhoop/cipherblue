#!/usr/bin/bash
# SPDX-FileCopyrightText: Copyright 2025-2026 The Cipherblue Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export HOME=${HOME:-~}

# ==============================================================================
# CIPHERBLUE SENTINEL
# ==============================================================================
notify_ui() {
    local title="$1"
    local msg="$2"
    local icon="${3:-security-high}"
    local target_user=$(loginctl list-sessions --no-legend | awk '$3 != "gdm" && $3 != "root" {print $3}' | head -n 1)
    
    if [[ -n "$target_user" ]]; then
        local target_uid=$(id -u "$target_user")
        runuser -u "$target_user" -- env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${target_uid}/bus" \
            notify-send -a "Cipherblue Sentinel" -i "$icon" "$title" "$msg" || true
    fi
}

raw_image_ref=$(rpm-ostree status --booted --json | jq -cr '.deployments[0]."container-image-reference"')

if [[ "$raw_image_ref" == *"ostree-unverified-registry"* ]]; then
    # Silent exit here, as secure-rebase.sh handles the unverified state notification
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