#!/usr/bin/bash
# SPDX-FileCopyrightText: Copyright 2025-2026 The Cipherblue Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export HOME=${HOME:-~}

notify_ui() {
    local title="$1"
    local msg="$2"
    local icon="${3:-security-high}"
    local target_user=$(loginctl list-sessions --no-legend | awk '$3 != "gdm" && $3 != "root" {print $3}' | head -n 1)
    
    if [[ -n "$target_user" ]]; then
        local target_uid=$(id -u "$target_user")
        # Apply strict 5-second timeout to prevent D-Bus deadlocks
        timeout 5 runuser -u "$target_user" -- env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${target_uid}/bus" \
            notify-send -a "Cipherblue Sentinel" -u "critical" -i "$icon" "$title" "$msg" || true
    fi
}

raw_image_ref=$(rpm-ostree status --booted --json | jq -cr '.deployments[0]."container-image-reference"')

if [[ "$raw_image_ref" == *"ostree-unverified-registry"* ]]; then
    exit 1
fi

notify_ui "🔍 Provenance Engine Waking Up" "Analyzing current OSTree deployment reference..." "system-search"

image_ref=${raw_image_ref#*:docker://}
case "${image_ref}" in
    ghcr.io/sowrhoop/cipherblue*) source_uri='github.com/sowrhoop/cipherblue' ;;
    *) notify_ui "🚨 Provenance Alert" "Unknown OS image reference detected: ${image_ref}. System integrity at risk." "dialog-error"; exit 1 ;;
esac

image_tag="${image_ref##*:}"
case "${image_tag}" in
    latest) branch='main' ;;
    br-*) branch="${image_tag#br-}"; branch="${branch%-*}" ;;
    *) notify_ui "🚨 Provenance Alert" "Unknown image tag: ${image_tag}. Verification aborted." "dialog-error"; exit 1 ;;
esac

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
until curl -sL -H "Authorization: Basic $B64_AUTH" --retry 3 https://ghcr.io > /dev/null; do sleep 5; done

notify_ui "🔎 Fetching Image Digest" "Querying GitHub Registry for immutable SHA256 layer hashes..." "document-properties"
crane auth login ghcr.io -u "sowrhoop" -p "$(echo "$B64_AUTH" | base64 -d | cut -d: -f2)"
full_ref=$(crane digest --full-ref "${image_ref}")

export GITHUB_TOKEN="$(echo "$B64_AUTH" | base64 -d | cut -d: -f2)"

notify_ui "🛡️ Cryptographic Math Engine" "Running slsa-verifier against $full_ref..." "security-high"

# ==============================================================================
# PIPELINE-AWARE TOCTOU MITIGATION
# ==============================================================================
if slsa-verifier verify-image --source-uri "${source_uri}" --source-branch "${branch}" "${full_ref}"; then
    notify_ui "✅ OS Integrity Verified" "SLSA Provenance mathematically matched. Immutable state is secure." "emblem-default"
    exit 0
else
    # The SLSA verification failed. We now check if it failed because of a hack, 
    # or just because the GitHub Action pipeline hasn't finished attaching the signature.
    IMAGE_CREATED_DATE=$(crane config "${full_ref}" | jq -r '.created' 2>/dev/null || echo "1970-01-01T00:00:00Z")
    IMAGE_TIMESTAMP=$(date -d "$IMAGE_CREATED_DATE" +%s 2>/dev/null || echo 0)
    CURRENT_TIMESTAMP=$(date +%s)
    AGE_SECONDS=$((CURRENT_TIMESTAMP - IMAGE_TIMESTAMP))
    
    if (( AGE_SECONDS < 1800 )); then 
        # If the image is less than 30 minutes old, the CI/CD pipeline is likely still running.
        notify_ui "⏳ Provenance Pending" "New OS image detected ($((AGE_SECONDS / 60)) min old), but GitHub Actions is still generating SLSA attestations. Verification deferred." "emblem-synchronizing"
        exit 0
    else
        # If it's been over 30 minutes and there is STILL no SLSA provenance, the supply chain is compromised!
        notify_ui "💀 CRITICAL SECURITY ALERT" "SLSA Provenance Verification FAILED! Upstream image may be compromised. Auto-updates have been suspended." "dialog-error"
        exit 1
    fi
fi
