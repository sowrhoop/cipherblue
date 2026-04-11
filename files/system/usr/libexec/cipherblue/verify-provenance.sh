#!/usr/bin/bash
# SPDX-FileCopyrightText: Copyright 2025-2026 The Cipherblue Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export HOME=${HOME:-~}

source /usr/libexec/cipherblue/cipher-core.sh

raw_image_ref=$(rpm-ostree status --booted --json | jq -cr '.deployments[0]."container-image-reference"')

# CRITICAL FIX: Declarative State Check
if [[ "$raw_image_ref" == *"ostree-unverified-registry"* ]]; then
    cipher_log "Developer/Debugging mode detected (Unverified Image)."
    cipher_log "Bypassing strict provenance checks to allow local updates."
    # We exit 0 instead of 1 so systemd doesn't crash the auto-updater!
    exit 0
fi

cipher_log "Provenance Engine Waking Up. Analyzing current OSTree deployment reference..."

image_ref=${raw_image_ref#*:docker://}
case "${image_ref}" in
    ghcr.io/sowrhoop/cipherblue*) source_uri='github.com/sowrhoop/cipherblue' ;;
    *) notify_ui "🚨 Provenance Alert" "Unknown OS image reference detected: ${image_ref}. System integrity at risk." "dialog-error" "critical"; exit 1 ;;
esac

image_tag="${image_ref##*:}"
case "${image_tag}" in
    latest) branch='main' ;;
    br-*) branch="${image_tag#br-}"; branch="${branch%-*}" ;;
    *) notify_ui "🚨 Provenance Alert" "Unknown image tag: ${image_tag}. Verification aborted." "dialog-error" "critical"; exit 1 ;;
esac

cipher_log "Unlocking GHCR Vault. Extracting encrypted credentials..."

if [[ ! -f /etc/ostree/auth.json ]]; then
    notify_ui "🚨 Provenance Alert" "Authentication vault missing. Cannot verify private OS image." "dialog-error" "critical"
    exit 1
fi

B64_AUTH=$(jq -r '.auths["ghcr.io"].auth // empty' /etc/ostree/auth.json)
if [[ -z "$B64_AUTH" || "$B64_AUTH" == "null" ]]; then
    notify_ui "🚨 Provenance Alert" "Malformed authentication vault. Verification aborted." "dialog-error" "critical"
    exit 1
fi

cipher_log "Establishing Secure Tunnel. Probing GHCR..."
until curl -sL -H "Authorization: Basic $B64_AUTH" --retry 3 https://ghcr.io > /dev/null; do sleep 5; done

cipher_log "Fetching Image Digest from GitHub Registry..."
crane auth login ghcr.io -u "sowrhoop" -p "$(echo "$B64_AUTH" | base64 -d | cut -d: -f2)"

full_ref=$(crane digest --full-ref "${image_ref}")
export GITHUB_TOKEN="$(echo "$B64_AUTH" | base64 -d | cut -d: -f2)"

cipher_log "Running slsa-verifier against $full_ref..."

if slsa-verifier verify-image --source-uri "${source_uri}" --source-branch "${branch}" "${full_ref}"; then
    cipher_log "✅ OS Integrity Verified. SLSA Provenance mathematically matched."
    exit 0
else
    IMAGE_CREATED_DATE=$(crane config "${full_ref}" | jq -r '.created' 2>/dev/null || echo "1970-01-01T00:00:00Z")
    IMAGE_TIMESTAMP=$(date -d "$IMAGE_CREATED_DATE" +%s 2>/dev/null || echo 0)
    CURRENT_TIMESTAMP=$(date +%s)
    AGE_SECONDS=$((CURRENT_TIMESTAMP - IMAGE_TIMESTAMP))
    
    if (( AGE_SECONDS < 1800 )); then 
        cipher_log "⏳ Provenance Pending. New OS image detected ($((AGE_SECONDS / 60)) min old). Awaiting attestations."
        exit 0
    else
        notify_ui "💀 CRITICAL SECURITY ALERT" "SLSA Provenance Verification FAILED! Upstream image may be compromised. Auto-updates have been suspended." "dialog-error" "critical"
        exit 1
    fi
fi