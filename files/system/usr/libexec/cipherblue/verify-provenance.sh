#!/usr/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 The Cipherblue Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export HOME=${HOME:-~}

raw_image_ref=$(rpm-ostree status --booted --json | jq -cr '.deployments[0]."container-image-reference"')

if [[ "$raw_image_ref" == *"ostree-unverified-registry"* ]]; then
    echo "CIPHERBLUE: Unverified bootstrap state detected."
    echo "CIPHERBLUE: Yielding daemon lock to cipher-secure-rebase.service..."
    exit 1
fi

image_ref=${raw_image_ref#*:docker://}

case "${image_ref}" in
    ghcr.io/sowrhoop/cipherblue*)
        source_uri='github.com/sowrhoop/cipherblue'
        ;;
    *)
        echo "CIPHERBLUE SECURITY ALERT: Unknown image reference '${image_ref}'; unable to check provenance."
        exit 1
        ;;
esac
echo "CIPHERBLUE: Verifying cryptographic build provenance for ${image_ref}..."

image_tag="${image_ref##*:}"
case "${image_tag}" in
    latest)
        branch='main'
        ;;
    br-**)
        branch="${image_tag#br-}"
        branch="${branch%-*}"
        ;;
    *)
        echo "CIPHERBLUE SECURITY ALERT: Unknown image tag '${image_tag}'; unable to check provenance."
        exit 1
        ;;
esac
echo "Expected Source: ${source_uri}:${branch}"

# ==============================================================================
# CIPHERBLUE PRIVATE AUTHENTICATION EXTRACTION
# ==============================================================================
echo "CIPHERBLUE: Extracting credentials for Provenance Engine..."
if [[ ! -f /etc/ostree/auth.json ]]; then
    echo "CIPHERBLUE FATAL: Auth vault missing at /etc/ostree/auth.json. Cannot verify private image."
    exit 1
fi

B64_AUTH=$(jq -r '.auths["ghcr.io"].auth // empty' /etc/ostree/auth.json)

# ==============================================================================
# CIPHERBLUE TRUE INTERNET PROBE (AUTHENTICATED)
# ==============================================================================
echo "CIPHERBLUE: Waiting for Authenticated Network routing to GitHub Container Registry..."
until curl -sL -H "Authorization: Basic $B64_AUTH" --retry 3 https://ghcr.io > /dev/null; do
    sleep 5
done
echo "CIPHERBLUE: True network connection established. Proceeding with verification..."

# Tell crane to authenticate using the extracted credentials
crane auth login ghcr.io -u "sowrhoop" -p "$(echo "$B64_AUTH" | base64 -d | cut -d: -f2)"

full_ref=$(crane digest --full-ref "${image_ref}")
echo "Locked Image Digest: ${full_ref}"

slsa-verifier verify-image --source-uri "${source_uri}" --source-branch "${branch}" "${full_ref}"

echo "CIPHERBLUE: Cryptographic Provenance Verified. Update Authorized."
exit 0