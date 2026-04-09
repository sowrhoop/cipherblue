#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

echo "CIPHERBLUE: Executing Day-0 State Initialization..."

# 1. ERADICATE INSTALLER DRIFT
# The Anaconda USB installer writes hardcoded config files to /etc that override our immutable image.
# We brutally overwrite them with the pure, mathematically verified files from /usr/etc.
cp /usr/etc/authselect/system-auth /etc/authselect/system-auth
cp /usr/etc/authselect/fingerprint-auth /etc/authselect/fingerprint-auth
cp /usr/etc/authselect/dconf-db /etc/authselect/dconf-db
cp /usr/etc/authselect/authselect.conf /etc/authselect/authselect.conf

cp /usr/etc/firewalld/zones/FedoraWorkstation.xml /etc/firewalld/zones/FedoraWorkstation.xml || true
cp /usr/etc/firewalld/zones/FedoraServer.xml /etc/firewalld/zones/FedoraServer.xml || true

# 2. THE FLATPAK NUKE
# We want a perfectly sterile environment. We delete all default Fedora remotes and wipe 
# any pre-installed software the base Fedora image tried to sneak in.
if command -v flatpak &> /dev/null; then
    echo "CIPHERBLUE: Sterilizing user-space packages..."
    flatpak remote-delete --system --force fedora || true
    flatpak remote-delete --user --force fedora || true
    flatpak remote-delete --system --force fedora-testing || true
    flatpak remote-delete --user --force fedora-testing || true
    # Wipe all existing system flatpaks so our declarative GitOps list takes absolute priority
    flatpak remove --system --noninteractive --all || true
fi

# 3. VERIFY CRYPTOGRAPHIC SIGNATURE STATE
RPM_OSTREE_STATUS=$(rpm-ostree status --json --booted)
IMAGE_BASE_STRING=$(echo "$RPM_OSTREE_STATUS" | jq -r '.deployments[0]."container-image-reference" // empty')

if [[ "$IMAGE_BASE_STRING" == *"ostree-image-signed"* ]]; then
    echo "CIPHERBLUE: OS is mathematically bound to a cryptographic signature. Initialization complete."
else
    # We log a critical error if the installed image isn't the signed variant.
    echo "CIPHERBLUE CRITICAL: OS is running on an unsigned image layer! Check your GitOps build pipeline."
fi

exit 0