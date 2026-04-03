#!/usr/bin/env bash
set -euo pipefail

echo "CIPHERBLUE: Initializing Cryptographic Bootstrap Engine..."

# 1. Wait for the rpm-ostree daemon to wake up
until rpm-ostree status >/dev/null 2>&1; do
    sleep 2
done

# 2. Check the current Image State
current_ref=$(rpm-ostree status --booted --json | jq -cr '.deployments[0]."container-image-reference"')

if [[ "$current_ref" != *"ostree-unverified-registry"* ]]; then
    echo "CIPHERBLUE: System is already running a cryptographically signed image."
    echo "CIPHERBLUE: Kernel arguments are natively enforced via bootc."
    echo "CIPHERBLUE: Creating stamp to permanently sleep this bootstrap service..."
    touch /var/lib/cipherblue-signed-rebase.stamp
    exit 0
fi

echo "CIPHERBLUE: Unverified OS state detected. Preparing Secure Rebase..."

# 3. Wait for True Network Connectivity
echo "CIPHERBLUE: Waiting for DNS routing to GitHub Container Registry..."
until curl -sL --retry 3 https://ghcr.io > /dev/null; do
    sleep 5
done
echo "CIPHERBLUE: True network connection established."

# 4. Execute the Cryptographic Rebase
echo "CIPHERBLUE: Executing Secure Rebase to signed image..."
rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sowrhoop/cipherblue:latest || exit 1

# 5. Finalize and Lock
echo "CIPHERBLUE: Cryptographic Rebase Staged Successfully."
touch /var/lib/cipherblue-signed-rebase.stamp

echo "CIPHERBLUE: Initiating required reboot to lock system into immutable state..."
systemctl reboot