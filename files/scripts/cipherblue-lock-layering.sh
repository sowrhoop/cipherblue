#!/usr/bin/env bash
set -euo pipefail

echo "[cipherblue] Initiating OS Layering Lock..."

TARGET_CONF="/etc/rpm-ostreed.conf"

if [[ ! -f "$TARGET_CONF" ]]; then
    echo "Error: $TARGET_CONF not found. Upstream structure changed!"
    exit 1
fi

# Remove any existing LockLayering keys to prevent duplicates
sed -i '/^LockLayering=/d' "$TARGET_CONF"
sed -i '/^#LockLayering=/d' "$TARGET_CONF"

# Dynamically inject LockLayering=true immediately after the [daemon] header
sed -i '/^\[daemon\]/a LockLayering=true' "$TARGET_CONF"

# Because rpm-ostree syncs /etc to /usr/etc during container builds, 
# we also patch /usr/etc directly just to guarantee it survives the 3-way boot merge
if [[ -f "/usr/etc/rpm-ostreed.conf" ]]; then
    sed -i '/^LockLayering=/d' /usr/etc/rpm-ostreed.conf
    sed -i '/^#LockLayering=/d' /usr/etc/rpm-ostreed.conf
    sed -i '/^\[daemon\]/a LockLayering=true' /usr/etc/rpm-ostreed.conf
fi

echo "[cipherblue] Success: rpm-ostree layering is now mathematically locked."
exit 0