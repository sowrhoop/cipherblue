#!/usr/bin/env bash
set -euo pipefail

echo "CIPHERBLUE: Executing Secure Private Injection Engine inside container..."

# ==============================================================================
# 1. PURE DECLARATIVE FLATPAK ENGINE (Zero-GUI Architecture)
# ==============================================================================
mkdir -p /etc/cipherblue
touch /etc/cipherblue/flatpaks.list

# The GitHub Action's sed command replaces this placeholder before the container starts
RAW_FLATPAKS="__SECRET_FLATPAK_WHITELIST__"

if [[ -n "$RAW_FLATPAKS" && "$RAW_FLATPAKS" != "__SECRET_FLATPAK_WHITELIST__" ]]; then
    # Parse the secret, split by comma, and write directly to the vault list
    echo "$RAW_FLATPAKS" | tr ',' '\n' | tr -d ' ' | grep -v '^$' > /etc/cipherblue/flatpaks.list
    echo "Flatpak whitelist successfully baked into /etc/cipherblue/."
else
    echo "[info] No Flatpaks defined in secret. Vault will remain empty."
fi

chmod 644 /etc/cipherblue/flatpaks.list

# ==============================================================================
# 2. PRIVATE DOMAIN BLOCKLIST INJECTION (The OSTree Blueprint Fix)
# ==============================================================================
echo "Cleanly appending Domain Blocklist to native OSTree blueprint (/usr/etc/hosts)..."

# FIX: In OCI containers, /etc/hosts is a live bind-mount. Modifying it crashes sed
# and changes are discarded. We must append to the OSTree blueprint at /usr/etc/hosts, 
# which rpm-ostree merges into the live /etc/hosts automatically during boot!

# The GitHub Action's Perl script replaces the placeholder below perfectly.
cat << 'EOF' >> /usr/etc/hosts

# ===========================================================
# CIPHERBLUE PRIVATE DOMAIN BLOCKLIST
# ===========================================================
__SECRET_HOSTS_BLOCKLIST__
EOF

echo "CIPHERBLUE: Private data mathematically fused into the immutable OS blueprint."
exit 0