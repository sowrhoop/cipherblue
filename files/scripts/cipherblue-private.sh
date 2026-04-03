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
# 2. PRIVATE DOMAIN BLOCKLIST INJECTION (The GitOps Fix)
# ==============================================================================
echo "Staging Domain Blocklist to immutable vault..."

# We store the blocklist safely in /etc/cipherblue to avoid OCI bind-mount crashes.
# The cipher-cleaner systemd service will natively inject this into /etc/hosts on boot.
cat << 'EOF' > /etc/cipherblue/hosts.blocklist
__SECRET_HOSTS_BLOCKLIST__
EOF

# Safely delete the placeholder string if the secret was empty
sed -i '/__SECRET_HOSTS_BLOCKLIST__/d' /etc/cipherblue/hosts.blocklist
chmod 644 /etc/cipherblue/hosts.blocklist

echo "CIPHERBLUE: Private data mathematically fused into the immutable OS blueprint."
exit 0