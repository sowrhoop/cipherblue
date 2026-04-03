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

# Note: Because cipher-flatpak-vault.service runs natively as root in the background, 
# it completely bypasses Polkit. We no longer need to inject complex Polkit rules 
# to allow a GUI App Store to function. The user is strictly locked out.

# ==============================================================================
# 2. PRIVATE DOMAIN BLOCKLIST INJECTION
# ==============================================================================
echo "Cleanly appending Domain Blocklist to native /etc/hosts..."

# The GitHub Action's Perl script replaced the placeholder below.
# We use a heredoc to perfectly append it without overwriting Fedora's defaults.
cat << 'EOF' >> /etc/hosts

# ===========================================================
# CIPHERBLUE PRIVATE DOMAIN BLOCKLIST
# ===========================================================
__SECRET_HOSTS_BLOCKLIST__
EOF

# If the secret was empty, we safely delete the placeholder from the file
sed -i '/__SECRET_HOSTS_BLOCKLIST__/d' /etc/hosts

echo "CIPHERBLUE: Private data mathematically fused into the immutable OS."
exit 0