#!/usr/bin/env bash
set -euo pipefail

echo "CIPHERBLUE: Executing Native Buildah Secret Injection Engine..."

mkdir -p /etc/cipherblue

# ==============================================================================
# 1. PURE DECLARATIVE FLATPAK ENGINE
# ==============================================================================
if [[ -f /tmp/secrets/CIPHERBLUE_FLATPAKS ]]; then
    FLATPAKS=$(cat /tmp/secrets/CIPHERBLUE_FLATPAKS)
    if [[ -n "$FLATPAKS" ]]; then
        echo "Injecting Flatpak whitelist from secure RAM mount..."
        echo "$FLATPAKS" | tr ',' '\n' | tr -d ' ' | grep -v '^$' > /etc/cipherblue/flatpaks.list
    else
        touch /etc/cipherblue/flatpaks.list
    fi
else
    echo "Warning: CIPHERBLUE_FLATPAKS secret not found in RAM mount."
    touch /etc/cipherblue/flatpaks.list
fi

chmod 644 /etc/cipherblue/flatpaks.list

# ==============================================================================
# 2. PRIVATE DOMAIN BLOCKLIST INJECTION
# ==============================================================================
if [[ -f /tmp/secrets/CIPHERBLUE_BLOCKLIST ]]; then
    HOSTS=$(cat /tmp/secrets/CIPHERBLUE_BLOCKLIST)
    if [[ -n "$HOSTS" ]]; then
        echo "Injecting Domain Blocklist from secure RAM mount..."
        echo "$HOSTS" > /etc/cipherblue/hosts.blocklist
    else
        touch /etc/cipherblue/hosts.blocklist
    fi
else
    echo "Warning: CIPHERBLUE_BLOCKLIST secret not found in RAM mount."
    touch /etc/cipherblue/hosts.blocklist
fi

chmod 644 /etc/cipherblue/hosts.blocklist

echo "CIPHERBLUE: Private data mathematically fused into the immutable OS blueprint."
exit 0