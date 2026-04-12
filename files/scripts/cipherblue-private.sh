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

# ==============================================================================
# 3. ZERO-TRUST FLATPAK OVERRIDES INJECTION (Staging to /etc)
# ==============================================================================
if [[ -f /tmp/secrets/PRIVATE_VAULT_PAT ]]; then
    VAULT_TOKEN=$(cat /tmp/secrets/PRIVATE_VAULT_PAT)
    if [[ -n "$VAULT_TOKEN" ]]; then
        echo "CIPHERBLUE: Authenticating with Private Vault natively inside container..."
        
        TEMP_VAULT=$(mktemp -d)
        
        curl -sSfL -H "Authorization: token ${VAULT_TOKEN}" \
             "https://api.github.com/repos/sowrhoop/Private-Vault/tarball" \
             -o /tmp/vault.tar.gz
        
        tar -xzf /tmp/vault.tar.gz -C "$TEMP_VAULT" --strip-components=1
        
        if [ -d "$TEMP_VAULT/cipherblue/flatpak/overrides" ]; then
            echo "CIPHERBLUE: Vault unlocked. Staging overrides in immutable OS layer..."
            
            # CRITICAL: Stage in /etc/cipherblue. OSTree will sync this perfectly.
            mkdir -p /etc/cipherblue/flatpak-overrides/
            cp -r "$TEMP_VAULT/cipherblue/flatpak/overrides/"* /etc/cipherblue/flatpak-overrides/
            
            chmod 644 /etc/cipherblue/flatpak-overrides/*
            
            echo "CIPHERBLUE: Overrides successfully staged."
        else
            echo "CIPHERBLUE CRITICAL: Overrides directory not found in private vault!"
            exit 1
        fi
        
        rm -rf "$TEMP_VAULT" /tmp/vault.tar.gz
    else
        echo "CIPHERBLUE CRITICAL: PRIVATE_VAULT_PAT is empty!"
        exit 1
    fi
else
    echo "CIPHERBLUE CRITICAL: PRIVATE_VAULT_PAT secret not found in RAM mount!"
    exit 1
fi

echo "CIPHERBLUE: Private data mathematically fused into the immutable OS blueprint."
exit 0