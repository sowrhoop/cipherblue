#!/usr/bin/env bash
set -oue pipefail

# Install line (unchanged)
dnf5 install --setopt=install_weak_deps=False trivalent tlp fapolicyd unbound dnscrypt-proxy ima-evm-utils keyutils openssl -y --skip-unavailable