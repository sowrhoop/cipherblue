#!/usr/bin/env bash
set -oue pipefail

# Install line (unchanged)
dnf5 install --setopt=install_weak_deps=False tlp -y --skip-unavailable