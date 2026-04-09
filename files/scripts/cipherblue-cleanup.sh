#!/usr/bin/env bash

set -oue pipefail

echo "CIPHERBLUE: Executing Final Immutability Cleanup..."

# 1. Remove testing firmware remotes (keep stable fwupd untouched)
rm -f /etc/fwupd/remotes.d/lvfs-testing.conf

# 2. Remove unused graphical software/update daemons
rm -f /usr/libexec/gnome-software-dkms-helper
rm -f /etc/xdg/autostart/org.gnome.Software.desktop

# ==============================================================================
# PACKAGE MANAGER ANNIHILATION
# Physically removes all local DNF/RPM repository configurations.
# Forces 100% reliance on the GitHub CI/CD pipeline for all OS packages.
# ==============================================================================
echo "CIPHERBLUE: Purging local DNF/RPM repository attack surface..."

# Delete all repo configuration files (including hidden ones)
rm -rf /etc/yum.repos.d/*
rm -rf /etc/yum.repos.d/.* 2>/dev/null || true

# Delete all RPM GPG keys used for local package verification
rm -rf /etc/pki/rpm-gpg/*

# Delete flatpak remotes configured at the system level (prevents adding Flathub system-wide)
# User-level flatpaks (Bitwarden, etc) will still install perfectly via your flatpak-vault script.
rm -rf /etc/flatpak/remotes.d/*

echo "CIPHERBLUE: Local package layering mathematically disabled."