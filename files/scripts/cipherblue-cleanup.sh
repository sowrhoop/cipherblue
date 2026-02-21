#!/usr/bin/env bash

set -oue pipefail

shopt -s extglob
rm -f /etc/yum.repos.d/!(fedora.repo|fedora-updates.repo)
rm -f /etc/fwupd/remotes.d/lvfs-testing.conf
rm -f /usr/libexec/gnome-software-dkms-helper
rm -f /etc/xdg/autostart/org.gnome.Software.desktop