#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

echo "CIPHERBLUE: Initiating System Garbage Collection..."

# 1. Vacuum Systemd Journals (Keep only the last 2 weeks of logs)
/usr/bin/journalctl --vacuum-time=2weeks

# 2. Sweep orphaned Flatpak runtimes
/usr/bin/flatpak uninstall --system --unused -y --noninteractive --delete-data || true

# 3. Deep OS Layer Cleanup
# The '-bm' flag cleans up base image metadata and removes older, unpinned deployments
/usr/bin/rpm-ostree cleanup -bm || true

echo "CIPHERBLUE: Garbage collection complete. Appliance running at maximum efficiency."
exit 0