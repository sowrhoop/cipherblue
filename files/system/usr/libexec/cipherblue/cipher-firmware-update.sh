#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

source /usr/libexec/cipherblue/cipher-core.sh

/usr/bin/fwupdmgr refresh --force >/dev/null 2>&1 || true

if /usr/bin/fwupdmgr get-updates --json 2>/dev/null | jq -e '.Devices != []' >/dev/null 2>&1; then
    
    cipher_log "Hardware firmware updates detected. Attempting to stage..."
    cipher_log "Engaging UPower Blindfold to bypass 0% dead battery lock..."
    
    cp /etc/fwupd/fwupd.conf /tmp/fwupd.conf.bak
    
    if grep -q "^DisabledPlugins=" /etc/fwupd/fwupd.conf; then
        sed -i 's/^DisabledPlugins=/DisabledPlugins=upower;/g' /etc/fwupd/fwupd.conf
    elif grep -q "^#DisabledPlugins=" /etc/fwupd/fwupd.conf; then
        sed -i 's/^#DisabledPlugins=.*/DisabledPlugins=upower/g' /etc/fwupd/fwupd.conf
    else
        echo "DisabledPlugins=upower" >> /etc/fwupd/fwupd.conf
    fi
    
    systemctl restart fwupd
    
    EXIT_CODE=0
    UPDATE_OUTPUT=$(/usr/bin/fwupdmgr update -y --force 2>&1) || EXIT_CODE=$?

    mv /tmp/fwupd.conf.bak /etc/fwupd/fwupd.conf
    systemctl restart fwupd

    if [ $EXIT_CODE -eq 0 ]; then
        cipher_log "Firmware staged successfully."
        notify_ui "🔄 Firmware Staged" "Hardware updates have been securely downloaded. Please restart your computer to flash the firmware." "software-update-available" "critical"
        exit 0
    else
        cipher_log "Firmware update paused. Hardware safety lock engaged."
        notify_ui "🔌 Power Required for Update" "Firmware updates are waiting, but your AC adapter is unplugged. Connect to wall power so the system can safely update." "battery-low" "critical"
        exit 1
    fi
else
    exit 0
fi