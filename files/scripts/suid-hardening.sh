#!/usr/bin/env bash

set -oue pipefail

whitelist=(
    "/usr/lib/polkit-1/polkit-agent-helper-1"
)


is_in_whitelist() {
    local binary="$1"
    for allowed_binary in "${whitelist[@]}"; do
        if [ "$binary" = "$allowed_binary" ]; then
            return 0
        fi
    done
    return 1
}

find /usr -type f -perm /4000 |
    while IFS= read -r binary; do
        if ! is_in_whitelist "$binary"; then
            echo "Removing SUID bit from $binary"
            chmod u-s "$binary"
            echo "Removed SUID bit from $binary"
        fi
    done

find /usr -type f -perm /2000 |
    while IFS= read -r binary; do
        if ! is_in_whitelist "$binary"; then
            echo "Removing SGID bit from $binary"
            chmod g-s "$binary"
            echo "Removed SGID bit from $binary"
        fi
    done

rm -f /usr/bin/chsh
rm -f /usr/bin/pkexec
rm -f /usr/bin/sudo
rm -f /usr/bin/su

set_caps_if_present() {
    local caps="$1"
    local binary_path="$2"
    if [ -f "$binary_path" ]; then
        echo "Setting caps $caps on $binary_path"
        setcap "$caps" "$binary_path"
        echo "Set caps $caps on $binary_path"
    fi
}

set_caps_if_present "cap_dac_read_search,cap_audit_write=ep" "/usr/bin/chage"
set_caps_if_present "cap_chown,cap_dac_override,cap_fowner,cap_audit_write=ep" "/usr/bin/chfn"
set_caps_if_present "cap_dac_read_search=ep" "/usr/libexec/openssh/ssh-keysign"
set_caps_if_present "cap_sys_admin=ep" "/usr/bin/fusermount3"
set_caps_if_present "cap_dac_read_search,cap_audit_write=ep" "/usr/sbin/unix_chkpwd"
