#!/usr/bin/env bash

set -euo pipefail

uncomment_and_modify() {
    local file="$1"
    local pattern="$2"
    local replacement="$3"
    
    sed -i "s/^# \(.*$pattern.*\)/\1/g" "$file"
    sed -i "s/$pattern.*/$pattern $replacement/g" "$file"
}

pwquality_file="/etc/security/pwquality.conf"

if [ -f "$pwquality_file" ]; then
  uncomment_and_modify "$pwquality_file" "minlen" "15"
  uncomment_and_modify "$pwquality_file" "dcredit" "-1"
  uncomment_and_modify "$pwquality_file" "ucredit" "-1"
  uncomment_and_modify "$pwquality_file" "lcredit" "-1"
  uncomment_and_modify "$pwquality_file" "ocredit" "-1"
  uncomment_and_modify "$pwquality_file" "maxrepeat" "3"
  uncomment_and_modify "$pwquality_file" "dictcheck" "1"
  uncomment_and_modify "$pwquality_file" "usercheck" "1"
  uncomment_and_modify "$pwquality_file" "usersubstr" "5"
  uncomment_and_modify "$pwquality_file" "enforcing" "1"
  uncomment_and_modify "$pwquality_file" "retry" "5"
  uncomment_and_modify "$pwquality_file" "enforce_for_root" ""
fi

faillock_file="/etc/security/faillock.conf"

if [ -f "$faillock_file" ]; then
  uncomment_and_modify "$faillock_file" "audit" ""
  uncomment_and_modify "$faillock_file" "deny" "25"
  uncomment_and_modify "$faillock_file" "unlock_time" "86400"
  uncomment_and_modify "$faillock_file" "even_deny_root" ""
fi

if command -v authselect >/dev/null 2>&1; then
  authselect create-profile cipherblue -b sssd > /dev/null 2>&1 || true

  new_delay="5000000"

  pwd_files=(
      "/etc/authselect/custom/cipherblue/password-auth"
      "/etc/authselect/custom/cipherblue/system-auth"
  )

  for file in "${pwd_files[@]}"; do
      if [ -f "$file" ]; then
          sed -i "s/\(auth\s*required\s*pam_faildelay.so\s*delay=\).*$/\1$new_delay/" "$file" || true
      fi
  done

  authselect select custom/cipherblue with-pamaccess with-faillock without-nullok --quiet 1> /dev/null || true
fi
