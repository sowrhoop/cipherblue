#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

TOML_DIR="/usr/lib/bootc/kargs.d"

echo "CIPHERBLUE: Parsing declarative TOML kernel arguments..."

# 1. Safely extract all kargs from TOML files using Fedora's native Python 3 tomllib
# This mathematically guarantees we don't break on weird quotes, brackets, or multi-line arrays.
mapfile -t DESIRED_KARGS < <(python3 -c '
import sys, tomllib, glob
for file in glob.glob(sys.argv[1] + "/*.toml"):
    try:
        with open(file, "rb") as f:
            data = tomllib.load(f)
            # Safely grab the "kargs" array, default to empty list if missing
            for arg in data.get("kargs", []):
                print(arg)
    except Exception:
        pass
' "$TOML_DIR" || true)

if [ ${#DESIRED_KARGS[@]} -eq 0 ]; then
    echo "CIPHERBLUE: No kernel arguments found in $TOML_DIR. Exiting."
    exit 0
fi

# 2. Fetch the CURRENT staged kernel arguments from the OSTree database
CURRENT_KARGS=$(rpm-ostree kargs)
declare -a APPEND_ARGS=()

# 3. The Idempotency Engine
for karg in "${DESIRED_KARGS[@]}"; do
    # We pad the string with spaces and use grep -qF to ensure exact word matching.
    # This mathematically prevents "enforcing=1" from accidentally matching "noenforcing=1".
    if ! echo " $CURRENT_KARGS " | grep -qF " $karg "; then
        echo "CIPHERBLUE: Missing kernel argument detected -> $karg"
        APPEND_ARGS+=("--append=$karg")
    fi
done

# 4. Atomic Execution
if [ ${#APPEND_ARGS[@]} -gt 0 ]; then
    echo "CIPHERBLUE: Injecting missing arguments into OSTree..."
    
    # We pass the entire array to rpm-ostree at once. 
    # This prevents the system from generating 5 different deployment layers for 5 arguments.
    rpm-ostree kargs "${APPEND_ARGS[@]}"
    
    echo "CIPHERBLUE: Kernel state mutated successfully."
    echo "CIPHERBLUE: A hard reboot is mathematically required to enforce the new Kernel constraints."
    sleep 3
    systemctl reboot
else
    echo "CIPHERBLUE: Kernel arguments are mathematically perfect. Boot sequence authorized."
fi

exit 0