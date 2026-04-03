#!/usr/bin/env bash
set -euo pipefail

echo "[cipherblue] Compiling dconf database into the immutable image..."
dconf update
echo "[cipherblue] dconf database successfully compiled."
exit 0