#!/usr/bin/env bash
set -euo pipefail
if command -v dconf >/dev/null 2>&1; then
  dconf update || true
fi