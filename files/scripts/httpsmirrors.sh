#!/usr/bin/env bash

set -oue pipefail

shopt -s nullglob
for repo in /etc/yum.repos.d/*.repo; do
    sed -i 's/metalink?/metalink?protocol=https\&/g' "$repo" || true
done