#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright 2025-2026 The Cipherblue Authors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

for repo in /etc/yum.repos.d/*.repo; do
    sed -i 's/metalink?/metalink?protocol=https\&/g' "$repo"
done