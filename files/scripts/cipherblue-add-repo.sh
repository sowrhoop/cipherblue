#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright 2025-2026 The Cipherblue Authors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

dnf5 config-manager addrepo --from-repofile="https://copr.fedorainfracloud.org/coprs/secureblue/packages/repo/fedora-$OS_VERSION/secureblue-packages-fedora-$OS_VERSION.repo"