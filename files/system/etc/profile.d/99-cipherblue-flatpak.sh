# SPDX-License-Identifier: Apache-2.0
# Cipherblue Flatpak Lockdown

# Mathematically breaks the flatpak --user flag by pointing the installation directory into the void
export FLATPAK_USER_DIR="/dev/null"