# SPDX-License-Identifier: Apache-2.0
# Cipherblue Absolute Shell Lockdown

# The $- variable holds current shell options. 'i' means interactive.
# GNOME boots non-interactively, so it bypasses this completely.
if [[ $- == *i* ]]; then
    echo "CIPHERBLUE: Interactive terminal access is mathematically prohibited."
    # Instantly terminate the shell process
    exit 1
fi