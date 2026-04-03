#!/usr/bin/env bash
set -oue pipefail

# Default settings (can be overridden via env or CLI args)
# DRY_RUN: if set to 1, dnf5 remove will be run with --assumeno (non-destructive)
DRY_RUN=${DRY_RUN:-0}

# Print usage/help
usage() {
  cat <<USAGE
Usage: ${0##*/} [options]

Options:
  -c, --category NAME    Only run the given category (overrides CATEGORY env)
  -l, --log-dir PATH     (deprecated) Write logs to PATH (not used; logs are emitted to stdout)
  -n, --dry-run          Do not remove packages; use dnf5 remove --assumeno if available
  -y, --yes              Force removals (opposite of --dry-run). Note: script already uses -y for dnf5.
      --list             Print the unique package names that would be removed and exit
  -h, --help             Show this help and exit

Environment variables:
  CATEGORY               If set, only that category will be executed (same as -c)
  DRY_RUN                If set to 1, run non-destructive removals (same as -n)

If CATEGORY is unset, all categories will be executed.
USAGE
}

# Parse CLI arguments (simple loop)
while [ "$#" -gt 0 ]; do
  case "$1" in
    -c|--category)
      CATEGORY="$2"
      shift 2
      ;;
    -l|--log-dir)
      # kept for backward compatibility but ignored; logs are printed to stdout for CI
      shift 2
      ;;
    -n|--dry-run)
      DRY_RUN=1
      shift
      ;;
    -y|--yes)
      DRY_RUN=0
      shift
      ;;
    --list)
      # Print unique package list and exit
      awk '/<<'\''PKGS'\''/{flag=1; next} /PKGS/{flag=0} flag' "${BASH_SOURCE[0]}" | sed 's/#.*//' | tr ' ' '\n' | sed '/^$/d' | awk 'BEGIN{IGNORECASE=1} /^[a-z0-9][a-z0-9+._-]*$/ {print tolower($0)}' | sort -u
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

# No log files are written; all logging is emitted to stdout/stderr so CI captures it.

# Helper: read package names from stdin, ignore lines starting with # and empty lines,
# then call dnf5 remove on the remaining packages. This allows you to comment packages
# inside the heredoc for testing without breaking shell line-continuation.
remove_pkgs() {
  local raw pkgs pkg to_remove failures
  raw=$(grep -v '^\s*#' | tr '\n' ' ' | sed 's/  */ /g' | sed 's/^ //; s/ $//')
  if [ -z "$raw" ]; then
    echo "No packages to remove (all lines were comments/blank)" >&2
    return 0
  fi

  echo "Packages to remove: $raw"

  # Build a list of packages that are actually installed. This avoids attempting
  # to remove packages that aren't present in the build image which can produce
  # noisy errors in CI logs. We prefer dnf5 query when available, fall back to rpm -q.
  pkgs=()
  for pkg in $raw; do
    if command -v dnf5 >/dev/null 2>&1; then
      if dnf5 list installed "$pkg" >/dev/null 2>&1; then
        pkgs+=($pkg)
      else
        echo "Skipping not-installed package: $pkg"
      fi
    else
      if rpm -q "$pkg" >/dev/null 2>&1; then
        pkgs+=($pkg)
      else
        echo "Skipping not-installed package: $pkg"
      fi
    fi
  done

  if [ "${#pkgs[@]}" -eq 0 ]; then
    echo "No installed packages to remove" >&2
    return 0
  fi

  # If DRY_RUN is enabled, show the removals (per-package) and exit.
  if [ "$DRY_RUN" -eq 1 ]; then
    if command -v dnf5 >/dev/null 2>&1; then
      echo "(dry-run) Would remove: ${pkgs[*]}"
      for pkg in "${pkgs[@]}"; do
        dnf5 remove --assumeno "$pkg" || true
      done
      return 0
    else
      echo "dnf5 not found; dry-run mode — would remove: ${pkgs[*]}"
      return 0
    fi
  fi

  if ! command -v dnf5 >/dev/null 2>&1; then
    echo "Error: dnf5 not found in PATH; cannot remove packages" >&2
    return 2
  fi
  # Try removing the whole category in one batch first — this is faster and
  # produces a single transaction. If the batch removal fails, fall back to
  # per-package removals to isolate which packages actually failed.
  failures=()
  echo "Attempting batch removal of packages: ${pkgs[*]}"
  if batch_output=$(dnf5 remove -y "${pkgs[@]}" 2>&1); then
    echo "$batch_output"
    echo "Successfully removed packages: ${pkgs[*]}"
    return 0
  else
    echo "$batch_output"
    # If dnf reported nothing to do or no packages, don't treat it as fatal —
    # fall back to per-package removal which will skip not-installed pkgs.
    if printf '%s' "$batch_output" | grep -Ei -q 'nothing to do|no packages marked for removal|no match for argument|no package|is not installed|not installed'; then
      echo "Batch removal reported nothing removed; falling back to per-package removal to confirm/skips"
    else
      echo "Batch removal failed; falling back to per-package removal to isolate failures"
    fi
  fi

  # Per-package removal fallback: remove packages one-by-one to isolate failures
  # and provide clearer logs.
  for pkg in "${pkgs[@]}"; do
    echo "Removing package: $pkg"
    # Run dnf5 remove but capture output so we can detect "not installed" cases
    # and treat them as non-fatal (just skip). Use an if with command
    # substitution so 'set -e' doesn't abort the script on non-zero.
    if output=$(dnf5 remove -y "$pkg" 2>&1); then
      echo "Successfully removed: $pkg"
      continue
    else
      echo "$output"
      # If dnf reports the package is not available/installed, skip it.
      if printf '%s' "$output" | grep -Ei -q 'no match for argument|no package|nothing to do|is not installed|not installed|no packages marked for removal'; then
        echo "Skipping not-present package (dnf reported not installed): $pkg"
        continue
      fi
    fi

    # If dnf5 fails for another reason, try a conservative rpm -e fallback.
    echo "dnf5 remove failed for $pkg — attempting fallback: rpm -e --noscripts $pkg"
    if command -v rpm >/dev/null 2>&1; then
      if rpm_output=$(rpm -e --noscripts "$pkg" 2>&1); then
        echo "Fallback rpm -e --noscripts succeeded for $pkg"
        continue
      else
        echo "$rpm_output"
        if printf '%s' "$rpm_output" | grep -Ei -q 'is not installed|not installed|package .* is not installed'; then
          echo "Skipping not-present package (rpm reported not installed): $pkg"
          continue
        fi
      fi
    fi

    echo "Failed to remove package: $pkg" >&2
    failures+=($pkg)
  done

  if [ "${#failures[@]}" -ne 0 ]; then
    echo "Failed to remove the following packages: ${failures[*]}" >&2
    return 1
  fi

  return 0
}

# Run a single category (reads package list from stdin).
# Usage: run_remove_category "category-key" <<'PKGS' ... PKGS
# If CATEGORY env var is set, only the matching category will be executed.
failures=()
run_remove_category() {
  local name="$1"; shift

  echo "=== START: $name ==="

  # If CATEGORY is set and doesn't match, skip this category
  if [ -n "${CATEGORY:-}" ] && [ "$CATEGORY" != "$name" ]; then
    echo "Skipping category '$name' (CATEGORY='$CATEGORY')"
    return 0
  fi

  # Call remove_pkgs reading from this function's stdin (the heredoc).
  # Capture exit status of remove_pkgs.
  remove_pkgs 2>&1
  local rc=$?

  if [ "$rc" -eq 0 ]; then
    echo "=== SUCCESS: $name ==="
  else
    echo "=== FAILURE ($rc): $name ==="
    failures+=("$name:$rc")
  fi
}

# housekeeping
rm -f /etc/dnf/protected.d/sudo.conf

# --- Desktop / GNOME / Shell ---
run_remove_category "desktop" <<'PKGS'
#nautilus-extensions
desktop-backgrounds-gnome
fedora-bookmarks
fedora-workstation-backgrounds
gnome-backgrounds
gnome-classic-session
gnome-color-manager
gnome-tour
gnome-user-docs
gnome-user-share
gnome-disk-utility
gnome-software
gnome-software-rpm-ostree
gnome-remote-desktop
gnome-browser-connector
epiphany-runtime
firefox
firefox-langpacks
mozilla-filesystem
fedora-chromium-config
fedora-chromium-config-gnome
fedora-flathub-remote
fedora-repos-archive
fedora-third-party
fedora-workstation-repositories
gnome-epub-thumbnailer
gnome-shell-extension-apps-menu
gnome-shell-extension-background-logo
gnome-shell-extension-common
gnome-shell-extension-launch-new-instance
gnome-shell-extension-places-menu
gnome-shell-extension-window-list
#ptyxis # added for debugging
qadwaitadecorations-qt5
qt-settings
qt5-filesystem
qt5-qtbase
qt5-qtbase-common
qt5-qtbase-gui
qt5-qtdeclarative
qt5-qtsvg
qt5-qttranslations
qt5-qtwayland
qt5-qtx11extras
qt5-qtxmlpatterns
gtkmm3.0
xcb-util-image
xcb-util-keysyms
xcb-util-renderutil
xcb-util-wm
xdriinfo
yelp
yelp-libs
yelp-xsl
#nautilus-extensions
PKGS

# --- Printing / Scanning ---
run_remove_category "printing" <<'PKGS'
cups
cups-browsed
cups-client
cups-filters
cups-filters-driverless
cups-ipptool
ghostscript
ghostscript-tools-printing
gutenprint
gutenprint-cups
gutenprint-libs
hplip
hplip-common
hplip-libs
libcupsfilters
libppd
libpaper
ipp-usb
system-config-printer-libs
system-config-printer-udev
sane-airscan
sane-backends
sane-backends-drivers-cameras
sane-backends-libs
libsane-airscan
libsane-hpaio
tesseract-libs
gutenprint-libs
PKGS

# --- Multimedia / Audio / Video / GStreamer ---
run_remove_category "multimedia" <<'PKGS'
ffmpeg-free
gst-editing-services
gstreamer1-plugin-libav
gstreamer1-plugins-bad-free
gstreamer1-plugins-good-qt
gstreamer1-plugins-ugly-free
ImageMagick
ImageMagick-libs
totem-video-thumbnailer
pulseaudio-utils
libavc1394
libavdevice-free
libavfilter-free
libraw1394
LibRaw
libimagequant
libwmf-lite
libgs
rygel
gupnp-av
gupnp-dlna
qpdf-libs
qrencode-libs
exiv2
djvulibre-libs
gvfs-gphoto2
libgphoto2
libmediaart
leptonica
PKGS

# --- Browsers / Web / Networking tools ---
run_remove_category "browsers" <<'PKGS'
bind-utils
dnsmasq
dhcp-client
dhcp-common
mtr
net-snmp-libs
rsync
wget2
wget2-libs
wget2-wget
#curl
PKGS

# --- NetworkManager / VPN / Remote access ---
run_remove_category "networking" <<'PKGS'
NetworkManager-adsl
NetworkManager-bluetooth
NetworkManager-openconnect
NetworkManager-openconnect-gnome
NetworkManager-openvpn
NetworkManager-openvpn-gnome
NetworkManager-ppp
NetworkManager-ssh
NetworkManager-ssh-gnome
NetworkManager-vpnc
NetworkManager-vpnc-gnome
NetworkManager-wwan
nm-connection-editor
openvpn
openconnect
slirp4netns
open-vm-tools
open-vm-tools-desktop
qemu-guest-agent
qemu-user-static-aarch64
spice-vdagent
spice-webdavd
samba-client
smbclient
PKGS

# --- Virtualization & Containers ---
run_remove_category "virtualization" <<'PKGS'
virtualbox-guest-additions
toolbox
systemd-container
fuse
fuse-overlayfs
slirp4netns
open-vm-tools
open-vm-tools-desktop
qemu-guest-agent
qemu-user-static-aarch64
PKGS

# --- Hardware / Modems / Bluetooth / USB ---
run_remove_category "hardware" <<'PKGS'
bluez
bluez-cups
bluez-obexd
ModemManager
usb_modeswitch
usb_modeswitch-data
libmbim-utils
libqmi-utils
libpcap
libvncserver
libwinpr
libiec61883
libavc1394
libdc1394
libraw1394
ipp-usb
bolt
hyperv-daemons
hyperv-daemons-license
hypervfcopyd
hypervkvpd
hypervvssd
PKGS

# --- Accessibility / Input / IBus / Speech / Braille ---
run_remove_category "accessibility" <<'PKGS'
braille-printer-app
brlapi
brltty
orca
speech-dispatcher
speech-dispatcher-espeak-ng
speech-dispatcher-libs
speech-dispatcher-utils
espeak-ng
fprintd
fprintd-pam
libfprint
python3-brlapi
python3-pyatspi
python3-louis
liblouisutdml-utils
ibus-anthy
ibus-anthy-python
ibus-gtk4
ibus-hangul
ibus-libpinyin
ibus-m17n
ibus-typing-booster
orca
PKGS

# --- System services / Daemons / HTTP ---
run_remove_category "system-services" <<'PKGS'
httpd
httpd-core
httpd-filesystem
httpd-tools
mod_dnssd
mod_http2
mod_lua
realmd
PackageKit-glib
sos
passim
mtr
rsync
PKGS

# --- System & Kernel tools / Storage / LVM / Filesystems ---
run_remove_category "system-kernel" <<'PKGS'
kpartx
lvm2
lvm2-libs
kernel-modules-extra
kernel-tools
kernel-tools-libs
xfsprogs
ntfs-3g
ntfs-3g-system-compression
ntfsprogs
nilfs-utils
udftools
tar
unzip
zip
ppp
slirp4netns
PKGS

# --- Security / Auth / SSSD / SSH / PAM / PKI ---
run_remove_category "security" <<'PKGS'
sudo-python-plugin
sssd-common
sssd-kcm
sssd-krb5-common
sssd-nfs-idmap
libsss_certmap
libsss_sudo
openssh-server
sudo
cracklib-dicts
libdnf5-plugin-expired-pgp-keys
realmd
policycoreutils-devel
openconnect
openvpn
PKGS

# --- Libraries (misc low-level libraries) ---
run_remove_category "libraries" <<'PKGS'
apr
apr-util
apr-util-lmdb
apr-util-openssl
libcaca
libijs
libmspack
libzip
libgee
libimagequant
libmbim-utils
libmediaart
libqmi-utils
libslirp
libwmf-lite
libgs
libhangul
libfprint
libXpm
libppd
libpaper
libraw1394
libavc1394
libdnf5-plugin-expired-pgp-keys
libraqm
LibRaw
PKGS

# --- Language packs / Spell / Fonts / Locale ---
run_remove_category "language-packs" <<'PKGS'
langpacks-core-en
langpacks-en
langpacks-fonts-en
hunspell-en
langtable
gawk-all-langpacks
python3-langtable
unicode-ucd
words
PKGS

# --- Python & runtime packages ---
run_remove_category "python-runtime" <<'PKGS'
python-unversioned-command
python3-boto3
python3-click
python3-cups
python3-enchant
python3-olefile
python3-packaging
python3-pexpect
python3-pillow
python3-regex
python3-requests
python3-speechd
python3-urllib3+socks
python3-brlapi
python3-pyatspi
python3-louis
python3-langtable
PKGS

# --- Developer / Build / Tools / CLI ---
run_remove_category "developer-tools" <<'PKGS'
git-core-doc
rpm-build-libs
rsync
tar
unzip
vim-data
vim-minimal
qpdf-libs
qrencode-libs
libcaca
gd
mtr
sos
thermald
tuned
tuned-ppd
mod_http2
mod_lua
passim
PKGS

# --- Smart card / PC/SC / Security tokens ---
run_remove_category "smartcard" <<'PKGS'
pcsc-lite
pcsc-lite-ccid
pcsc-lite-libs
opensc
opensc-libs
pcsc-lite
pcsc-lite-ccid
pcsc-lite-libs
PKGS

# --- Printing/Office helpers / Poppler / PDF ---
run_remove_category "pdf" <<'PKGS'
poppler-cpp
poppler-utils
qpdf-libs
ghostscript
ghostscript-tools-printing
exiv2
djvulibre-libs
PKGS

# --- Misc utilities & extras (remaining miscellaneous packages) ---
run_remove_category "misc" <<'PKGS'
cifs-utils-info
gawk-all-langpacks
gd
geolite2-city
geolite2-country
gamemode
ImageMagick-libs
ipp-usb
jbig2dec-libs
libcaca
libgphoto2
libmbim-utils
libmspack
libpcap
mailcap
malcontent-control
malcontent-ui-libs
mod_dnssd
mozilla-filesystem
net-snmp-libs
nilfs-utils
#noopenh264
open-vm-tools
open-vm-tools-desktop
passim
ppp
pulseaudio-utils
qadwaitadecorations-qt5
realmd
rygel
samba-client
slirp4netns
sos
spice-vdagent
spice-webdavd
sudo-python-plugin
systemd-container
tcl
thermald
toolbox
totem-video-thumbnailer
udftools
unicode-ucd
usb_modeswitch
usb_modeswitch-data
virtualbox-guest-additions
vpnc
vpnc-script
wget2-wget
words
xfsprogs
zip
PKGS