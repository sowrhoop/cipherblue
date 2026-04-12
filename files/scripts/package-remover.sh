#!/usr/bin/env bash
set -eou pipefail

# ==============================================================================
# ATOMIC PACKAGE REMOVER ENGINE (Strict Verification Mode)
# Strictly removes installed packages and dependencies. 
# Verifies complete removal against the RPM database. Aborts on ANY leftover.
# ==============================================================================

if ! command -v dnf5 >/dev/null 2>&1; then
  echo "::error::dnf5 is required but not found in PATH. Aborting."
  exit 1
fi

# Housekeeping: Remove sudo protection rule so it can be uninstalled if requested
rm -f /etc/dnf/protected.d/sudo.conf || true

remove_category() {
  local name="$1"
  local raw pkgs installed_cache
  
  if [ "${GITHUB_ACTIONS:-}" == "true" ]; then
    echo "::group::Removing Category: $name"
  else
    echo "=== START: $name ==="
  fi

  # Read packages from stdin, ignoring comments and blank lines
  raw=$(grep -v '^\s*#' | tr '\n' ' ' | sed 's/  */ /g' | sed 's/^ //; s/ $//')
  
  if [ -z "$raw" ]; then
    echo "No packages defined."
    if [ "${GITHUB_ACTIONS:-}" == "true" ]; then echo "::endgroup::"; fi
    return 0
  fi

  # Build a precise cache of exactly what is installed right now
  installed_cache=$(mktemp)
  rpm -qa --queryformat "%{NAME}\n" > "$installed_cache"
  
  pkgs=()
  for pkg in $raw; do
    if grep -qx "$pkg" "$installed_cache" 2>/dev/null; then
      pkgs+=("$pkg")
    fi
  done
  rm -f "$installed_cache"

  if [ "${#pkgs[@]}" -eq 0 ]; then
    echo "None of the specified packages are currently installed. Skipping."
    if [ "${GITHUB_ACTIONS:-}" == "true" ]; then echo "::endgroup::"; fi
    return 0
  fi

  echo "Executing atomic removal for: ${pkgs[*]}"
  
  # Execute strict, atomic removal. 
  # clean_requirements_on_remove=True ensures dependencies aren't left behind as an attack surface.
  # We temporarily disable 'set -e' because offline container scriptlets frequently return 1.
  set +e
  dnf5 remove -y --setopt=protected_packages= --setopt=clean_requirements_on_remove=True "${pkgs[@]}"
  local dnf_rc=$?
  set -e

  # ============================================================================
  # STRICT VERIFICATION PASS
  # DNF5 often returns an error (exit 1) in container builds due to harmless 
  # %postun scriptlet failures (e.g., trying to restart systemd services).
  # We must strictly query the RPM db to ensure no attack surface remains.
  # ============================================================================
  local remaining=()
  for pkg in "${pkgs[@]}"; do
    # If the package is still found in the database, the uninstall failed
    if rpm -q "$pkg" >/dev/null 2>&1; then
      remaining+=("$pkg")
    fi
  done

  if [ "${#remaining[@]}" -ne 0 ]; then
    echo "::error::Atomic removal failed for category: $name"
    echo "::error::The following packages failed to uninstall completely and remain an attack surface: ${remaining[*]}"
    echo "::error::Aborting build to prevent insecure/inconsistent state."
    exit 1
  fi

  if [ "$dnf_rc" -ne 0 ]; then
    echo "::notice::dnf5 returned non-zero ($dnf_rc) due to a non-critical offline scriptlet error, but strict verification confirms all packages were fully and safely removed."
  fi

  echo "=== SUCCESS: $name ==="
  if [ "${GITHUB_ACTIONS:-}" == "true" ]; then
    echo "::endgroup::"
  fi
}

# --- Desktop / GNOME / Shell ---
remove_category "desktop" <<'PKGS'
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
ptyxis
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
PKGS

# --- Printing / Scanning ---
remove_category "printing" <<'PKGS'
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
remove_category "multimedia" <<'PKGS'
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
remove_category "browsers" <<'PKGS'
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
PKGS

# --- NetworkManager / VPN / Remote access ---
remove_category "networking" <<'PKGS'
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
remove_category "virtualization" <<'PKGS'
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
remove_category "hardware" <<'PKGS'
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
remove_category "accessibility" <<'PKGS'
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
PKGS

# --- System services / Daemons / HTTP ---
remove_category "system-services" <<'PKGS'
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
remove_category "system-kernel" <<'PKGS'
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
remove_category "security" <<'PKGS'
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
remove_category "libraries" <<'PKGS'
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
remove_category "language-packs" <<'PKGS'
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
remove_category "python-runtime" <<'PKGS'
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
remove_category "developer-tools" <<'PKGS'
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
remove_category "smartcard" <<'PKGS'
pcsc-lite
pcsc-lite-ccid
pcsc-lite-libs
opensc
opensc-libs
PKGS

# --- Printing/Office helpers / Poppler / PDF ---
remove_category "pdf" <<'PKGS'
poppler-cpp
poppler-utils
qpdf-libs
ghostscript
ghostscript-tools-printing
exiv2
djvulibre-libs
PKGS

# --- Misc utilities & extras (remaining miscellaneous packages) ---
remove_category "misc" <<'PKGS'
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

echo "::notice::All specified package categories removed successfully and verified securely."