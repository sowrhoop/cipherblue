#!/usr/bin/env bash
set -oue pipefail

# Log directory (change by setting LOG_DIR env var)
LOG_DIR=${LOG_DIR:-/var/log/cipherblue}
mkdir -p "$LOG_DIR"

# Helper: read package names from stdin, ignore lines starting with # and empty lines,
# then call dnf5 remove on the remaining packages. This allows you to comment packages
# inside the heredoc for testing without breaking shell line-continuation.
remove_pkgs() {
  local pkgs
  pkgs=$(grep -v '^\s*#' | tr '\n' ' ' | sed 's/  */ /g' | sed 's/^ //; s/ $//')
  if [ -z "$pkgs" ]; then
    echo "No packages to remove (all lines were comments/blank)" >&2
    return 0
  fi
  echo "Removing packages: $pkgs"
  dnf5 remove -y $pkgs
}

# Run a single category (reads package list from stdin).
# Usage: run_remove_category "category-key" <<'PKGS' ... PKGS
# If CATEGORY env var is set, only the matching category will be executed.
# Logs are appended to $LOG_DIR/package-hardening-<category>.log
failures=()
run_remove_category() {
  local name="$1"; shift
  local logfile="$LOG_DIR/package-hardening-${name// /_}.log"

  echo "=== START: $name ===" | tee -a "$logfile"

  # If CATEGORY is set and doesn't match, skip this category
  if [ -n "${CATEGORY:-}" ] && [ "$CATEGORY" != "$name" ]; then
    echo "Skipping category '$name' (CATEGORY='$CATEGORY')" | tee -a "$logfile"
    return 0
  fi

  # Call remove_pkgs reading from this function's stdin (the heredoc).
  # Capture output to logfile and capture exit status of remove_pkgs using PIPESTATUS.
  remove_pkgs 2>&1 | tee -a "$logfile"
  local rc=${PIPESTATUS[0]:-1}

  if [ "$rc" -eq 0 ]; then
    echo "=== SUCCESS: $name ===" | tee -a "$logfile"
  else
    echo "=== FAILURE ($rc): $name ===" | tee -a "$logfile"
    failures+=("$name:$rc")
  fi
}

# add repo & housekeeping (unchanged)
dnf5 config-manager addrepo --from-repofile="https://repo.secureblue.dev/secureblue.repo"
rm -f /etc/dnf/protected.d/sudo.conf

# --- Desktop / GNOME / Shell ---
run_remove_category "desktop" <<'PKGS'
nautilus-extensions
desktop-backgrounds-gnome
fedora-bookmarks
fedora-workstation-backgrounds
gnome-backgrounds
#gnome-classic-session
#gnome-color-manager
gnome-tour
#gnome-user-docs
#gnome-user-share
#gnome-disk-utility
gnome-software
gnome-software-rpm-ostree
#gnome-remote-desktop
#gnome-browser-connector
#epiphany-runtime
firefox
firefox-langpacks
mozilla-filesystem
fedora-chromium-config
fedora-chromium-config-gnome
fedora-flathub-remote
fedora-repos-archive
fedora-third-party
fedora-workstation-repositories
#gnome-epub-thumbnailer
gnome-shell-extension-apps-menu
gnome-shell-extension-background-logo
gnome-shell-extension-common
gnome-shell-extension-launch-new-instance
gnome-shell-extension-places-menu
gnome-shell-extension-window-list
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
#gtkmm3.0
#xcb-util-image
#xcb-util-keysyms
#xcb-util-renderutil
#xcb-util-wm
#xdriinfo
yelp
yelp-libs
yelp-xsl
nautilus-extensions
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
curl
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
sssd-common
sssd-kcm
sssd-krb5-common
sssd-nfs-idmap
libsss_certmap
libsss_sudo
openssh-server
sudo-python-plugin
cracklib-dicts
libdnf5-plugin-expired-pgp-keys
realmd
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
selinux-policy-devel
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
noopenh264
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