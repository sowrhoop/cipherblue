#!/usr/bin/env bash

set -oue pipefail

dnf5 config-manager addrepo --from-repofile="https://repo.secureblue.dev/secureblue.repo"
dnf5 install --setopt=install_weak_deps=False gnome-tweaks trivalent tlp -y
rm -f /etc/dnf/protected.d/sudo.conf
dnf5 remove bluez bluez-cups bluez-obexd systemd-container adobe-mappings-cmap-deprecated adobe-mappings-pdf apr apr-util apr-util-lmdb apr-util-openssl avahi-gobject avahi-tools avif-pixbuf-loader bind-utils bolt braille-printer-app brlapi brltty cifs-utils-info cracklib-dicts cups cups-browsed cups-client cups-filters cups-filters-driverless cups-ipptool default-fonts-am default-fonts-ar default-fonts-as default-fonts-ast default-fonts-be default-fonts-bg default-fonts-bn default-fonts-bo default-fonts-br default-fonts-chr default-fonts-cjk-mono default-fonts-cjk-sans default-fonts-cjk-serif default-fonts-core-emoji default-fonts-core-math default-fonts-core-mono default-fonts-core-serif default-fonts-dv default-fonts-dz default-fonts-el default-fonts-eo default-fonts-eu default-fonts-fa default-fonts-gu default-fonts-he default-fonts-hi default-fonts-hy default-fonts-ia default-fonts-iu default-fonts-ka default-fonts-km default-fonts-kn default-fonts-ku default-fonts-lo default-fonts-mai default-fonts-ml default-fonts-mni default-fonts-mr default-fonts-my default-fonts-nb default-fonts-ne default-fonts-nn default-fonts-nr default-fonts-nso default-fonts-or default-fonts-other-mono default-fonts-other-sans default-fonts-other-serif default-fonts-pa default-fonts-ru default-fonts-sat default-fonts-si default-fonts-ss default-fonts-ta default-fonts-te default-fonts-th default-fonts-tn default-fonts-ts default-fonts-uk default-fonts-ur default-fonts-ve default-fonts-vi default-fonts-xh default-fonts-yi default-fonts-zu desktop-backgrounds-gnome dhcp-client dhcp-common djvulibre-libs dnsmasq elfutils-debuginfod-client epiphany-runtime espeak-ng evince-djvu evince-libs evince-previewer evince-thumbnailer exiv2 fedora-bookmarks fedora-chromium-config fedora-chromium-config-gnome fedora-flathub-remote fedora-repos-archive fedora-third-party fedora-workstation-backgrounds fedora-workstation-repositories ffmpeg-free firefox firefox-langpacks fprintd fprintd-pam freerdp-libs fuse fuse-overlayfs gamemode gawk-all-langpacks gd gdouros-symbola-fonts geolite2-city geolite2-country ghostscript ghostscript-tools-fonts ghostscript-tools-printing git-core-doc gnome-backgrounds gnome-bluetooth gnome-browser-connector gnome-classic-session gnome-color-manager gnome-epub-thumbnailer gnome-remote-desktop gnome-shell-extension-apps-menu gnome-shell-extension-background-logo gnome-shell-extension-common gnome-shell-extension-launch-new-instance gnome-shell-extension-places-menu gnome-shell-extension-window-list gnome-software gnome-software-rpm-ostree gnome-tour gnome-user-docs gnome-user-share google-droid-sans-fonts google-noto-naskh-arabic-vf-fonts google-noto-sans-arabic-vf-fonts google-noto-sans-armenian-vf-fonts google-noto-sans-bengali-vf-fonts google-noto-sans-canadian-aboriginal-vf-fonts google-noto-sans-cherokee-vf-fonts google-noto-sans-cjk-vf-fonts google-noto-sans-devanagari-vf-fonts google-noto-sans-ethiopic-vf-fonts google-noto-sans-georgian-vf-fonts google-noto-sans-gujarati-vf-fonts google-noto-sans-gurmukhi-vf-fonts google-noto-sans-hebrew-vf-fonts google-noto-sans-kannada-vf-fonts google-noto-sans-khmer-vf-fonts google-noto-sans-lao-vf-fonts google-noto-sans-math-fonts google-noto-sans-mono-cjk-vf-fonts google-noto-sans-ol-chiki-vf-fonts google-noto-sans-oriya-vf-fonts google-noto-sans-sinhala-vf-fonts google-noto-sans-tamil-vf-fonts google-noto-sans-telugu-vf-fonts google-noto-sans-thaana-vf-fonts google-noto-sans-thai-vf-fonts google-noto-serif-armenian-vf-fonts google-noto-serif-bengali-vf-fonts google-noto-serif-cjk-vf-fonts google-noto-serif-devanagari-vf-fonts google-noto-serif-ethiopic-vf-fonts google-noto-serif-georgian-vf-fonts google-noto-serif-gujarati-vf-fonts google-noto-serif-gurmukhi-vf-fonts google-noto-serif-hebrew-vf-fonts google-noto-serif-kannada-vf-fonts google-noto-serif-khmer-vf-fonts google-noto-serif-lao-vf-fonts google-noto-serif-oriya-vf-fonts google-noto-serif-sinhala-vf-fonts google-noto-serif-tamil-vf-fonts google-noto-serif-telugu-vf-fonts google-noto-serif-thai-vf-fonts gspell gst-editing-services gstreamer1-plugin-libav gstreamer1-plugins-bad-free gstreamer1-plugins-good-qt gstreamer1-plugins-ugly-free gtkmm3.0 gupnp-av gupnp-dlna gutenprint gutenprint-cups gutenprint-libs gvfs-afc gvfs-afp gvfs-archive gvfs-fuse gvfs-gphoto2 gvfs-smb hplip hplip-common hplip-libs httpd httpd-core httpd-filesystem httpd-tools hunspell-en hyperv-daemons hyperv-daemons-license hypervfcopyd hypervkvpd hypervvssd ibus-anthy ibus-anthy-python ibus-gtk4 ibus-hangul ibus-libpinyin ibus-m17n ibus-typing-booster ImageMagick ImageMagick-libs ipp-usb jbig2dec-libs jomolhari-fonts julietaula-montserrat-fonts jxl-pixbuf-loader kasumi-unicode kernel-modules-extra kernel-tools kernel-tools-libs kpartx langpacks-core-en langpacks-en langpacks-fonts-en langtable leptonica libavc1394 libavdevice-free libavfilter-free libcaca libcupsfilters libdc1394 liberation-mono-fonts liberation-sans-fonts liberation-serif-fonts libfprint libgee libgphoto2 libgs libhangul libiec61883 libijs libimagequant liblouisutdml-utils libmbim-utils libmediaart libmspack libpaper libpcap libpinyin libpinyin-data libppd libqmi-utils libraqm LibRaw libraw1394 libsane-airscan libsane-hpaio libslirp libspectre libsss_certmap libsss_sudo libvncserver libwinpr libwmf-lite libXpm libzip linux-atm-libs lvm2 lvm2-libs m17n-lib madan-fonts mailcap malcontent-control malcontent-ui-libs mod_dnssd mod_http2 mod_lua ModemManager mozilla-filesystem mtr net-snmp-libs NetworkManager-adsl NetworkManager-bluetooth NetworkManager-openconnect NetworkManager-openconnect-gnome NetworkManager-openvpn NetworkManager-openvpn-gnome NetworkManager-ppp NetworkManager-pptp NetworkManager-pptp-gnome NetworkManager-ssh NetworkManager-ssh-gnome NetworkManager-vpnc NetworkManager-vpnc-gnome NetworkManager-wwan nilfs-utils nm-connection-editor noopenh264 ntfs-3g ntfs-3g-system-compression ntfsprogs open-sans-fonts open-vm-tools open-vm-tools-desktop openconnect opensc opensc-libs openssh-server openvpn orca PackageKit-glib paktype-naskh-basic-fonts passim pcsc-lite pcsc-lite-ccid pcsc-lite-libs poppler-cpp poppler-utils ppp pptp pulseaudio-utils python-unversioned-command python3-boto3 python3-brlapi python3-click python3-cups python3-enchant python3-langtable python3-louis python3-olefile python3-packaging python3-pexpect python3-pillow python3-pyatspi python3-regex python3-requests python3-speechd python3-urllib3+socks qadwaitadecorations-qt5 qemu-guest-agent qemu-user-static-aarch64 qpdf-libs qrencode-libs qt-settings qt5-filesystem qt5-qtbase qt5-qtbase-common qt5-qtbase-gui qt5-qtdeclarative qt5-qtsvg qt5-qttranslations qt5-qtwayland qt5-qtx11extras qt5-qtxmlpatterns realmd rit-meera-new-fonts rit-rachana-fonts rpm-build-libs rsync rygel samba-client sane-airscan sane-backends sane-backends-drivers-cameras sane-backends-drivers-scanners sane-backends-libs sil-padauk-fonts slirp4netns sos speech-dispatcher speech-dispatcher-espeak-ng speech-dispatcher-libs speech-dispatcher-utils spice-vdagent spice-webdavd sssd-common sssd-kcm sssd-krb5-common sssd-nfs-idmap stix-fonts sudo sudo-python-plugin system-config-printer-libs system-config-printer-udev tar tcl tesseract-libs texlive-lib thermald toolbox totem-video-thumbnailer tuned tuned-ppd udftools unicode-ucd unzip urw-base35-bookman-fonts urw-base35-c059-fonts urw-base35-d050000l-fonts urw-base35-fonts urw-base35-fonts-common urw-base35-gothic-fonts urw-base35-nimbus-mono-ps-fonts urw-base35-nimbus-roman-fonts urw-base35-nimbus-sans-fonts urw-base35-p052-fonts urw-base35-standard-symbols-ps-fonts urw-base35-z003-fonts usb_modeswitch usb_modeswitch-data vazirmatn-vf-fonts vim-data vim-minimal virtualbox-guest-additions vpnc vpnc-script wget2 wget2-libs wget2-wget words xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm xdriinfo xfsprogs yelp yelp-libs yelp-xsl zip -y
dnf5 remove crun buildah yajl -y
dnf5 install --setopt=install_weak_deps=False openh264 -y
