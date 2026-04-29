# 🛡️ Cipherblue Sync Telemetry Report
*Auto-generated during the CI/CD pipeline run to provide complete visibility into the Sync Engine state machine.*

## 🔒 The Local Vault (Preserved Local Files)
These files exist in our repo. If upstream pushes a file with the exact same name, the Sync Engine **blocks** the upstream version to protect our custom code.

- `.git`
- `.github/workflows/cipherblue-build.yml`
- `.github/workflows/cipherblue-sync.yml`
- `LICENSE`
- `README.md`
- `cosign.pub`
- `cipherblue-sync/cipherblue-exclude.txt`
- `cipherblue-sync/cipherblue-preserve.txt`
- `cipherblue-sync/cipherblue-sync.sh`
- `cipherblue-sync/upstream-preserve.txt`
- `recipes/recipe-cipherblue.yml`
- `files/scripts/authselect-hardening.sh`
- `files/scripts/cipherblue-cleanup.sh`
- `files/scripts/cipherblue-compile-dconf.sh`
- `files/scripts/package-remover.sh`
- `files/scripts/permission-hardening.sh`
- `files/scripts/selinux-hardening.sh`
- `files/scripts/suid-hardening.sh`
- `files/scripts/systemd-hardening.sh`
- `files/scripts/cipherblue-private.sh`
- `files/system/etc/modprobe.d/cipherblue-blacklist.conf`
- `files/system/etc/NetworkManager/conf.d/60-cipherblue.conf`
- `files/system/etc/NetworkManager/conf.d/99-disable-connectivity.conf`
- `files/system/etc/profile.d/cipherblue_umask.sh`
- `files/system/etc/security/limits.d/60-cipherblue.conf`
- `files/system/etc/sysctl.d/60-cipherblue-hardening.conf`
- `files/system/etc/systemd/resolved.conf.d/99-cipherblue-dns.conf`
- `files/system/etc/systemd/system/cipher-cleaner.service.d/cipherblue.conf`
- `files/system/etc/systemd/system/cipher-remount.service.d`
- `files/system/etc/systemd/system.conf.d/50-cipherblue-defaults.conf`
- `files/system/etc/systemd/user.conf.d/50-cipherblue-defaults.conf`
- `files/system/etc/systemd/zram-generator.conf`
- `files/system/etc/tlp.d/cipherblue.conf`
- `files/system/etc/tmpfiles.d/99-cipherblue-proc.conf`
- `files/system/etc/tmpfiles.d/99-cipherblue-sys.conf`
- `files/system/etc/trivalent/policies/managed/cipherblue.json`
- `files/system/etc/trivalent/trivalent.conf`
- `files/system/etc/xdg/autostart/cipherblue-mute-mic.desktop`
- `files/system/etc/environment`
- `files/system/etc/securetty`
- `files/system/etc/systemd/coredump.conf.d/disable-coredump.conf`
- `files/system/usr/share/xdg-desktop-portal/gnome-portals.conf`
- `files/system/etc/containers/policy.json`
- `files/system/usr/lib/systemd/system/cipher-cleaner.service`
- `files/system/etc/dconf/db/local.d/locks/00-cipherblue-locks`
- `files/system/etc/dconf/db/local.d/00-cipherblue-settings`
- `files/system/etc/dconf/profile/user`
- `files/system/etc/systemd/system/user@.service.d/99-cipher-run-hardening.conf`
- `files/system/etc/udisks2/mount_options.conf`
- `files/system/etc/polkit-1/rules.d/00-cipherblue-appliance.rules`
- `files/system/etc/tmpfiles.d/99-cipherblue-dns.conf`
- `files/system/usr/lib/systemd/system/cipher-flatpak-vault.service`
- `files/system/usr/lib/systemd/system/cipher-mount-enforcer.service`
- `files/system/usr/libexec/cipherblue/cipher-flatpak-vault.sh`
- `files/system/etc/systemd/logind.conf.d/99-cipherblue-tty-lockdown.conf`
- `files/system/etc/profile.d/99-cipherblue-kill-shell.sh`
- `files/system/usr/lib/systemd/system/cipher-secure-rebase.service`
- `files/system/usr/libexec/cipherblue/cipher-secure-rebase.sh`
- `files/system/etc/systemd/system/rpm-ostreed-automatic.timer.d/99-cipherblue-aggressive.conf`
- `files/system/usr/libexec/cipherblue/verify-provenance.sh`
- `files/system/usr/lib/systemd/system-preset/35-cipherblue-desktop.preset`
- `files/system/usr/lib/systemd/system-preset/40-cipherblue.preset`
- `files/system/usr/lib/systemd/user-preset/35-cipherblue-desktop.preset`
- `files/system/etc/systemd/system/rpm-ostreed-automatic.service.d/override.conf`
- `files/system/etc/systemd/journald.conf.d/60-cipherblue-privacy.conf`
- `files/system/usr/lib/systemd/system/cipherblue-sentinel.service`
- `files/system/usr/libexec/cipherblue/sentinel-daemon.sh`
- `files/system/usr/lib/systemd/system/cipher-cleanup.service`
- `files/system/usr/lib/systemd/system/cipher-cleanup.timer`
- `files/system/usr/lib/systemd/system/cipher-flatpak-update.service`
- `files/system/usr/lib/systemd/system/cipher-flatpak-update.timer`
- `files/system/usr/libexec/cipherblue/cipher-cleanup.sh`
- `files/system/usr/libexec/cipherblue/cipher-flatpak-update.sh`
- `files/system/usr/lib/systemd/system/cipher-grub-lockdown.service`
- `files/system/usr/libexec/cipherblue/cipher-grub-lockdown.sh`
- `files/system/usr/lib/systemd/system/cipher-kargs-reconciler.service`
- `files/system/usr/libexec/cipherblue/cipher-kargs-reconciler.sh`
- `files/system/usr/lib/systemd/system/cipher-audit-drift.service`
- `files/system/usr/lib/systemd/system/cipher-audit-drift.timer`
- `files/system/usr/lib/systemd/system/cipher-firmware-update.service`
- `files/system/usr/lib/systemd/system/cipher-firmware-update.timer`
- `files/system/usr/libexec/cipherblue/cipher-audit-drift.sh`
- `files/system/usr/libexec/cipherblue/cipher-firmware-update.sh`
- `files/system/usr/libexec/cipherblue/cipher-firstboot-init.sh`
- `files/system/usr/lib/systemd/system/cipher-firstboot-init.service`
- `files/system/usr/libexec/cipherblue/cipher-core.sh`
- `files/system/usr/libexec/cipherblue/cipher-user-env-lockdown.sh`
- `files/system/usr/lib/systemd/system/cipher-user-env-lockdown.service`
- `files/system/etc/systemd/user/xdg-user-dirs.service.d/override.conf`
- `files/system/etc/rpm-ostreed.conf`
- `files/system/etc/systemd/system/dev-hugepages.mount.d/override.conf`
- `files/system/etc/systemd/system/dev-mqueue.mount.d/override.conf`
- `files/system/etc/systemd/system/tmp.mount.d/override.conf`
- `modules/cipherblue-signing/cipherblue-signing.sh`
- `modules/cipherblue-signing/module.yml`
- `modules/cipherblue-signing/registry-config.yaml`

## ⚡ The Laser Scalpel (Force-Synced Files)
These files are explicitly ripped from upstream and pulled into our OS, mathematically bypassing all blanket exclusions.

- `files/system/usr/share/pki/rpm-gpg/cipherblue.gpg`
- `files/system/etc/yum.repos.d/repo.cipherblue.dev.cipherblue.repo`
- `files/system/usr/share/pki/rpm-gpg/cipherblue-copr-pubkey.gpg`
- `files/system/etc/yum.repos.d/cipherblue-packages-fedora.repo`
- `files/system/usr/lib/udev/rules.d/99-cipherblue.rules`

## ✂️ The Great Wall (Excluded Upstream Files)
These files and directories were completely annihilated from the upstream pull. Click the dropdowns to see the exact upstream files that were dropped by the wildcard rules.

<details><summary><b>Excluded Rule: <code>/.github/**</code></b></summary>

```text
  - .github/CODEOWNERS
  - .github/ISSUE_TEMPLATE/bug_report.yml
  - .github/ISSUE_TEMPLATE/config.yml
  - .github/ISSUE_TEMPLATE/feature_request.yml
  - .github/dependabot.yml
  - .github/semantic.yml
  - .github/workflows/automod.yml
  - .github/workflows/build-all.yml
  - .github/workflows/build-one-recipe.yml
  - .github/workflows/check-rpm-repos.yml
  - .github/workflows/cleanup.yml
  - .github/workflows/config/linkspector.yml
  - .github/workflows/config/lorax/remove_root_password_prompt.tmpl
  - .github/workflows/integration_tests.yml
  - .github/workflows/integration_tests/check_audit_results.sh
  - .github/workflows/integration_tests/check_cleanup.sh
  - .github/workflows/integration_tests/check_flatpak_setup.sh
  - .github/workflows/integration_tests/check_unbound_migration.sh
  - .github/workflows/integration_tests/expected-audit-silverblue-main-hardened.txt
  - .github/workflows/integration_tests/validate_systemd_unit_files.sh
  - .github/workflows/iso.yml
  - .github/workflows/isos/prep_initramfs.sh
  - .github/workflows/isos/prep_rootfs.sh
  - .github/workflows/justlint.yml
  - .github/workflows/linkspector.yml
  - .github/workflows/pr_build.yml
  - .github/workflows/pr_build_all_main.yml
  - .github/workflows/pr_build_minimal.yml
  - .github/workflows/pr_build_nvidia.yml
  - .github/workflows/pr_build_zfs.yml
  - .github/workflows/private_key.priv.test
  - .github/workflows/provenance.yml
  - .github/workflows/public_key.der.test
  - .github/workflows/python-lint.yml
  - .github/workflows/scorecard.yml
  - .github/workflows/shared-runner-setup/action.yml
  - .github/workflows/tests.yml
  - .github/workflows/tests/justfile_tests.bats
  - .github/workflows/tests/motd_tests.bats
  - .github/workflows/trivy.yml
  - .github/workflows/update-modules.yml
  - .github/workflows/update-po.yml
  - .github/workflows/validate_exec_bit.yml
  - .github/workflows/zizmor.yml
```
</details>

<details><summary><b>Excluded Rule: <code>/LICENSES</code></b></summary>

```text
  - LICENSES/Apache-2.0.txt
  - LICENSES/BSD-2-Clause.txt
  - LICENSES/BSD-3-Clause.txt
  - LICENSES/GPL-2.0-or-later.txt
  - LICENSES/GPL-3.0-or-later.txt
  - LICENSES/LGPL-2.1-or-later.txt
  - LICENSES/MIT.txt
```
</details>

<details><summary><b>Excluded Rule: <code>/docs</code></b></summary>

```text
  - docs/CODE_OF_CONDUCT.md
  - docs/README.md
  - docs/SECURITY.md
  - docs/cipherblue.png
  - docs/cipherblue.svg
  - docs/example.butane
```
</details>

<details><summary><b>Excluded Rule: <code>/recipes/iot</code></b></summary>

```text
  - recipes/iot/recipe-iot-main.yml
  - recipes/iot/recipe-iot-nvidia-open.yml
  - recipes/iot/recipe-iot-nvidia.yml
  - recipes/iot/recipe-iot-zfs-main.yml
  - recipes/iot/recipe-iot-zfs-nvidia-open.yml
  - recipes/iot/recipe-iot-zfs-nvidia.yml
```
</details>

<details><summary><b>Excluded Rule: <code>/recipes/securecore</code></b></summary>

```text
  - recipes/securecore/recipe-securecore-main.yml
  - recipes/securecore/recipe-securecore-nvidia-open.yml
  - recipes/securecore/recipe-securecore-nvidia.yml
  - recipes/securecore/recipe-securecore-zfs-main.yml
  - recipes/securecore/recipe-securecore-zfs-nvidia-open.yml
  - recipes/securecore/recipe-securecore-zfs-nvidia.yml
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/bin/ugum</code></b></summary>

```text
  - files/system/usr/bin/ugum
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/bin/ujust</code></b></summary>

```text
  - files/system/usr/bin/ujust
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/share/bash-completion/completions/ujust</code></b></summary>

```text
  - files/system/usr/share/bash-completion/completions/ujust
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/share/fish/**</code></b></summary>

```text
  - files/system/usr/share/fish/vendor_completions.d/ujust.fish
```
</details>

<details><summary><b>Excluded Rule: <code>**/.just</code></b></summary>

```text
  (No upstream files matched this rule during this sync commit)
```
</details>

<details><summary><b>Excluded Rule: <code>**/.py</code></b></summary>

```text
  (No upstream files matched this rule during this sync commit)
```
</details>

<details><summary><b>Excluded Rule: <code>**/*.patch</code></b></summary>

```text
  (No upstream files matched this rule during this sync commit)
```
</details>

<details><summary><b>Excluded Rule: <code>files/justfiles/**</code></b></summary>

```text
  - files/justfiles/common/luks.just
  - files/justfiles/common/toggles.just
  - files/justfiles/common/utilities.just
  - files/justfiles/common/wrappers.just
  - files/justfiles/desktop/desktop.just
  - files/justfiles/desktop/flatpak.just
  - files/justfiles/desktop/steam.just
  - files/justfiles/kinoite.just
  - files/justfiles/nvidia/kargs.just
  - files/justfiles/silverblue.just
```
</details>

<details><summary><b>Excluded Rule: <code>files/po/**</code></b></summary>

```text
  - files/po/audit_cipherblue.pot
  - files/po/de/audit_cipherblue.po
  - files/po/en/audit_cipherblue.po
  - files/po/es/audit_cipherblue.po
  - files/po/pl/audit_cipherblue.po
  - files/po/po-source-files.json
  - files/po/pt/audit_cipherblue.po
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/cosmic/**</code></b></summary>

```text
  - files/system/cosmic/usr/share/cosmic/com.system76.CosmicAppList/v1/favorites
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/kinoite/**</code></b></summary>

```text
  - files/system/kinoite/etc/systemd/user/plasma-kwin_wayland.service.d/override.conf
  - files/system/kinoite/etc/xdg/kdeglobals
  - files/system/kinoite/etc/xdg/ksplashrc
  - files/system/kinoite/etc/xdg/kwinrc
  - files/system/kinoite/usr/lib/systemd/user/plasma-ksmserver.service.d/40-cipherblue.conf
  - files/system/kinoite/usr/lib/systemd/user/plasma-xembedsniproxy.service.d/40-cipherblue.conf
  - files/system/kinoite/usr/share/kde-settings/kde-profile/default/xdg/kicker-extra-favoritesrc
  - files/system/kinoite/usr/share/plasma/look-and-feel/org.fedoraproject.fedora.desktop/contents/layouts/org.kde.plasma.desktop-layout.js
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/sericea/**</code></b></summary>

```text
  - files/system/sericea/etc/sway/config.d/98-wallpaper.conf
  - files/system/sericea/etc/sway/config.d/99-noxwayland.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/server/**</code></b></summary>

```text
  - files/system/server/etc/firewalld/zones/FedoraServer.xml
  - files/system/server/etc/ssh/sshd_config.d/30-hardening.conf
  - files/system/server/usr/lib/sysctl.d/56-server-hardening.conf
  - files/system/server/usr/lib/systemd/system-preset/30-securecore.preset
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/zfs/**</code></b></summary>

```text
  - files/system/zfs/usr/lib/systemd/system-preset/35-cipherblue-zfs.preset
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/nvidia/**</code></b></summary>

```text
  - files/system/nvidia/etc/yum.repos.d/fedora-nvidia-580.repo
  - files/system/nvidia/etc/yum.repos.d/negativo17-fedora-nvidia.repo
  - files/system/nvidia/etc/yum.repos.d/nvidia-container-toolkit.repo
  - files/system/nvidia/usr/lib/bootc/kargs.d/20-nvidia.toml
  - files/system/nvidia/usr/lib/systemd/system-preset/35-cipherblue-nvidia.preset
  - files/system/nvidia/usr/libexec/cipherblue/remove_kargs_nvidia.py
  - files/system/nvidia/usr/libexec/cipherblue/set_kargs_nvidia.py
  - files/system/nvidia/usr/share/pki/rpm-gpg/nvidia-container-gpgkey.gpg
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/desktop/etc/skel/.config/libvirt/qemu.conf</code></b></summary>

```text
  - files/system/desktop/etc/skel/.config/libvirt/qemu.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/desktop/etc/tmpfiles.d/homebrew.conf</code></b></summary>

```text
  - files/system/desktop/etc/tmpfiles.d/homebrew.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/desktop/usr/lib/tmpfiles.d/libvirt-fix-secontexts.conf</code></b></summary>

```text
  - files/system/desktop/usr/lib/tmpfiles.d/libvirt-fix-secontexts.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/containers/registries.d/**</code></b></summary>

```text
  - files/system/etc/containers/registries.d/blue-build.yaml
  - files/system/etc/containers/registries.d/build-container-installer.yaml
  - files/system/etc/containers/registries.d/cosign-release.yaml
  - files/system/etc/containers/registries.d/dangerzone.yaml
  - files/system/etc/containers/registries.d/davincibox.yaml
  - files/system/etc/containers/registries.d/quay.io-fedora-ostree-desktops.yaml
  - files/system/etc/containers/registries.d/quay.io-toolbx-images.yaml
  - files/system/etc/containers/registries.d/ublue-os.yaml
  - files/system/etc/containers/registries.d/wayblueorg.yaml
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/containers/toolbox.conf</code></b></summary>

```text
  - files/system/etc/containers/toolbox.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/distrobox/**</code></b></summary>

```text
  - files/system/etc/distrobox/distrobox.ini
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/toolbox/**</code></b></summary>

```text
  - files/system/etc/toolbox/toolbox.ini
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/yum.repos.d/**</code></b></summary>

```text
  - files/system/desktop/etc/yum.repos.d/repo.cipherblue.dev.cipherblue.repo
  - files/system/etc/yum.repos.d/cipherblue-packages-fedora.repo
  - files/system/etc/yum.repos.d/dangerzone.repo
  - files/system/etc/yum.repos.d/docker-ce.repo
  - files/system/etc/yum.repos.d/fedora-multimedia.repo
  - files/system/etc/yum.repos.d/ivpn.repo
  - files/system/etc/yum.repos.d/mullvad.repo
  - files/system/etc/yum.repos.d/protonvpn-stable.repo
  - files/system/etc/yum.repos.d/tailscale.repo
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/dracut/dracut.conf.d/90-ublue-luks.conf</code></b></summary>

```text
  - files/system/usr/lib/dracut/dracut.conf.d/90-ublue-luks.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/libexec/**</code></b></summary>

```text
  - files/system/desktop/usr/libexec/cipherblue/brew_main.py
  - files/system/desktop/usr/libexec/cipherblue/cipherbluecheckoutofdate
  - files/system/desktop/usr/libexec/cipherblue/cipherblueflatpaksetup
  - files/system/desktop/usr/libexec/cipherblue/cipherblueoutofdatenotify
  - files/system/desktop/usr/libexec/cipherblue/cipherbluesecurebootnotify
  - files/system/desktop/usr/libexec/cipherblue/firmwarecheckoutofdate
  - files/system/desktop/usr/libexec/cipherblue/firmwareoutofdatenotify
  - files/system/desktop/usr/libexec/cipherblue/harden_flatpak.py
  - files/system/desktop/usr/libexec/cipherblue/image-deprecation-check
  - files/system/desktop/usr/libexec/cipherblue/image-deprecation-notify
  - files/system/desktop/usr/libexec/cipherblue/inner/brew.py
  - files/system/desktop/usr/libexec/cipherblue/security-update-notification
  - files/system/desktop/usr/libexec/cipherblue/set_libvirt_daemons.py
  - files/system/desktop/usr/libexec/cipherblue/set_xwayland.py
  - files/system/desktop/usr/libexec/cipherblue/upgrade-on-boot
  - files/system/usr/libexec/cipherblue-motd
  - files/system/usr/libexec/cipherblue/audit_cipherblue.py
  - files/system/usr/libexec/cipherblue/audit_flatpak/__init__.py
  - files/system/usr/libexec/cipherblue/audit_utils/__init__.py
  - files/system/usr/libexec/cipherblue/audit_utils/containers.py
  - files/system/usr/libexec/cipherblue/auditor/__init__.py
  - files/system/usr/libexec/cipherblue/bluetooth_main.py
  - files/system/usr/libexec/cipherblue/cipherbluecleanup
  - files/system/usr/libexec/cipherblue/create_admin.py
  - files/system/usr/libexec/cipherblue/dhcp_hostname_sending_main.py
  - files/system/usr/libexec/cipherblue/dns_selector.py
  - files/system/usr/libexec/cipherblue/inner/admin.py
  - files/system/usr/libexec/cipherblue/inner/bluetooth.py
  - files/system/usr/libexec/cipherblue/inner/dangerzone.py
  - files/system/usr/libexec/cipherblue/inner/dhcp_hostname_sending.py
  - files/system/usr/libexec/cipherblue/inner/dns.py
  - files/system/usr/libexec/cipherblue/inner/set_selinux_module.py
  - files/system/usr/libexec/cipherblue/inner/webcam.py
  - files/system/usr/libexec/cipherblue/install_dangerzone.py
  - files/system/usr/libexec/cipherblue/kargs_hardening_common/__init__.py
  - files/system/usr/libexec/cipherblue/remove_kargs_hardening.py
  - files/system/usr/libexec/cipherblue/sandbox/__init__.py
  - files/system/usr/libexec/cipherblue/set_container_userns.py
  - files/system/usr/libexec/cipherblue/set_kargs_hardening.py
  - files/system/usr/libexec/cipherblue/set_unconfined_userns.py
  - files/system/usr/libexec/cipherblue/system-update-available
  - files/system/usr/libexec/cipherblue/toggle_user_motd.py
  - files/system/usr/libexec/cipherblue/utils/__init__.py
  - files/system/usr/libexec/cipherblue/verify-provenance.sh
  - files/system/usr/libexec/cipherblue/webcam_main.py
  - files/system/usr/libexec/deprecated-images.json
  - files/system/usr/libexec/deprecated-images.json.md
  - files/system/usr/libexec/luks-disable-fido2-unlock.sh
  - files/system/usr/libexec/luks-disable-tpm2-autounlock.sh
  - files/system/usr/libexec/luks-enable-fido2-unlock.sh
  - files/system/usr/libexec/luks-enable-tpm2-autounlock.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/ujust/**</code></b></summary>

```text
  - files/system/usr/lib/ujust/COPYRIGHT.md
  - files/system/usr/lib/ujust/libcolors.sh
  - files/system/usr/lib/ujust/libdistrobox.sh
  - files/system/usr/lib/ujust/libformatting.sh
  - files/system/usr/lib/ujust/libfunctions.sh
  - files/system/usr/lib/ujust/libtoolbox.sh
  - files/system/usr/lib/ujust/ujust.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/share/backgrounds/**</code></b></summary>

```text
  - files/system/usr/share/backgrounds/cipherblue/cipherblue-black.png
  - files/system/usr/share/backgrounds/cipherblue/cipherblue-black.svg
  - files/system/usr/share/backgrounds/cipherblue/cipherblue-blue.png
  - files/system/usr/share/backgrounds/cipherblue/cipherblue-blue.svg
  - files/system/usr/share/backgrounds/cipherblue/cipherblue-bw.png
  - files/system/usr/share/backgrounds/cipherblue/cipherblue-bw.svg
  - files/system/usr/share/backgrounds/default.xml
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/share/bazaar/**</code></b></summary>

```text
  - files/system/desktop/usr/share/bazaar/README.md
  - files/system/desktop/usr/share/bazaar/blocklist.yaml
  - files/system/desktop/usr/share/bazaar/curated.yaml
  - files/system/desktop/usr/share/bazaar/main.yaml
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/share/cipherblue/**</code></b></summary>

```text
  - files/system/usr/share/cipherblue/secure-dns-providers.json
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/share/distrobox/**</code></b></summary>

```text
  - files/system/usr/share/distrobox/distrobox.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/pki/containers/**</code></b></summary>

```text
  - files/system/etc/pki/containers/bluebuild-cli.pub
  - files/system/etc/pki/containers/bluebuild-modules.pub
  - files/system/etc/pki/containers/build-container-installer.pub
  - files/system/etc/pki/containers/cipherblue-2025.pub
  - files/system/etc/pki/containers/cipherblue.pub
  - files/system/etc/pki/containers/cosign-release.pub
  - files/system/etc/pki/containers/davincibox.pub
  - files/system/etc/pki/containers/freedomofpress-dangerzone.pub
  - files/system/etc/pki/containers/quay.io-fedora-ostree-desktops.pub
  - files/system/etc/pki/containers/quay.io-toolbx-images.pub
  - files/system/etc/pki/containers/ublue-os.pub
  - files/system/etc/pki/containers/wayblueorg.pub
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/share/ublue-os/**</code></b></summary>

```text
  - files/system/usr/share/ublue-os/just/60-custom.just
  - files/system/usr/share/ublue-os/justfile
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/bin/ugum</code></b></summary>

```text
  - files/system/usr/bin/ugum
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/profile.d/ujust-chooser.sh</code></b></summary>

```text
  - files/system/etc/profile.d/ujust-chooser.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/profile.d/user-motd.sh</code></b></summary>

```text
  - files/system/etc/profile.d/user-motd.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/profile.d/xx-bash-prompt-command.sh</code></b></summary>

```text
  - files/system/etc/profile.d/xx-bash-prompt-command.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/brew-setup-migration.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/system/brew-setup-migration.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/NetworkManager/conf.d/dnsconfd.conf</code></b></summary>

```text
  - files/system/etc/NetworkManager/conf.d/dnsconfd.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/tmpfiles.d/unbound.conf</code></b></summary>

```text
  - files/system/etc/tmpfiles.d/unbound.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/unbound/conf.d/cipherblue.conf</code></b></summary>

```text
  - files/system/etc/unbound/conf.d/cipherblue.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/dnsconfd.service.d/cipherblue.conf</code></b></summary>

```text
  - files/system/usr/lib/systemd/system/dnsconfd.service.d/cipherblue.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/unbound-control.socket</code></b></summary>

```text
  - files/system/usr/lib/systemd/system/unbound-control.socket
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/unbound.socket</code></b></summary>

```text
  - files/system/usr/lib/systemd/system/unbound.socket
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/unbound.service.d/cipherblue.conf</code></b></summary>

```text
  - files/system/usr/lib/systemd/system/unbound.service.d/cipherblue.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/cipherblue-unbound-key.service</code></b></summary>

```text
  - files/system/usr/lib/systemd/system/cipherblue-unbound-key.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/cipherblue-flatpak-setup.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/cipherblue-flatpak-setup.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/cipherblue-flatpak-setup.timer</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/cipherblue-flatpak-setup.timer
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/cipherblue-key-enrollment-verification.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/cipherblue-key-enrollment-verification.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/cipherblue-key-enrollment-verification.timer</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/cipherblue-key-enrollment-verification.timer
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/cipherblue-update-verification.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/cipherblue-update-verification.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/cipherblue-update-verification.timer</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/cipherblue-update-verification.timer
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/flatpak-user-update.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/flatpak-user-update.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/flatpak-user-update.timer</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/flatpak-user-update.timer
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/security-update-notification.path</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/security-update-notification.path
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/security-update-notification.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/security-update-notification.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/systemd/system/rpm-ostreed-automatic.timer.d/**</code></b></summary>

```text
  - files/system/etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/share/pki/**</code></b></summary>

```text
  - files/system/desktop/usr/share/pki/rpm-gpg/cipherblue.gpg
  - files/system/usr/share/pki/rpm-gpg/RPM-GPG-KEY-slaanesh.gpg
  - files/system/usr/share/pki/rpm-gpg/cipherblue-copr-pubkey.gpg
  - files/system/usr/share/pki/rpm-gpg/docker-ce.gpg
  - files/system/usr/share/pki/rpm-gpg/fpf-yum-tools-archive-keyring.gpg
  - files/system/usr/share/pki/rpm-gpg/ivpn-repo.gpg
  - files/system/usr/share/pki/rpm-gpg/mullvad-keyring.asc
  - files/system/usr/share/pki/rpm-gpg/protonvpn_public_key.asc
  - files/system/usr/share/pki/rpm-gpg/tailscale-repo.gpg
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/flatpak-system-update.timer</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/system/flatpak-system-update.timer
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/flatpak-system-update.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/system/flatpak-system-update.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/cipherblue-firmware-check.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/cipherblue-firmware-check.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/cipherblue-firmware-check.timer</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/cipherblue-firmware-check.timer
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/system/cipherbluecleanup.service</code></b></summary>

```text
  - files/system/usr/lib/systemd/system/cipherbluecleanup.service
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/sysctl.d/61-ptrace-scope.conf</code></b></summary>

```text
  - files/system/etc/sysctl.d/61-ptrace-scope.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user-preset/40-cipherblue.preset</code></b></summary>

```text
  - files/system/usr/lib/systemd/user-preset/40-cipherblue.preset
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/common/cosmic-modules.yml</code></b></summary>

```text
  - recipes/common/cosmic-modules.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/common/kinoite-modules.yml</code></b></summary>

```text
  - recipes/common/kinoite-modules.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/common/nvidia-install.yml</code></b></summary>

```text
  - recipes/common/nvidia-install.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/common/proprietary-modules.yml</code></b></summary>

```text
  - recipes/common/proprietary-modules.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/common/sericea-modules.yml</code></b></summary>

```text
  - recipes/common/sericea-modules.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/common/server-modules.yml</code></b></summary>

```text
  - recipes/common/server-modules.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/common/zfs-modules.yml</code></b></summary>

```text
  - recipes/common/zfs-modules.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-cosmic-main.yml</code></b></summary>

```text
  - recipes/general/recipe-cosmic-main.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-cosmic-nvidia-open.yml</code></b></summary>

```text
  - recipes/general/recipe-cosmic-nvidia-open.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-cosmic-nvidia.yml</code></b></summary>

```text
  - recipes/general/recipe-cosmic-nvidia.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-kinoite-main.yml</code></b></summary>

```text
  - recipes/general/recipe-kinoite-main.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-kinoite-nvidia-open.yml</code></b></summary>

```text
  - recipes/general/recipe-kinoite-nvidia-open.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-kinoite-nvidia.yml</code></b></summary>

```text
  - recipes/general/recipe-kinoite-nvidia.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-sericea-main.yml</code></b></summary>

```text
  - recipes/general/recipe-sericea-main.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-sericea-nvidia-open.yml</code></b></summary>

```text
  - recipes/general/recipe-sericea-nvidia-open.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-sericea-nvidia.yml</code></b></summary>

```text
  - recipes/general/recipe-sericea-nvidia.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-silverblue-nvidia-open.yml</code></b></summary>

```text
  - recipes/general/recipe-silverblue-nvidia-open.yml
```
</details>

<details><summary><b>Excluded Rule: <code>recipes/general/recipe-silverblue-nvidia.yml</code></b></summary>

```text
  - recipes/general/recipe-silverblue-nvidia.yml
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/certs/**</code></b></summary>

```text
  - files/scripts/certs/.keep
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/addrepos.sh</code></b></summary>

```text
  (No upstream files matched this rule during this sync commit)
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/authselect.sh</code></b></summary>

```text
  - files/scripts/authselect.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/checksinglekernel.sh</code></b></summary>

```text
  - files/scripts/checksinglekernel.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/createautostartdir.sh</code></b></summary>

```text
  (No upstream files matched this rule during this sync commit)
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/createjustcompletions.sh</code></b></summary>

```text
  (No upstream files matched this rule during this sync commit)
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/disable-coreos-migration-motd.sh</code></b></summary>

```text
  - files/scripts/disable-coreos-migration-motd.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/disablewlrportals.sh</code></b></summary>

```text
  - files/scripts/disablewlrportals.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/hardenlogindefs.patch</code></b></summary>

```text
  - files/scripts/hardenlogindefs.patch
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/hardenlogindefs.sh</code></b></summary>

```text
  - files/scripts/hardenlogindefs.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/installandroidudev.sh</code></b></summary>

```text
  (No upstream files matched this rule during this sync commit)
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/installnvidiakmod.sh</code></b></summary>

```text
  - files/scripts/installnvidiakmod.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/installnvidiapackages.sh</code></b></summary>

```text
  - files/scripts/installnvidiapackages.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/installpinnedkernel.sh</code></b></summary>

```text
  - files/scripts/installpinnedkernel.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/installrar.sh</code></b></summary>

```text
  - files/scripts/installrar.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/installsubresourcefilter.sh</code></b></summary>

```text
  - files/scripts/installsubresourcefilter.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/installzfskmod.sh</code></b></summary>

```text
  - files/scripts/installzfskmod.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/localization.sh</code></b></summary>

```text
  - files/scripts/localization.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/manuallyinstalljust.sh</code></b></summary>

```text
  - files/scripts/manuallyinstalljust.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/regenerateinitramfs.sh</code></b></summary>

```text
  - files/scripts/regenerateinitramfs.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/removekrunnerappstream.sh</code></b></summary>

```text
  - files/scripts/removekrunnerappstream.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/setdefaultkdewallpapers.sh</code></b></summary>

```text
  - files/scripts/setdefaultkdewallpapers.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/setdrmvariables.sh</code></b></summary>

```text
  - files/scripts/setdrmvariables.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/setearlyloading.sh</code></b></summary>

```text
  - files/scripts/setearlyloading.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/setserverdefaultzone.sh</code></b></summary>

```text
  - files/scripts/setserverdefaultzone.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/setswaynvidiaenvironment.sh</code></b></summary>

```text
  - files/scripts/setswaynvidiaenvironment.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/sign-check.sh</code></b></summary>

```text
  - files/scripts/sign-check.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/signkernel.sh</code></b></summary>

```text
  - files/scripts/signkernel.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/signmodules.sh</code></b></summary>

```text
  - files/scripts/signmodules.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/disableresolved.sh</code></b></summary>

```text
  - files/scripts/disableresolved.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/scripts/setup-dnsconfd.sh</code></b></summary>

```text
  - files/scripts/setup-dnsconfd.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/udev/rules.d/**</code></b></summary>

```text
  (No upstream files matched this rule during this sync commit)
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/udev/rules.d/**</code></b></summary>

```text
  - files/system/desktop/usr/lib/udev/rules.d/51-android.rules
  - files/system/usr/lib/udev/rules.d/50-framework16.rules
  - files/system/usr/lib/udev/rules.d/50-usb-realtek-net.rules
  - files/system/usr/lib/udev/rules.d/70-titan-key.rules
  - files/system/usr/lib/udev/rules.d/70-u2f.rules
  - files/system/usr/lib/udev/rules.d/99-cipherblue.rules
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/pki/akmods/certs/akmods-cipherblue.der</code></b></summary>

```text
  - files/system/etc/pki/akmods/certs/akmods-cipherblue.der
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/etc/profile.d/sudo-missing-message.sh</code></b></summary>

```text
  - files/system/etc/profile.d/sudo-missing-message.sh
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/systemd/user/image-deprecation-notice.service</code></b></summary>

```text
  - files/system/desktop/usr/lib/systemd/user/image-deprecation-notice.service
```
</details>

<details><summary><b>Excluded Rule: <code>modules/cipherblue-signing/policy.json</code></b></summary>

```text
  - modules/cipherblue-signing/policy.json
```
</details>

<details><summary><b>Excluded Rule: <code>files/system/usr/lib/sysusers.d/android-udev.conf</code></b></summary>

```text
  - files/system/desktop/usr/lib/sysusers.d/android-udev.conf
```
</details>

<details><summary><b>Excluded Rule: <code>files/gschema-overrides/zz1-cipherblue.gschema.override</code></b></summary>

```text
  - files/gschema-overrides/zz1-cipherblue.gschema.override
```
</details>

<details><summary><b>Excluded Rule: <code>tools</code></b></summary>

```text
  - tools/check_repo_keys.py
  - tools/rpm-repo-sources.json
  - tools/update_po.py
```
</details>

<details><summary><b>Excluded Rule: <code>pyproject.toml</code></b></summary>

```text
  - pyproject.toml
```
</details>

