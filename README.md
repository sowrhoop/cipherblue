# CIPHERBLUE

[![Build Status](https://github.com/sowrhoop/cipherblue/actions/workflows/cipherblue-build.yml/badge.svg)](https://github.com/sowrhoop/cipherblue/actions/workflows/cipherblue-build.yml)

Hardened minimal Fedora Silverblue image that enforces a zero‑trust, immutable OS blueprint with SLSA provenance verification, SELinux + systemd lockdown, strict package controls and a declarative Flatpak vault.

This repository contains the image recipe, the system configuration injected into the immutable layer and the helper code used during the build and at runtime to enforce the Cipherblue security posture.

Table of contents
- Quick summary
- High level architecture
- Hardening features (what changes and where)
- Build, CI and secrets
- Deploying Cipherblue (rebase instructions)
- Security / limitations / contribution
- Appendix: exact file mapping (implementing files & scripts)

---

Quick summary

- Base: forked Silverblue image (recipe: `recipes/recipe-cipherblue.yml`, base-image: `quay.io/fedora/fedora-silverblue`, image-version: `latest`).
- Purpose: provide an immutable, auditable workstation appliance for focused, high-value engineering with strong platform integrity guarantees.

High level architecture

- Build-time:
  - GitHub Actions + BlueBuild assemble the image using `recipes/recipe-cipherblue.yml` and a set of file and script modules. The CI injects secrets (when configured) and runs verification tooling (crane, slsa-verifier).
  - A local module (modules/cipherblue-signing) configures container registries and copies container signing keys to enable image verification.

- Runtime enforcement:
  - Multiple systemd one-shot/daemon units and helper scripts (under `files/system/usr/libexec/cipherblue/` and `files/system/usr/lib/systemd/system/`) enforce immutability, reconcile kernel arguments, manage Flatpak state, audit configuration drift and verify SLSA provenance of the currently deployed OSTree image.

What the recipe changes vs upstream Silverblue (summary)

Cipherblue is opinionated: it reduces runtime attack surface, enforces cryptographic provenance, locks down user and system state, and converts runtime configuration to a small, auditable set of files under the immutable layer. Key changes:

- Packages added (recipe dnf installs): `hardened_malloc`, `openssl`, `patch`, `sbsigntools`, `no_rlimit_as`, `crane`, `slsa-verifier`, `gnome-tweaks`, `tlp`, `fscrypt`, `wl-clipboard`.
- RPM-OSTree install: `gnome-disk-utility`.
- Packages explicitly removed by the recipe (rpm-ostree remove): `buildah`, `crun`, `dnf5`, `fedora-logos`, `fedora-logos-httpd`, `libdnf5`, `libdnf5-cli`, `sdbus-cpp`, `yajl`.
- Aggressive package removal at build-time (DNF5 driven) — see `files/scripts/package-remover.sh` for the exhaustive list and categories removed (desktop, multimedia, virtualization, printing, networking helpers, etc.).
- Local package layering & repositories are purged from the image (see `files/scripts/cipherblue-cleanup.sh`). System-level Flatpak remotes are removed and a controlled Flatpak vault is enforced.

Hardening features (detailed, mapped to implementing files)

1) Image provenance and rebase / SLSA verification
- files/system/usr/libexec/cipherblue/verify-provenance.sh — verifies the running OSTree image using `slsa-verifier` and `crane` against expected source/branch; uses credentials in `/etc/ostree/auth.json`.
- files/system/usr/libexec/cipherblue/cipher-secure-rebase.sh — secure rebase logic (rebase to a signed image when a vault/credentials are available).
- modules/cipherblue-signing/* — configures container signing (copies `/etc/pki/containers/*.pub` to `/usr/etc/pki/containers/` and places a registry config into `registries.d/`).

2) Kernel / boot hardening
- files/system/usr/lib/bootc/kargs.d/10-cipherblue.toml — declarative kernel arguments injected into OSTree (many hardening and mitigation kargs).
- cipherblue-sync/cipherblue-sync.sh and files/system/usr/libexec/cipherblue/cipher-kargs-reconciler.sh — harmonize and reconcile TOML / OSTree kargs, applying missing args atomically (systemd unit: `cipher-kargs-reconciler.service`).
- files/system/usr/libexec/cipherblue/cipher-grub-lockdown.sh — generates GRUB PBKDF2 hash and writes `/boot/grub2/user.cfg` to lock the bootloader.

3) SELinux hardening & custom policies
- files/scripts/selinux-hardening.sh — a single-transaction `setsebool -P` pass toggling a large set of SELinux booleans (many are turned off; a few turned on: `deny_bluetooth`, `deny_ptrace`, `secure_mode`, `secure_mode_policyload`).
- files/scripts/installselinuxpolicies.sh and `files/scripts/selinux/*` — compile and install additional SELinux modules (e.g., `flatpakfull`, `nautilus`, `systemsettings`, `thunar`, user-namespace hardening modules).

4) Systemd state & service hardening
- files/scripts/systemd-hardening.sh — disables and masks a long list of upstream services considered unnecessary or dangerous (sshd, avahi, cups, sssd, NFS daemons, etc.) and enables Cipherblue zero-trust services.
- files/system/usr/lib/systemd/system/*.service & timers — cipher-* units implement the enforcement agents (examples below):
  - `files/system/usr/lib/systemd/system/cipherblue-sentinel.service` + `usr/libexec/cipherblue/sentinel-daemon.sh` — runtime watchdog/telemetry daemon (alerts via notify-send/logger), watches for drift, service failures and SELinux state.
  - `files/system/usr/lib/systemd/system/cipher-flatpak-vault.service` + `usr/libexec/cipherblue/cipher-flatpak-vault.sh` — reconciles system Flatpaks with the declarative vault list.
  - `files/system/usr/lib/systemd/system/cipher-flatpak-update.{service,timer}` — scheduled app updates.
  - `files/system/usr/lib/systemd/system/cipher-audit-drift.{service,timer}` — daily configuration drift auditor.
  - `files/system/usr/lib/systemd/system/cipher-cleanup.{service,timer}` — periodic garbage collection and rpm-ostree cleanup.

5) Polkit-based state mutation control
- files/system/etc/polkit-1/rules.d/00-cipherblue-appliance.rules — absolute zero-trust polkit policy. It:
  - Hard denies flatpak and rpm-ostree state mutations for non-root users.
  - Implements an allowlist for ordinary GNOME control-center actions, and enforces AUTH_ADMIN on sensitive actions.
  - Sends telemetry via `logger` for blocked attempts so the sentinel can notify/record events.

6) Flatpak vault & software supply control
- files/scripts/cipherblue-private.sh — CI-time secret injection engine that stages a declarative Flatpak whitelist and a private vault overrides tarball into `/etc/cipherblue/`.
- files/system/usr/libexec/cipherblue/cipher-flatpak-vault.sh — runtime enforcer that ensures only a verified, CI-controlled Flatpak remote (`cipherblue-verified-floss`) is trusted and that the system Flatpak set matches `/etc/cipherblue/flatpaks.list`.
- files/scripts/removefedoraflatpakremoteservice.sh + cipherblue-cleanup.sh — remove Fedora/Flathub system remotes and prevent automatic re-adding.

7) Filesystem & user environment immutability
- files/system/usr/libexec/cipherblue/cipher-user-env-lockdown.sh — cascading node-freeze engine: enforces a narrow whitelist under user home directories and freezes important files with `chattr +i` to prevent state mutation.
- files/system/usr/libexec/cipherblue/cipher-mount-enforcer.service — remounts temporary filesystems with nosuid,noexec,nodev where appropriate.
- files/system/usr/libexec/cipherblue/cipher-audit-drift.sh — compares `/usr/etc` vs `/etc` to detect configuration drift and raises alerts.

8) SUID / capability & permission hardening
- files/scripts/suid-hardening.sh & files/scripts/removesuid.sh — remove SUID/SGID bits except for a small whitelist; remove `pkexec`, `sudo`, `su` where appropriate and add necessary capabilities to specific binaries instead of SUID.
- files/scripts/permission-hardening.sh — strict umask, disable securetty, tighten internal helper scripts permissions (700) and other PAM/login defaults.

9) Kernel tunables & runtime hardening (sysctl)
- files/system/etc/sysctl.d/60-cipherblue-hardening.conf — aggressive kernel runtime hardening (ptrace/yama, bpf JIT, kptr_restrict, disable IPv6 by default in many configs, disable unprivileged userns, etc.).
- files/system/usr/lib/sysctl.d/55-hardening.conf — supplemental network & kernel hardening values.

10) Module blacklisting & kernel feature blocking
- files/system/etc/modprobe.d/cipherblue-blacklist.conf — blacklist of many drivers/subsystems and `install <module> /bin/false` lines to prevent loading of attack-surface modules (USB networking, legacy filesystems, telemetry modules, etc.).

11) Journald privacy, coredump & tmpfiles hardening
- files/system/etc/systemd/journald.conf.d/60-cipherblue-privacy.conf — `Storage=volatile`, limits and rate-limiting.
- files/system/etc/security/limits.d/60-disable-coredump.conf & files/system/etc/sysctl.d/* — disable core dumps and tune resource limits.
- files/system/etc/tmpfiles.d/99-cipherblue-proc.conf and `99-cipherblue-sys.conf` — strict permissions for `/proc` and `/sys` entries.

12) Network & NetworkManager hardening
- files/system/etc/NetworkManager/conf.d/60-cipherblue.conf — disable auto DNS, cloned MACs (privacy), `dns=systemd-resolved` and disable connectivity checks (`99-disable-connectivity.conf`).

13) Package & repo trust model
- files/scripts/cipherblue-cleanup.sh — removes all `/etc/yum.repos.d/*` and `/etc/pki/rpm-gpg/*` to force reliance on the CI pipeline and the maintained set of signed packages.
- files/scripts/package-remover.sh — removes a large set of upstream packages to reduce attack surface; see the script for the precise exhaustive list.
- files/system/etc/yum.repos.d/cipherblue-packages-fedora.repo and `repo.cipherblue.dev.cipherblue.repo` — cipherblue repository configuration (signed GPG keys are under `files/system/usr/share/pki/rpm-gpg/`).

14) Trivalent browser & MDM
- files/scripts/install-trivalent.sh — fetches a verified trivalent RPM, verifies provenance with `slsa-verifier`, installs the browser and related SELinux policy (`trivalent-selinux`).

How CI, builds and secrets are used

- The production build is run in GitHub Actions using `.github/workflows/cipherblue-build.yml` and `.github/workflows/cipherblue-sync.yml`.
- Secrets consumed at build-time (set in the repository/GH Actions secrets):
  - `CIPHERBLUE_BLOCKLIST` — newline/comma separated list; staged at `/etc/cipherblue/hosts.blocklist` by `cipherblue-private.sh`.
  - `CIPHERBLUE_FLATPAKS` — comma-separated list of Flatpak application IDs; staged at `/etc/cipherblue/flatpaks.list`.
  - `PRIVATE_VAULT_PAT` — a GitHub token/PAT used to fetch a private vault tarball (over HTTPS) which contains Flatpak overrides and other private configuration; `cipherblue-private.sh` stages overrides into `/etc/cipherblue/flatpak-overrides/`.
- The repository also provisions container signing config (modules/cipherblue-signing) so that runtime verification can require signature/attestation artifacts.

Deploying / Testing locally

- Quick (testing) rebase to the latest development image (unsigned/test):

```bash
rpm-ostree rebase ostree-unverified-registry:ghcr.io/sowrhoop/cipherblue:latest
systemctl reboot
```

- Production (signed image) workflow — prefer verification and signed `ostree-image-signed:` references. The runtime `cipher-secure-rebase.sh` expects a signed GHCR image and a populated `/etc/ostree/auth.json` for authenticated pulls.

Notes, caveats and limitations

- Cipherblue intentionally removes many upstream convenience packages and services (SSH server, printing, many desktop extras, local package layering tools). This is by design — the image is targeted for single-tenant, high-assurance use cases and CI-managed package lifecycle.
- Removing `sudo` and other userland utilities breaks workflows that expect password-based privilege escalation. Administrative tasks should be performed in the image build pipeline or via ostree-based workflows.
- Some kernel and service hardenings may be aggressive on certain hardware (e.g., disabling IEEE 802.11 features, disabling some telemetry modules and filesystems). Test carefully on target hardware.

Contributing & reporting security issues

- This project is open to contributions. For general issues or PRs, please use GitHub issues/pull requests: https://github.com/sowrhoop/cipherblue
- If you discover a security issue, please open a private issue (or use the Security contact channel configured in the repository) so the maintainers can respond.

License

This project is released under the GNU Affero General Public License v3 (AGPL-3.0-or-later). See the LICENSE file for full terms.

Appendix: important files & where the enforcement lives (selected)

- Recipe and orchestration
  - `recipes/recipe-cipherblue.yml` — image recipe used by BlueBuild/GitHub Actions.
  - `cipherblue-sync/cipherblue-sync.sh` — upstream sync, rebrand and kargs harmonization engine.

- Build / secret injection
  - `files/scripts/cipherblue-private.sh` — consumes `CIPHERBLUE_BLOCKLIST`, `CIPHERBLUE_FLATPAKS`, `PRIVATE_VAULT_PAT`.
  - `modules/cipherblue-signing/` — signing/registry configuration copied into the image during build.

- Runtime enforcement scripts (examples)
  - `files/system/usr/libexec/cipherblue/sentinel-daemon.sh`
  - `files/system/usr/libexec/cipherblue/verify-provenance.sh`
  - `files/system/usr/libexec/cipherblue/cipher-secure-rebase.sh`
  - `files/system/usr/libexec/cipherblue/cipher-flatpak-vault.sh`
  - `files/system/usr/libexec/cipherblue/cipher-flatpak-update.sh`
  - `files/system/usr/libexec/cipherblue/cipher-kargs-reconciler.sh`
  - `files/system/usr/libexec/cipherblue/cipher-user-env-lockdown.sh`

- Systemd units & presets (examples)
  - `files/system/usr/lib/systemd/system/cipherblue-sentinel.service`
  - `files/system/usr/lib/systemd/system/cipher-flatpak-vault.service`
  - `files/system/usr/lib/systemd/system/cipher-flatpak-update.service`
  - `files/system/usr/lib/systemd/system/cipher-flatpak-update.timer`
  - `files/system/usr/lib/systemd/system/cipher-cleanup.{service,timer}`
  - `files/system/usr/lib/systemd/system/cipher-audit-drift.{service,timer}`
  - `files/system/usr/lib/systemd/system/cipher-firmware-update.{service,timer}`
  - `files/system/usr/lib/systemd/system/cipher-kargs-reconciler.service`
  - `files/system/usr/lib/systemd/system-preset/40-cipherblue.preset`

- Key system configuration files (examples)
  - `files/system/etc/sysctl.d/60-cipherblue-hardening.conf`
  - `files/system/usr/lib/sysctl.d/55-hardening.conf`
  - `files/system/etc/modprobe.d/cipherblue-blacklist.conf`
  - `files/system/etc/polkit-1/rules.d/00-cipherblue-appliance.rules`
  - `files/system/etc/dconf/db/local.d/00-cipherblue-settings`
  - `files/system/etc/dconf/db/local.d/locks/00-cipherblue-locks`
  - `files/system/etc/systemd/journald.conf.d/60-cipherblue-privacy.conf`
  - `files/system/etc/systemd/logind.conf.d/99-cipherblue-tty-lockdown.conf`
  - `files/system/etc/tmpfiles.d/99-cipherblue-proc.conf`
  - `files/system/etc/tmpfiles.d/99-cipherblue-sys.conf`
  - `files/system/usr/lib/bootc/kargs.d/10-cipherblue.toml`

For the exhaustive, machine-readable lists of files, packages removed/installed and the exact exclusions used by the sync engine see:

- `files/scripts/package-remover.sh` (explicit removal categories)
- `cipherblue-sync/cipherblue-exclude.txt` and `cipherblue-sync/upstream-preserve.txt`
- `cipherblue-sync/SYNC_AUDIT.md` (generated by the sync job and included in CI artifacts)