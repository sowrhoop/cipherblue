# CIPHERBLUE

[![Build Status](https://github.com/sowrhoop/cipherblue/actions/workflows/cipherblue-build.yml/badge.svg)](https://github.com/sowrhoop/cipherblue/actions/workflows/cipherblue-build.yml)

🛡️ Engineering a Digital Sanctum

Cipherblue is a mathematically enforced digital sanctuary forked from Secureblue and tailored for high-performance workloads without compromising security. It is designed for engineers who require strong cryptographic privacy, zero-trust hardware execution, and a stable environment for focused, high-value work.

## Core Architecture & Features

### Zero-Trust Immutability & CI/CD

- Built in the cloud using GitHub Actions and BlueBuild. Images are assembled, minimized, configured, and cryptographically signed with Cosign before deployment.
- Tamper-proof: the root filesystem is immutable.
- State enforcement: a local systemd watchdog verifies the bootloader signature at every boot.

### Optimized Kernel Hardening

- Utilizing the modern bootc declarative infrastructure, the Linux kernel is built with 54+ security and performance parameters at compile time.
- Hyper-threading preserved to avoid the 30–40% compile-time penalties associated with some blanket security profiles.
- Extreme hardware isolation: enforces AMD Secure Memory Encryption (mem_encrypt=on), blocks raw mounted disk writes (bdev_allow_write_mounted=0), and reduces attack surface by disabling IPv6 where appropriate.

### Unbreakable Enterprise MDM (Trivalent Browser)

- The default browser runs under a strict Mobile Device Management (MDM) JSON policy mounted on the read-only OS layer.
- Extensions (Bitwarden, uBlock Origin Lite, LeechBlock NG, FilterTube) are pinned and managed via CI/CD.
- Users cannot modify the extension store or access chrome://extensions; updates are handled by the pipeline.

### Aggressive Anti-Forensics

- Journald logs are kept in volatile RAM (tmpfs) and destroyed on reboot.
- Kernel and user-space coredumps are disabled to prevent RAM extraction on crashes.
- System-wide DNS-over-TLS (DoT) is enforced; local caching is minimized.

### Network-Level Distraction Blackhole

- A dynamically injected /etc/hosts file routes distracting domains (algorithmic feeds, short-form video, social media) to 0.0.0.0 at the OS routing layer to reduce temptation and distraction.

## Self-Healing Sync Engine

- Nightly pipeline (cipherblue-sync/cipherblue-sync.sh) pulls upstream security updates from Secureblue, harmonizes kernel configuration, removes ML-performance blockers, and re-injects custom AI-hardening flags.
- Produces a deduplicated SYNC_AUDIT.md report for observability and auditing.

## Deployment

Prerequisites: Fedora Silverblue or Kinoite, and rpm-ostree installed.

To transition a Silverblue/Kinoite installation into Cipherblue:

```bash
rpm-ostree rebase ostree-unverified-registry:ghcr.io/sowrhoop/cipherblue:latest
systemctl reboot
```

See the cipherblue-sync/ directory and files/ for sync scripts and system configuration. Notable files:

- cipherblue-sync/cipherblue-sync.sh — nightly sync driver
- cipherblue-sync/SYNC_AUDIT.md — generated sync audit report
- files/ — system configuration and packaging files

## License & Provenance

This project is licensed under the GNU Affero General Public License v3 (AGPL-3.0-or-later). It builds upon work from the Fedora Project and the Secureblue community. See the LICENSE file for details.

## Contributing & Support

Found an issue or want to contribute? Please open an issue or pull request on GitHub: https://github.com/sowrhoop/cipherblue

"First we shape our tools, thereafter our tools shape us."