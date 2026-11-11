# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-11

### Added ✨

- Add CRL generation and CRLDistributionPoints support

### Build system 🛠️

- Accept the rsa and crypto-bigint advisories until yubikey 0.9
- Stop tracking the lockfile
- Track the lockfile and check it with cargo-deny (#10)

### CI/CD ⚙️

- Check, test and release for linux and windows on both arches (#9)

### Fixed 🐛

- Update rust crate clap to 4.6.7 (#11)
- Update rust crate thiserror to 2.0.21 (#13)
- Update tokio-tracing monorepo (#14)
- Update rust crate hex to 0.4.3 (#16)

### Miscellaneous 🧹

- Initial commit
- Apply the repository skeleton
- Let renovate update dependencies through the shared preset
- Update svaroglab/.github action to v2 (#15)
