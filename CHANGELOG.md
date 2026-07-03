# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-03

### Changed
- Upgraded dependencies: `rand` 0.9 → 0.10, `aes-gcm` 0.10 → 0.11, `sha2` 0.10 → 0.11, `pbkdf2` 0.12 → 0.13, `thiserror` → 2.0.18
- Migrated to the new `rand` 0.10 API (`OsRng` → `SysRng`, `TryRngCore` → `TryRng`)
- Replaced deprecated `Nonce::from_slice` with `Nonce::try_from`, surfacing a wrong-length IV as an error instead of a panic

## [0.1.0] - 2025-05-08

### Added
- Initial release
- Basic obfuscation and unobfuscation functionality
- Configurable salt length and separator
- Comprehensive error handling
- Extensive test suite
