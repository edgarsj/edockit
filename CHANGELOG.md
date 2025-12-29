# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-29

### Added

- **Certificate Revocation Checking** - OCSP-first verification with CRL fallback
  - Soft-fail mode: network errors return `status: 'unknown'`, signature remains valid
  - Issuer certificate retrieval from XAdES chain or AIA extension
  - Optional via `checkRevocation: false` for offline-only verification
- **RFC 3161 Timestamp Verification**
  - Parse and verify RFC 3161 timestamps (SignatureTimeStamp)
  - Check TSA certificate validity and revocation (OCSP/CRL)
  - Use trusted TSA time for signer certificate validation
  - `revocationOptions` pass-through to `verifySignature()`

### Changed

- Refactored encoding utilities (consolidated base64/hex/ArrayBuffer helpers)

### Fixed

- Browser compatibility import fixes (direct paths vs barrel imports)
- Fixed vulnerable dev dependencies

## [0.1.2] - 2025-12-29

### Added

- Initial public release
- Parse ASiC-E containers (including Latvian eDoc files)
- Extract and verify XAdES signatures
- Certificate validity checking
- File checksum verification (SHA-256/384/512)
- Browser and Node.js support

[0.2.0]: https://github.com/edgarsj/edockit/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/edgarsj/edockit/releases/tag/v0.1.2
