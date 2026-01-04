# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-04

### Added

- **Multi-state validation results** - `VerificationResult` now includes granular status beyond boolean `isValid`:
  - `status`: `"VALID"` | `"INVALID"` | `"INDETERMINATE"` | `"UNSUPPORTED"`
  - `statusMessage`: Human-readable explanation
  - `limitations`: Array describing platform/environment constraints
- **Platform limitation detection** - Detect unsupported RSA key sizes (>4096 bits) in Safari/WebKit and return `UNSUPPORTED` status instead of failing as `INVALID`
- **Cross-browser testing** - Added Safari/WebKit and Firefox to browser test suite locally

### Fixed

- **C14N 1.1 canonicalization** - Fixed bug where C14N 1.1 incorrectly added newlines between XML elements when the original had none. This caused signature verification to fail for compact XML.
- **INDETERMINATE for expired timestamps** - Return `INDETERMINATE` status (instead of `INVALID`) when timestamp or certificate has expired but signature is otherwise valid
- **Legacy RSA DigestInfo verification** - Fix signature verification for old documents signed with pre-Java 8 tools that produced non-standard DigestInfo format (missing NULL in AlgorithmIdentifier)

## [0.2.4] - 2025-12-31

### Fixed

- **OCSP issuerKeyHash calculation** - Fixed critical bug where OCSP requests used wrong hash (full SPKI instead of public key BIT STRING), causing incorrect revocation status responses
- **Timestamp signature coverage verification** - Now correctly verifies that timestamps cover the canonicalized ds:SignatureValue XML element per XAdES (ETSI EN 319 132-1) specification, fixing `coversSignature: false` issue
- **TSA name formatting** - Fixed timestamp TSA name showing as `[object Object]` instead of readable DN string like `CN=..., O=..., C=...`
- **Base64 whitespace handling** - Fixed browser `atob` errors when decoding base64 strings containing whitespace from XML
- **ECDSA signature format normalization** - Fixed signature verification failures for ECDSA signatures with leading zero padding by normalizing to IEEE P1363 format expected by Web Crypto API

## [0.2.3] - 2025-12-30

### Fixed

- **Long-Term Validation (LTV) for revoked certificates** - Signatures made before certificate revocation are now correctly validated as valid when a trusted timestamp proves the signing time

## [0.2.2] - 2025-12-30

### Fixed

- **proxyUrl now works for timestamp revocation** - TSA certificate revocation checks now correctly use the proxy
- **XPath DOM mismatch error in browser** - Fixed "Node cannot be used in a document other than the one in which it was created" error when parsing XML in browsers

## [0.2.1] - 2025-12-30

### Added

- **CORS Proxy Support** - New `proxyUrl` option in `revocationOptions` for browser environments
  - Routes OCSP, CRL, and CA issuer certificate requests through a CORS proxy
  - Enables revocation checking in browsers where direct requests are blocked by CORS

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

[Unreleased]: https://github.com/edgarsj/edockit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/edgarsj/edockit/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/edgarsj/edockit/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/edgarsj/edockit/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/edgarsj/edockit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/edgarsj/edockit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/edgarsj/edockit/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/edgarsj/edockit/releases/tag/v0.1.2
