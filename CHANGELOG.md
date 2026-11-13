# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Signature qualification** - `verifySignature()` reports `qualification` (`QESig`, `QESeal`, `AdESig-QC`, `AdESeal-QC`, `AdESig`, `AdESeal`, `AdES`, `INDETERMINATE`) with the certificate type (`esign` / `eseal` / `web`) and QSCD status, determined from the certificate's QC statements and the issuing service's trusted-list data (granted `CA/QC` status at issuance and signing time, `ForeSignatures` / `ForeSeals` / `ForWebSiteAuthentication`, qualifiers such as `QCWithQSCD` or `NotQualified`)
- **QC statements** - `getQcStatements()` / `parseQcStatementsValue()` parse the qcStatements certificate extension (QcCompliance, QcType, QcSSCD, QcPDS, QcRetentionPeriod, QcCClegislation, semantics identifier); `getCertificateQualificationFacts()` adds policies, key usage, extended key usage and subject attributes
- **Trusted-list qualification data** - Trusted-list parsing keeps AdditionalServiceInformation and Qualifications extensions per history period; exact signature-issuer matches carry `qualificationPeriods`
- **Build helpers** - `edockit/trusted-list/build` exports `fetchTrustedListBundleWithDiagnostics` and `mergeForwardUnreachableTerritories` (version 3 bundles only); `edockit/trusted-list/bundled` exports `getBundledTrustedListBundle()`

### Changed

- **Trusted-list bundle version 3** - SPKI hashes are stored as 144-bit lookup keys, SKIs are dropped, DNs are stored normalized and qualification data is added as a codebook. The gzipped bundle is about 35% smaller and loads several times faster. Version 2 bundles remain readable; older edockit versions cannot match version 3 bundles. `TrustedListEntry.spkiSha256Hex` is replaced by `spkiKey` and `TrustedListIndexes.bySpkiSha256` by `bySpkiKey`; SKI + DN matches (`ski_dn`) are only possible with version 2 bundles
- **Bundled snapshot** - Embedded as a `JSON.parse` string (faster to load than an object literal) and left out of source maps

### Fixed

- **Pre-2016 trusted-list statuses** - The Directive 1999/93/EC statuses `undersupervision` and `supervisionincessation` are treated as trusted, so services in the history of national lists before 1 July 2016 match signatures from that period
- **Build options** - `generateTrustedListBundle` passes `retries` and `allowInsecureHttp` to the fetcher

## [0.5.0] - 2026-11-13

### Added

- **Trusted-list match source** - `TrustListMatch` now carries `source` / `sourceLabel` identifying the LOTL a matched service was published through (`"eu"` or `"ades"` with the default sources), so applications can distinguish third-country trusted lists (AdES LOTL) from EU/EEA ones. Compact bundles store this as an optional seventh element (source index) per service; older bundles remain readable

### Changed

- **Stricter validation status** - `VALID` now requires a configured `trustListProvider` and an issuer certificate that cryptographically issued the signer certificate and is listed in the trusted list (SPKI match). Without a provider the status is `INDETERMINATE` (`TRUST_NOT_CHECKED`); a SKI/DN-only match is `INDETERMINATE` (`ISSUER_NOT_VERIFIED`); an available issuer certificate that did not sign the signer certificate is `INVALID`
- **Proof of time** - Certificate expiry and revocation are evaluated at the time of a verified signature timestamp from a trusted timestamp authority, otherwise at the validation time. The claimed `SigningTime` is reported but no longer used for these checks
- **Revocation** - Unknown or unavailable revocation status is now `INDETERMINATE` (`REVOCATION_UNKNOWN`) instead of passing. OCSP responses are verified (signature, responder authorization, CertID, freshness) and CRLs are verified (issuer signature, issuer name, freshness) before their status is used. Verified OCSP responses embedded in the signature are used for long-term validation when live data is unavailable
- **Timestamp validation** - RFC 3161 tokens are verified cryptographically (CMS signature, message digest, TSA certificate identified by `sid`, ESS signing-certificate binding, timeStamping EKU); a token that does not cover the signature is invalid
- **Signature structure** - `SignedInfo`, `SignatureValue`, `KeyInfo`, references and qualifying properties are resolved by their exact position in the top-level `ds:Signature`; same-document references (`SignedProperties`) are digest-verified and `SigningCertificate(V2)` is checked against the signer certificate. A signature that covers no files is `INVALID`
- **Container parsing** - `parseEdoc(buffer, options)` enforces entry-count and size limits (`ParseEdocOptions`, `DEFAULT_PARSE_EDOC_LIMITS`) and rejects unsafe or duplicate entry names; the text-based signature fallback was removed
- **Network limits** - Revocation and certificate fetches accept only `http:`/`https:` URLs (including redirects), cap response sizes and the number of URLs per certificate, and apply the timeout to the body read
- **Refreshed bundled EU trusted-list snapshot** - Regenerated from the EU LOTL and AdES LOTL on 2026-11-13 (3811 → 3847 services)
- **Trusted lists fetched over HTTPS by default** - `http://` LOTL/TSL locations (e.g. the Slovak TSL pointer) are upgraded to `https://` because trusted-list XML signatures are not verified by the builder; opt out with `allowInsecureHttp: true`. Failed endpoints are retried once (`retries` option)

### Fixed

- **XML canonicalization** - Canonical XML 1.0, 1.1 and exclusive c14n now match libxml2 output: exclusive c14n renders namespace declarations where visibly used; inclusive subtrees pass their rendered namespace context to descendants and carry inherited `xml:*` attributes (with the C14N 1.1 `xml:base` fixup); text and attribute escaping, attribute ordering, CDATA sections, processing instructions and `#WithComments` follow the specifications; unknown canonicalization URIs are rejected instead of falling back to inclusive c14n
- **RSA DigestInfo compatibility check** - The non-standard (NULL-less) DigestInfo fallback now requires an exact encoding match

### Security

- **Dependency advisories** - `fflate` 0.8.3 (infinite loop on malformed ZIP64 archives in `unzipSync`) and `@xmldom/xmldom` 0.9.12 (well-formedness bypasses and quadratic-time/memory parsing DoS). Dev toolchain moved to `@web/test-runner` 1.x; `npm audit --omit=dev` reports 0 vulnerabilities

## [0.4.1] - 2026-06-26

### Added

- **Embedded XAdES RevocationValues exposed** - `SignatureInfo.revocationValues` exposes the raw embedded OCSP/CRL material (base64 DER) from `xades:UnsignedSignatureProperties`. These properties are unsigned, so edockit does **not** use them as a revocation verdict; they are provided for consumers performing their own authenticated long-term validation
- **Trusted-list bundle identifier** - Compact trusted-list bundles and the bundled snapshot now carry a top-level `bundleId` (derived from `generatedAt`) so downstream consumers can identify a snapshot (previously `null`)
- **Resilient trusted-list regeneration** - `npm run update-trusted-list` carries forward last-known-good services only when every advertised TSL endpoint for a territory explicitly fails to fetch or parse, so transient failures and HTTP 200 error pages cannot silently drop a country while valid empty TSLs and successful removals are not resurrected; it also falls back to Node's native http(s) client for endpoints that block undici's client fingerprint (e.g. Estonia's `sr.riik.ee`)

### Changed

- **Lighter live revocation** - The issuer certificate required to build an OCSP request is now also resolved from certificates embedded in the signature's `RevocationValues` OCSP responses, and OCSP issuer resolution requires a candidate whose key actually signed the certificate — a same-name certificate that did not issue it is rejected and the AIA lookup is used instead. When the container ships no certificate chain, this lets the small live OCSP query answer revocation instead of falling back to downloading the full CRL (verified end-to-end: `method: "ocsp"` instead of `"crl"` for the LV eID sample). The status in the embedded response is not trusted — a fresh OCSP query is still made
- **Refreshed bundled EU trusted-list snapshot** - Regenerated from the EU LOTL with a fresh `generatedAt` and `bundleId`
- **Declared direct dependencies** - `asn1js`, `@peculiar/asn1-schema`, and `@peculiar/asn1-x509` are now declared dependencies (previously relied on transitively)

### Fixed

- **Per-signature XAdES properties** - `parseSignatureElement` now reads `RevocationValues`, `CertificateValues`, `SigningTime`, and `SignatureTimeStamp` from the current signature element instead of document-wide, so a signature in a multi-signature document no longer inherits the first signature's embedded material (which would point OCSP issuer resolution at the wrong certs)
- **Large national CRL parsing** - `parseCRL()` now parses CRLs that exceed asn1js's default `DEFAULT_MAX_NODES` (10000) DoS guard (e.g. the ~13k-entry Latvian LV eID CRL) by re-parsing with a raised, bounded node limit. Fixes `certificate_not_revoked_at_signing_time` returning `INDETERMINATE` with "Failed to parse CRL data" against `asn1js@^3.0.9`
- **InclusiveNamespaces XPath warning** - Node XPath queries now resolve namespace prefixes via `xpath.useNamespaces` instead of misusing `xpath.select`'s third (`single`) argument as a resolver, eliminating noisy "XPath evaluation failed" errors during signature parsing

### Security

- **Dependency advisory cleanup** - Updated the only affected runtime dependency, `@xmldom/xmldom`, to 0.9.10 (resolves high-severity XML injection and serialization DoS advisories) and cleared all remaining `npm audit` findings in the dev/test toolchain via in-range bumps and `esbuild`/`js-yaml` overrides. `npm audit` now reports 0 vulnerabilities

## [0.4.0] - 2026-03-19

### Added

- **Verification checklist output** - `verifySignature()` can now return a structured `checklist` with per-check status details when `includeChecklist: true`
- **Pluggable trusted-list provider support** - `verifySignature()` now uses `trustListProvider` for trust-list checks instead of built-in root-level trusted-list behavior
- **Purpose-aware trusted-list matching** - Trusted-list checks now distinguish signer issuer lookup from timestamp authority lookup and expose both `trustListMatch` and `timestampTrustListMatch`
- **Trusted-list package split** - Added opt-in subpath exports for `edockit/trusted-list`, `edockit/trusted-list/build`, `edockit/trusted-list/http`, and `edockit/trusted-list/bundled`
- **Compact trusted-list bundle format** - Added local matching against compact JSON bundles with a dedicated provider contract
- **Public Node-only trusted-list builder** - Added `edockit/trusted-list/build` for generating app-hosted trusted-list JSON, along with the repository `npm run update-trusted-list` script

### Changed

- **Trust-list aware validation status** - When a `trustListProvider` is configured and the signer's issuer is not found or not trusted at signing time, overall status is now `INDETERMINATE` (previously `VALID`). Also downgrades to `INDETERMINATE` when the trust-list provider throws an error.
- **ESM-compatible module builds** - `@xmldom/xmldom` and `xpath` are now externalized in ESM/CJS builds with proper `import` statements, fixing `"XML DOM parser not available"` errors in Node.js ESM consumers

### Fixed

- **SignatureTimeStamp canonicalization** - Respect the timestamp's declared canonicalization method when hashing `ds:SignatureValue`, fixing false `coversSignature: false` results for some real samples
- **Skip LDAP CRL distribution points** - Filter out non-HTTP(S) URLs from CRL distribution points to avoid failed fetch attempts on unsupported protocols like LDAP
- **Timestamp trust-list evaluation** - Trusted-list verification now checks timestamp authorities at the timestamp signing time instead of only checking the signer issuer side
- **TypeScript 5.9 compatibility** - Fix `Uint8Array`/`BufferSource` type errors in Web Crypto API calls
- **Package security updates** - Update transitive dependencies to resolve vulnerabilities in rollup, minimatch, koa, basic-ftp, diff, qs, and brace-expansion

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

[Unreleased]: https://github.com/edgarsj/edockit/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/edgarsj/edockit/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/edgarsj/edockit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/edgarsj/edockit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/edgarsj/edockit/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/edgarsj/edockit/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/edgarsj/edockit/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/edgarsj/edockit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/edgarsj/edockit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/edgarsj/edockit/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/edgarsj/edockit/releases/tag/v0.1.2
