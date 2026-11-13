# edockit

A JavaScript/TypeScript library for viewing and verifying EU standard ASiC-E containers, including Latvian eDoc files, which use the same format with a different extension. It works in both browser and Node.js environments.

> Note: Work in progress. This library still needs broader real-world testing with ASiC-E implementations from more EU countries.

## Installation

```bash
npm install edockit
```

If you implement trusted-list checking, [TRUSTED-LIST.md](TRUSTED-LIST.md) is required reading. The README only covers the quick-start path.

## Quick Start

```typescript
import { parseEdoc, verifySignature } from "edockit";
import { createTrustListProvider } from "edockit/trusted-list";

const container = parseEdoc(fileBuffer);

const trustListProvider = createTrustListProvider({
  url: "/assets/trusted-list.json",
});

const result = await verifySignature(container.signatures[0], container.files, {
  includeChecklist: true,
  trustListProvider,
  revocationOptions: {
    proxyUrl: "https://cors-proxy.example.com/?url=",
  },
  trustedListFetchOptions: {
    proxyUrl: "https://cors-proxy.example.com/?url=",
  },
});

console.log(result.status, result.statusMessage);
console.log(
  result.checklist?.find((item) => item.check === "issuer_trusted_at_signing_time"),
);
```

Use `revocationOptions.proxyUrl` in browsers because OCSP and CRL endpoints usually do not support CORS. `trustedListFetchOptions.proxyUrl` is only needed if the verifier must fetch issuer certificates to strengthen trusted-list matching.

## Verification Results

`verifySignature()` returns:

- `status`: `"VALID" | "INVALID" | "INDETERMINATE" | "UNSUPPORTED"`
- `statusMessage`: a human-readable explanation
- `checklist`: optional structured verification steps when `includeChecklist: true`
- `trustListMatch`: signer-issuer trust-list result when `trustListProvider` is configured
- `timestampTrustListMatch`: timestamp-authority trust-list result when `trustListProvider` is configured

`VALID` requires all of the following:

- the signature value verifies over the signature's own `SignedInfo`, every referenced file matches its digest, and the signature covers at least one file
- the XAdES `SignedProperties` are covered by the signature and their `SigningCertificate` matches the signer certificate
- a `trustListProvider` is configured, and the signer certificate was issued (cryptographically verified) by a certificate listed in the trusted list, trusted at the validation time
- revocation status is established (live OCSP/CRL, or a verified OCSP response embedded in the signature for long-term validation), unless `checkRevocation: false`
- a signature timestamp, if present, verifies, covers the signature and comes from a trusted timestamp authority

Proof of time comes only from a verified, trusted signature timestamp. The `SigningTime` claimed by the signer is reported but never used to evaluate certificate expiry or revocation; without a timestamp they are evaluated at the validation time (`verifyTime`, default now).

Without a `trustListProvider` the result is `INDETERMINATE` with the `TRUST_NOT_CHECKED` limitation: the signature is intact (`signature.isValid`, `checksums.isValid`), but the signer is not established. Other limitation codes include `ISSUER_NOT_TRUSTED`, `ISSUER_NOT_VERIFIED`, `REVOCATION_UNKNOWN`, `TIMESTAMP_AUTHORITY_NOT_TRUSTED`, `TIMESTAMP_VERIFICATION_FAILED` and `CERT_EXPIRED_NO_POE`.

`allowWeakDnOnlyTrustMatch` is off by default, so DN-only trusted-list matches remain `indeterminate` in the checklist; they never produce `VALID`.

`parseEdoc(buffer, options)` rejects containers with unsafe entry names (absolute paths, `..` segments, duplicates) and enforces size limits (`maxEntries`, `maxEntrySize`, `maxTotalSize`; see `DEFAULT_PARSE_EDOC_LIMITS`).

## Trusted List Setup

Recommended production path:

1. Generate your own compact trusted-list bundle in CI or a build step.
2. Host that JSON from your own app or CDN.
3. Load it with `createTrustListProvider({ url })`.

Build-time generation uses the Node-only helper:

```typescript
import { generateTrustedListBundle } from "edockit/trusted-list/build";

await generateTrustedListBundle({
  outputPath: "public/assets/trusted-list.json",
});
```

Runtime local matching uses:

```typescript
import { createTrustListProvider } from "edockit/trusted-list";
```

Other opt-in trusted-list subpaths:

- `edockit/trusted-list/build`: Node-only bundle generation helpers
- `edockit/trusted-list/http`: tiny remote API wrapper
- `edockit/trusted-list/bundled`: explicit bundled fallback snapshot

For proper trusted-list integration, remote API usage, hybrid local+remote setups, the provider contract, and bundle/manifest details, read [TRUSTED-LIST.md](TRUSTED-LIST.md).

## Timestamp Utilities

The root package also exposes timestamp helpers:

```typescript
import { getTimestampTime, parseTimestamp, verifyTimestamp } from "edockit";
```

Use these if you need direct RFC 3161 parsing or verification outside `verifySignature()`.

## Features

- Parse ASiC-E containers, including Latvian `.edoc`
- Verify XML signatures and signed file checksums
- Validate signer certificates at the relevant signing time
- Verify RFC 3161 timestamps
- Check revocation for signer and TSA certificates
- Return granular validation statuses instead of only boolean success/failure
- Return a structured verification checklist for consumer applications
- Match both signer issuers and timestamp authorities against a trusted list through an explicit provider contract

## Compatibility

The library has been used in production to verify ASiC-E containers across a range of signature algorithms, certificate authorities, and vendor implementations.

If the library fails to parse a valid container or does not recognize a signature format, please [open an issue](https://github.com/edgarsj/edockit/issues) or contact [edocviewer@zenomy.tech](mailto:edocviewer@zenomy.tech) and attach the sample file (if it does not contain sensitive or personal data). Real-world samples from other EU and non-EU countries are especially helpful.

## Contributing

Contributions are welcome, especially:

- real-world ASiC-E samples from different countries
- bug reports with reproducible files when possible
- interoperability fixes
