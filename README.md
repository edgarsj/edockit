# edockit

A JavaScript/TypeScript library for viewing and verifying EU standard ASiC-E containers (including Latvian eDoc files, which use the same format with a different extension). Works in both browser and Node.js environments.

> **Note: Work in Progress** - This library is under active development and requires more real-world testing with various ASiC-E implementations from different European countries. If you have sample files or encounter issues, please contribute!

## About

This library supports standard European ASiC-E (.asice, .sce) containers as defined by the ETSI standards. Latvian eDoc (.edoc) files are effectively ASiC-E containers with a different file extension, so they are also supported. While the core functionality exists, extensive testing with real-world documents from various EU countries is still needed to ensure complete compatibility across different implementations.

## Installation

```bash
npm install edockit
```

For trusted-list setup patterns, see [TRUSTED-LIST.md](TRUSTED-LIST.md).

## Usage

### Basic Usage

```typescript
import { parseEdoc, verifySignature } from "edockit";
import { createTrustListProvider } from "edockit/trusted-list";

// Parse an ASiC-E/eDoc file
const fileBuffer = /* your file buffer */;
const container = parseEdoc(fileBuffer);
// container = {
//   files: Map<string, Uint8Array>,  // All files in the container
//   documentFileList: string[],      // Document files (.pdf, .docx, etc.)
//   metadataFileList: string[],      // Metadata files
//   signedFileList: string[],        // Files covered by signatures
//   signatures: SignatureInfo[]      // Signature objects
// }

// List files in container
console.log(Array.from(container.files.keys()));

const trustListProvider = createTrustListProvider({
  url: "/assets/trusted-list.json",
});

// Verify a signature (with revocation and timestamp checking)
const result = await verifySignature(container.signatures[0], container.files, {
  checkRevocation: true,   // OCSP/CRL checking (default: true)
  verifyTimestamps: true,  // RFC 3161 timestamp verification (default: true)
  includeChecklist: true,  // Add a structured verification checklist (default: false)
  trustListProvider,       // Optional: local or remote trusted-list provider
  revocationOptions: {     // Optional: configure revocation check behavior
    ocspTimeout: 5000,     // OCSP request timeout in ms (default: 5000)
    crlTimeout: 10000,     // CRL fetch timeout in ms (default: 10000)
    proxyUrl: "https://cors-proxy.example.com/?url=",  // CORS proxy for browser (optional)
  },
  trustedListFetchOptions: {
    proxyUrl: "https://cors-proxy.example.com/?url=",  // Optional: helps with issuer-cert fetches in browsers
  },
  verifyTime: new Date()   // Verify certificate at specific time (default: timestamp time if present, otherwise now)
});
// result = {
//   isValid: boolean,                // Overall validity (for backwards compatibility)
//   status: 'VALID' | 'INVALID' | 'INDETERMINATE' | 'UNSUPPORTED',  // Granular status
//   statusMessage?: string,          // Human-readable explanation
//   limitations?: [{                 // Platform/environment constraints (if any)
//     code: string,                  // e.g., 'RSA_KEY_SIZE_UNSUPPORTED'
//     description: string,
//     platform?: string              // e.g., 'Safari/WebKit'
//   }],
//   certificate: {
//     isValid: boolean,              // Certificate validity (time-based)
//     revocation: {                  // Revocation check result
//       status: 'good' | 'revoked' | 'unknown' | 'error',
//       method: 'ocsp' | 'crl' | 'none',
//       checkedAt: Date,
//       isValid: boolean
//     }
//   },
//   checksums: {isValid: boolean},   // File checksums validation result
//   signature: {isValid: boolean},   // XML signature validation result
//   timestamp: {                     // Timestamp verification (if present)
//     isValid: boolean,
//     info: { genTime: Date, policy: string, ... },
//     coversSignature: boolean,
//     tsaRevocation: { status, method, ... }
//   },
//   checklist: [{
//     check: 'document_integrity' | 'signature_valid' | 'certificate_valid_at_signing_time' |
//            'timestamp_present' | 'timestamp_valid' | 'timestamp_authority_trusted_at_signing_time' |
//            'certificate_not_revoked_at_signing_time' |
//            'issuer_trusted_at_signing_time',
//     label: string,
//     status: 'pass' | 'fail' | 'skipped' | 'indeterminate',
//     detail?: string,
//     country?: string
//   }],
//   trustListMatch: {
//     found: boolean,
//     trustedAtTime?: boolean,
//     confidence?: 'exact' | 'ski_dn' | 'dn_only',
//     country?: string,
//     detail?: string
//   },
//   errors: string[]                 // Any validation errors (if present)
// }
console.log(`Status: ${result.status}`);
console.log(result.checklist?.find((item) => item.check === "issuer_trusted_at_signing_time"));
```

### Verification Checklist and Trusted List

`verifySignature()` can optionally return a checklist of the main verification decisions and a
trusted-list match for both the signer issuer and the timestamp authority when a
`trustListProvider` is configured.

```typescript
import { createTrustListProvider } from "edockit/trusted-list";

const trustListProvider = createTrustListProvider({
  url: "/assets/trusted-list.json",
});

const result = await verifySignature(container.signatures[0], container.files, {
  includeChecklist: true,
  trustListProvider,
});

for (const item of result.checklist || []) {
  console.log(`${item.check}: ${item.status}${item.detail ? ` - ${item.detail}` : ""}`);
}

if (result.trustListMatch?.found) {
  console.log(result.trustListMatch.detail);
}
```

Notes:

- Checklist statuses are `pass`, `fail`, `skipped`, and `indeterminate`
- The recommended production path is app-hosted JSON plus `createTrustListProvider({ url })`
- `allowWeakDnOnlyTrustMatch` is off by default, so DN-only matches stay `indeterminate`
- `trustListProvider` can be local JSON-backed, remote API-backed, or hybrid

### Node.js Example

```typescript
import { readFileSync } from "fs";
import { parseEdoc, verifySignature } from "edockit";
import { createTrustListProvider } from "edockit/trusted-list";

// Read file
const fileBuffer = readFileSync("document.asice");
const container = parseEdoc(fileBuffer);
const trustListProvider = createTrustListProvider({
  data: JSON.parse(readFileSync("./trusted-list.json", "utf8")),
});

// Check signatures with revocation and timestamp checking
for (const signature of container.signatures) {
  const result = await verifySignature(signature, container.files, {
    checkRevocation: true,
    verifyTimestamps: true,
    includeChecklist: true,
    trustListProvider,
  });

  // Use granular status for detailed handling
  console.log(`Status: ${result.status}`); // VALID, INVALID, INDETERMINATE, or UNSUPPORTED

  if (result.status === "VALID") {
    console.log("Signature is valid");
  } else if (result.status === "UNSUPPORTED") {
    // Platform limitation (e.g., RSA >4096 bits in Safari)
    console.log(`Cannot verify: ${result.statusMessage}`);
  } else if (result.status === "INDETERMINATE") {
    // Can't conclude (e.g., revocation status unknown)
    console.log(`Inconclusive: ${result.statusMessage}`);
  } else {
    // INVALID - definitely wrong
    console.log(`Invalid: ${result.statusMessage}`);
  }

  if (result.timestamp?.info) {
    console.log(`Signed at (TSA): ${result.timestamp.info.genTime}`);
  }

  const trustItem = result.checklist?.find(
    (item) => item.check === "issuer_trusted_at_signing_time",
  );
  if (trustItem) {
    console.log(`Trusted issuer at signing time: ${trustItem.status}`);
  }

  if (result.certificate.revocation) {
    console.log(`Revocation status: ${result.certificate.revocation.status}`);
  }
}
```

### Browser Example

```javascript
import { parseEdoc, verifySignature } from "edockit";
import { createTrustListProvider } from "edockit/trusted-list";

// Fetch and verify a document
async function verifyDocument(url) {
  const response = await fetch(url);
  const fileBuffer = await response.arrayBuffer();

  const container = parseEdoc(new Uint8Array(fileBuffer));
  const trustListProvider = createTrustListProvider({
    url: "/assets/trusted-list.json",
  });

  // List document files
  console.log("Documents:", container.documentFileList);

  for (const signature of container.signatures) {
    const result = await verifySignature(signature, container.files, {
      checkRevocation: true,
      includeChecklist: true,
      trustListProvider,
      revocationOptions: {
        // Use a CORS proxy for OCSP/CRL requests in browser environments
        proxyUrl: "https://your-cors-proxy.example.com/?url=",
      },
      trustedListFetchOptions: {
        // Optional: use a proxy if issuer certificates need to be fetched for stronger matches
        proxyUrl: "https://your-cors-proxy.example.com/?url=",
      },
    });

    // Handle different validation states
    if (result.status === "VALID") {
      console.log("Signature verified successfully");
    } else if (result.status === "UNSUPPORTED") {
      // Some signatures can't be verified in certain browsers (e.g., RSA >4096 in Safari)
      console.log(`Browser limitation: ${result.statusMessage}`);
    } else {
      console.log(`${result.status}: ${result.statusMessage}`);
    }

    if (result.timestamp?.info) {
      console.log(`Timestamp: ${result.timestamp.info.genTime}`);
    }
  }
}
```

> **Note:** OCSP and CRL endpoints typically don't support CORS, so browser environments need a proxy to perform revocation checks. The `proxyUrl` option routes all revocation requests through the specified proxy, which should accept the original URL as a query parameter.

> **Note:** The recommended browser trusted-list setup is a compact JSON file hosted by your own app and loaded through `edockit/trusted-list`. The optional bundled fallback lives in `edockit/trusted-list/bundled` and is meant for convenience, not as the primary production path.

### Timestamp Utilities

For advanced timestamp handling, you can use the timestamp utilities directly:

```typescript
import { parseTimestamp, verifyTimestamp, getTimestampTime } from "edockit";

// Get timestamp time from a signature (quick utility)
const timestampTime = getTimestampTime(signature.signatureTimestamp);
console.log(`Signed at: ${timestampTime}`);

// Parse timestamp for detailed info
const info = parseTimestamp(signature.signatureTimestamp);
// info = {
//   genTime: Date,           // When TSA signed
//   policy: string,          // TSA policy OID
//   hashAlgorithm: string,   // e.g., 'SHA-256'
//   messageImprint: string,  // Hash of timestamped data
//   tsaName?: string,        // TSA name
//   tsaCertificate?: string, // TSA cert in PEM format
// }

// Verify timestamp with options
const result = await verifyTimestamp(signature.signatureTimestamp, {
  canonicalSignatureValue: signature.canonicalSignatureValue, // Verify timestamp covers the canonicalized ds:SignatureValue element
  verifyTsaCertificate: true, // Check TSA cert validity
  checkTsaRevocation: true, // Check TSA cert revocation
});
```

### Trusted List Utilities

Trusted-list runtime is split into opt-in subpaths:

```typescript
import { verifySignature } from "edockit";
import { createTrustListProvider } from "edockit/trusted-list";
import { generateTrustedListBundle } from "edockit/trusted-list/build";
import { createRemoteTrustListProvider } from "edockit/trusted-list/http";
import { createBundledTrustListProvider } from "edockit/trusted-list/bundled";

await generateTrustedListBundle({
  outputPath: "public/assets/trusted-list.json",
});

const localProvider = createTrustListProvider({
  url: "/assets/trusted-list.json",
});

const remoteProvider = createRemoteTrustListProvider({
  url: "/api/trust-list/match",
});

const bundledProvider = createBundledTrustListProvider();

const result = await verifySignature(signature, files, {
  trustListProvider: localProvider,
});
```

Use `edockit/trusted-list/build` only in Node.js build scripts or CI. Keep browser code on `edockit/trusted-list` and `edockit/trusted-list/http`.
For the recommended production layout and rollout path, see [TRUSTED-LIST.md](TRUSTED-LIST.md).

## Features

- Support for EU standard ASiC-E containers and Latvian eDoc files/containers (same format, different extension)
- List files contained in ASiC-E/eDoc container
- Extract and display signature information
- Verify XML signatures against file checksums
- Validate certificate validity (time-based)
- RFC 3161 timestamp verification (when present, certificate is validated at the trusted TSA timestamp time)
- OCSP/CRL revocation checking for both signer and TSA certificates (soft-fail behavior - network errors don't invalidate signatures)
- Structured verification checklist for consumer applications
- Trusted-list issuer and TSA matching through an explicit provider contract
- Local trusted-list matching from app-hosted compact JSON via `edockit/trusted-list`
- Node-only JSON bundle generation via `edockit/trusted-list/build`
- Optional bundled fallback via `edockit/trusted-list/bundled`
- Optional remote API helper via `edockit/trusted-list/http`

## Testing Status

The library has been tested with a limited set of real Latvian eDoc files (which are ASiC-E containers with a .edoc extension). More testing is needed with:

- ASiC-E containers from different EU countries
- Files created with different software implementations
- Various signature algorithms and certificate types
- Edge cases and non-standard implementations

## Browser Usage with UMD Build

If you're not using a module bundler, you can use the UMD build:

```html
<script src="path/to/edockit/dist/index.umd.js"></script>
<script>
  // Access the library from the global 'edockit' object
  const { parseEdoc, verifySignature } = edockit;

  // Your code here
</script>
```

## Contributing

Contributions are highly encouraged! The library needs more real-world testing to improve compatibility and robustness. In particular:

1. Testing with ASiC-E containers from different European countries
2. Bug reports with sample files (when possible)
3. Feature requests for specific EU country implementations
4. Documentation improvements

If you encounter any issues, please open an issue on GitHub. Including sample files with your issue report (if possible) will help tremendously with debugging and improving compatibility.

## License

MIT - See LICENSE file for details.
