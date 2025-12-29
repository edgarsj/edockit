# edockit

A JavaScript/TypeScript library for viewing and verifying EU standard ASiC-E containers (including Latvian eDoc files, which use the same format with a different extension). Works in both browser and Node.js environments.

> **Note: Work in Progress** - This library is under active development and requires more real-world testing with various ASiC-E implementations from different European countries. If you have sample files or encounter issues, please contribute!

## About

This library supports standard European ASiC-E (.asice, .sce) containers as defined by the ETSI standards. Latvian eDoc (.edoc) files are effectively ASiC-E containers with a different file extension, so they are also supported. While the core functionality exists, extensive testing with real-world documents from various EU countries is still needed to ensure complete compatibility across different implementations.

## Installation

```bash
# Install the core library
npm install edockit

# If using in Node.js environment, also install xmldom
npm install @xmldom/xmldom
```

## Usage

### Basic Usage

```typescript
import { parseEdoc, verifySignature } from 'edockit';

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

// Verify a signature (with optional revocation checking)
const result = await verifySignature(container.signatures[0], container.files, {
  checkRevocation: true,  // Enable OCSP/CRL checking (defaults to false)
  ocspTimeout: 5000,      // OCSP request timeout in ms (defaults to 5000)
  crlTimeout: 10000,      // CRL fetch timeout in ms (defaults to 10000)
  verifyTime: new Date()  // Verify certificate at specific time (defaults to now)
});
// result = {
//   isValid: boolean,                // Overall validity
//   certificate: {
//     isValid: boolean,              // Certificate validity (time-based)
//     revocation: {                  // Revocation check result (if checkRevocation: true)
//       status: 'good' | 'revoked' | 'unknown' | 'error',
//       method: 'ocsp' | 'crl' | 'none',
//       checkedAt: Date,
//       isValid: boolean
//     }
//   },
//   checksums: {isValid: boolean},   // File checksums validation result
//   signature: {isValid: boolean},   // XML signature validation result
//   errors: string[]                 // Any validation errors (if present)
// }
console.log(`Signature valid: ${result.isValid}`);
```

### Node.js Example

```typescript
import { readFileSync } from "fs";
import { parseEdoc, verifySignature } from "edockit";

// Read file
const fileBuffer = readFileSync("document.asice");
const container = parseEdoc(fileBuffer);

// Check signatures with revocation checking
for (const signature of container.signatures) {
  const result = await verifySignature(signature, container.files, {
    checkRevocation: true
  });
  console.log(`Signature valid: ${result.isValid}`);

  if (result.certificate.revocation) {
    console.log(`Revocation status: ${result.certificate.revocation.status}`);
  }

  if (!result.isValid && result.errors) {
    console.log(`Errors: ${result.errors.join(', ')}`);
  }
}
}
```

### Browser Example

```javascript
// Fetch and verify a document
async function verifyDocument(url) {
  const response = await fetch(url);
  const fileBuffer = await response.arrayBuffer();

  const container = parseEdoc(new Uint8Array(fileBuffer));

  // List document files
  console.log("Documents:", container.documentFileList);

  for (const signature of container.signatures) {
    const result = await verifySignature(signature, container.files, {
      checkRevocation: true,
    });
    console.log(`Valid: ${result.isValid}`);
    if (result.certificate.revocation) {
      console.log(`Revocation: ${result.certificate.revocation.status}`);
    }
  }
}
```

## Features

- Support for EU standard ASiC-E containers and Latvian eDoc files/containers (same format, different extension)
- List files contained in ASiC-E/eDoc container
- Extract and display signature information
- Verify XML signatures against file checksums
- Validate certificate validity (time-based)
- Optional OCSP/CRL revocation checking with soft-fail behavior (network errors don't invalidate signatures)

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
