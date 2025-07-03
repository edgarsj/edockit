# edockit

A JavaScript/TypeScript library for viewing and verifying EU standard ASiC-E containers (including Latvian eDoc files, which use the same format with a different extension). Works in both browser and Node.js environments.

> **Note: Work in Progress** - This library is under active development and requires more real-world testing with various ASiC-E implementations from different European countries. If you have sample files or encounter issues, please contribute!

> **Important:** Certificate validation currently lacks OCSP checks (Online Certificate Status Protocol). Adding OCSP support is on the roadmap and will be implemented in a future release.

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

// Verify a signature
const result = await verifySignature(container.signatures[0], container.files);
// result = {
//   isValid: boolean,                // Overall validity
//   certificate: {isValid: boolean}, // Certificate validation result
//   checksums: {isValid: boolean},   // File checksums validation result
//   signature: {isValid: boolean},   // XML signature validation result
//   errors: string[]                 // Any validation errors (if present)
// }
console.log(`Signature valid: ${result.isValid}`);
```

### Node.js Example

```typescript
import { readFileSync } from 'fs';
import { parseEdoc, verifySignature } from 'edockit';

// Read file
const fileBuffer = readFileSync('document.asice');
const container = parseEdoc(fileBuffer);

// Check signatures
for (const signature of container.signatures) {
  const result = await verifySignature(signature, container.files);
  console.log(`Signature valid: ${result.isValid}`);

  if (!result.isValid && result.errors) {
    console.log(`Errors: ${result.errors.join(', ')}`);
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
    const result = await verifySignature(signature, container.files);
    console.log(`Valid: ${result.isValid}`);
  }
}
```

## Features

- Support for EU standard ASiC-E containers and Latvian eDoc files/containers (same format, different extension)
- List files contained in ASiC-E/eDoc container
- Extract and display signature information
- Verify XML signatures against file checksums
- Validate certificate validity (Note: OCSP validation planned for future releases)

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
