# edockit

A JavaScript/TypeScript library for viewing and verifying EU standard ASiC-E containers (including Latvian eDoc files, which use the same format with a different extension). Works in both browser and Node.js environments.

> **Note: Work in Progress** - This library is under active development and requires more real-world testing with various ASiC-E implementations from different European countries. If you have sample files or encounter issues, please contribute!

## About

This library supports standard European ASiC-E (.asice) containers as defined by the ETSI standards. Latvian eDoc (.edoc) files are effectively ASiC-E containers with a different file extension, so they are also supported. While the core functionality exists, extensive testing with real-world documents from various EU countries is still needed to ensure complete compatibility across different implementations.

## Installation

```bash
# Install the core library
npm install edockit

# If using in Node.js environment, also install jsdom
npm install jsdom
```

## Usage

```typescript
import { parseEdoc, verifySignature } from 'edockit';

// Parse an ASiC-E/eDoc file
const containerBuffer = new Uint8Array(/* your ASiC-E or eDoc file */);
const container = parseEdoc(containerBuffer);

// Get information about signatures
console.log('Files in container:', Array.from(container.files.keys()));
console.log('Signatures:', container.signatures);

// Verify signatures
for (const signature of container.signatures) {
  const result = await verifySignature(signature, container.files);
  console.log(`Signature ${signature.id} is ${result.isValid ? 'valid' : 'invalid'}`);
}
```

## Features

- Support for EU standard ASiC-E containers and Latvian eDoc files/containers (same format, different extension)
- List files contained in ASiC-E/eDoc container
- Extract and display signature information
- Verify XML signatures against file checksums
- Validate certificate validity

## Testing Status

The library has been tested with a limited set of real Latvian eDoc files (which are ASiC-E containers with a .edoc extension). More testing is needed with:
- ASiC-E containers from different EU countries
- Files created with different software implementations
- Various signature algorithms and certificate types
- Edge cases and non-standard implementations

## Browser Extension Usage

For browser extensions, use the UMD build:

```html
<script src="node_modules/edockit/dist/index.umd.js"></script>
<script>
  const { parseEdoc } = parseEdoc;

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
