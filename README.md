# edockit

A JavaScript/TypeScript library for viewing and verifying Latvian eDoc signatures. Works in both browser and Node.js environments.

> **Disclaimer:** This is my first TypeScript/JavaScript library package. I welcome collaborators, feedback, and contributions to help improve it!

## About

This library supports both Latvian eDoc (.edoc) files and standard EU ASiC-E (.asice) containers, as they share the same underlying format. The library has been primarily tested on real Latvian eDoc files that were available.

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

// Parse an eDoc file
const edocBuffer = new Uint8Array(/* your eDoc file */);
const container = parseEdoc(edocBuffer);

// Get information about signatures
console.log('Files in container:', Array.from(container.files.keys()));
console.log('Signatures:', container.signatures);

// Verify signatures
for (const signature of container.signatures) {
  const result = verifySignature(signature, container.files);
  console.log(`Signature ${signature.id} is ${result.isValid ? 'valid' : 'invalid'}`);
}
```

## Features

- List files contained in eDoc/ASiC-E container
- Extract and display signature information
- Verify XML signatures against file checksums
- Validate certificate validity

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

Contributions are very welcome! If you encounter any issues, please open an issue on GitHub.

If you find files that don't work with this library, please consider adding them as examples in your issue report (if possible), as this will help tremendously with debugging and improving compatibility.

## License

MIT - See LICENSE file for details.
