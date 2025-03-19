# Latvian eDoc Signature Library

A JavaScript/TypeScript library for viewing and verifying Latvian eDoc signatures. Works in both browser and Node.js environments.

## Installation

```bash
# Install the core library
npm install edockit

# If using in Node.js environment, also install xmldom
npm install xmldom
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

- List files contained in eDoc container
- Extract and display signature information
- Verify XML signatures against file checksums
- Validate certificate validity

## Browser Extension Usage

For browser extensions, use the UMD build:

```html
<script src="node_modules/edockit/dist/index.umd.js"></script>
<script>
  const { parseEdoc } = LatvianEdoc;

  // Your code here
</script>
```
