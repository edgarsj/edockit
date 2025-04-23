# XML Canonicalization (C14N) Test Samples

This folder contains sample XML files used for testing XML Canonicalization implementations.

## Important Notes on File Content

### Trailing Newlines
- **No trailing newlines should be added to canonicalized XML files**
- The XML C14N specification does not require trailing newlines after the final end tag
- Standard implementations like Java's xmlsec do not add trailing newlines
- Files in this directory explicitly **omit trailing newlines** to match reference implementations (or not for same reasons).

### Whitespace Preservation
- Exact whitespace must be preserved during test comparisons
- Do not normalize, trim, or modify whitespace when comparing test outputs
- Whitespace inside elements must be preserved exactly as in the original document

## Test File Naming Conventions

- `*_c14n.xml` - Files canonicalized using XML C14N 1.0
- `*_c14n11.xml` - Files canonicalized using XML C14N 1.1
- `*_c14n_exc.xml` - Files canonicalized using Exclusive XML Canonicalization
- `*_java.xml` - Reference outputs from Java's xmlsec implementation

## Usage in Tests

When comparing outputs from your canonicalization implementation with these sample files:

1. Do not add or remove trailing newlines
2. Store test outputs with the exact same whitespace/newline conventions as these reference files

## Reference

These test files follow the XML Canonicalization specification examples. For more details, see:
- [XML Canonicalization 1.0](https://www.w3.org/TR/xml-c14n)
- [XML Canonicalization 1.1](https://www.w3.org/TR/xml-c14n11/)
- [Exclusive XML Canonicalization 1.0](https://www.w3.org/TR/xml-exc-c14n/)
