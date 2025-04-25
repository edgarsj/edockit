# Test Fixtures

This directory contains files used for testing the Latvian eDoc library.

## Sensitive Fixtures

Some tests require files with sensitive information that should **not** be committed to the repository. These files should be placed in the `/tests/fixtures/sensitive/` directory, which is excluded from git via `.gitignore`.

### Required Sensitive Fixtures

For integration tests to pass, place the following files in the sensitive directory:

- `Sample File.edoc` - A sample eDoc file containing signed documents

### Why eDoc Files Often Contain Sensitive Data

Latvian eDoc files typically contain identifying information about the signers:
- Each eDoc usually contains the signer's full name and personal identification number
- These personal identifiers cannot be stored in Git without that person's consent
- Documents signed with company certificates rather than personal certificates are welcome for testing purposes

This is why the `/tests/fixtures/sensitive/` directory was created - to allow testing with real eDoc files without exposing personal information in the repository.

### Obtaining Test Fixtures

If you need access to the test fixtures:

1. Contact the project maintainer to obtain the test files securely
2. Place the files in the `/tests/fixtures/sensitive/` directory
3. Ensure these files are never committed to the repository

### Running Tests Without Sensitive Fixtures

Tests requiring sensitive fixtures will be automatically skipped if the files are not present. This ensures CI/CD pipelines can run without requiring sensitive data.

## Public Fixtures

Files in this main fixtures directory (/tests/fixtures/) are committed to the repository and should never contain real public edoc signatures that contain sensitive data like:

- Personal identification numbers
- Real names or addresses
- Any information that could identify a real person

## File Lists for Browser Tests

Browser tests use `filelist.json` files to discover test files since browser environments can't access the filesystem directly. These JSON files are simple arrays listing the filenames in each directory:

```json
[
  "example1.edoc",
  "example2.asice",
  "example3.edoc"
]
```

### Maintaining File Lists

When adding or removing test files, remember to update the corresponding `filelist.json`:

1. `/tests/fixtures/sensitive/valid_samples/filelist.json` - For sensitive valid samples
2. `/tests/fixtures/valid_samples/filelist.json` - For public valid samples

This approach allows browser tests to discover files without hardcoding sensitive filenames in test code.

## Creating New Test Fixtures

When creating new test fixtures:

1. Use synthetic/fictional data whenever possible
2. If real data must be used, sanitize all personally identifiable information
3. Place files with sensitive data only in the `/tests/fixtures/sensitive/` directory
4. Document any special requirements for new test fixtures in this README
5. Update the corresponding `filelist.json` file

## Modifying Tests

When writing tests that use sensitive fixtures:

```javascript
// Example pattern for tests with sensitive fixtures
const sensitiveFilePath = join(__dirname, "../fixtures/sensitive/Sample File.edoc");
const fileExists = existsSync(sensitiveFilePath);

(fileExists ? it : it.skip)("should parse and verify a real eDoc file", async () => {
  // Test code here
});
```

This pattern ensures tests will be skipped when sensitive fixtures are unavailable.
