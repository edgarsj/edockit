import { readFileSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../src/core/parser";
import {
  parseCertificate,
  getSignerDisplayName,
  formatValidityPeriod,
} from "../../src/core/certificate";
import { verifyChecksums, verifySignature } from "../../src/core/verification";

// Path to directory containing valid eDoc samples
const validSamplesDir = join(__dirname, "../fixtures/sensitive/valid_samples");
const validSamplesDirExists = existsSync(validSamplesDir);

// Get file list immediately to use for defining tests
let edocFiles: string[] = [];
if (validSamplesDirExists) {
  try {
    edocFiles = readdirSync(validSamplesDir)
      .filter((filename) => filename.toLowerCase().endsWith(".edoc"))
      .map((filename) => join(validSamplesDir, filename));
    console.log(`Found ${edocFiles.length} .edoc files in ${validSamplesDir}`);
  } catch (error) {
    console.error(
      "Error reading directory:",
      error instanceof Error ? error.message : String(error),
    );
  }
}
const describeFunc = validSamplesDirExists ? describe : describe.skip;

describeFunc("Valid eDoc Samples Batch Verification", () => {
  it("should find the valid samples directory", () => {
    expect(validSamplesDirExists).toBe(true);
  });

  // Skip testing files if none were found
  if (edocFiles.length === 0) {
    it("No .edoc files found - skipping validation tests", () => {
      console.log(
        "No .edoc files found in samples directory. Add some to run batch validation tests.",
      );
      return;
    });
  } else {
    // Tests for each found .edoc file
    edocFiles.forEach((filePath) => {
      const filename = filePath.split("/").pop() || "";

      it(`should validate eDoc file: ${filename}`, async () => {
        try {
          // Read and parse the eDoc file
          const edocBuffer = readFileSync(filePath);
          const container = parseEdoc(edocBuffer);

          // Verify the container has at least one signature
          expect(container.signatures.length).toBeGreaterThan(0);

          // Track overall status for this file
          let isFileValid = true;
          let signerNames: string[] = [];
          let validationErrors: string[] = [];

          // Test each signature in the file
          for (let i = 0; i < container.signatures.length; i++) {
            const signature = container.signatures[i];
            let signerName = `Unknown-${i}`;

            // Get signer info if available
            if (signature.certificatePEM) {
              try {
                const certInfo = await parseCertificate(signature.certificatePEM);
                signerName = getSignerDisplayName(certInfo);
                signerNames.push(signerName);

                // Verify certificate info
                if (
                  !certInfo.subject.commonName &&
                  !(certInfo.subject.givenName && certInfo.subject.surname)
                ) {
                  isFileValid = false;
                  validationErrors.push(`Signature #${i + 1}: Missing signer information`);
                }
              } catch (error) {
                isFileValid = false;
                validationErrors.push(
                  `Signature #${i + 1}: Error parsing certificate: ${error instanceof Error ? error.message : String(error)}`,
                );
              }
            } else {
              isFileValid = false;
              validationErrors.push(`Signature #${i + 1}: No certificate found`);
            }

            // Verify checksums
            try {
              const checksumResults = await verifyChecksums(signature, container.files);
              if (!checksumResults.isValid) {
                isFileValid = false;
                const failedChecksums = Object.entries(checksumResults.details)
                  .filter(([_, result]) => !result.matches)
                  .map(([filename]) => filename);
                validationErrors.push(
                  `Signature #${i + 1}: Invalid checksums for: ${failedChecksums.join(", ")}`,
                );
              }
            } catch (error) {
              isFileValid = false;
              validationErrors.push(
                `Signature #${i + 1}: Error verifying checksums: ${error instanceof Error ? error.message : String(error)}`,
              );
            }

            // Verify full signature
            try {
              const verificationResult = await verifySignature(signature, container.files, {
                verifyTime: signature.signingTime,
              });

              if (!verificationResult.isValid) {
                isFileValid = false;
                validationErrors.push(`Signature #${i + 1}: Signature verification failed`);

                if (!verificationResult.certificate.isValid) {
                  validationErrors.push(`Signature #${i + 1}: Certificate is invalid`);
                }

                if (verificationResult.signature && !verificationResult.signature.isValid) {
                  validationErrors.push(
                    `Signature #${i + 1}: ${verificationResult.signature.reason || "Invalid XML signature"}`,
                  );
                }

                if (verificationResult.errors && verificationResult.errors.length > 0) {
                  verificationResult.errors.forEach((error) => {
                    validationErrors.push(`Signature #${i + 1}: ${error}`);
                  });
                }
              }
            } catch (error) {
              isFileValid = false;
              validationErrors.push(
                `Signature #${i + 1}: Error during signature verification: ${error instanceof Error ? error.message : String(error)}`,
              );
            }
          }

          // Log results concisely
          const signersList = signerNames.length > 0 ? signerNames.join(", ") : "Unknown signer(s)";
          const signingTime = container.signatures[0]?.signingTime
            ? new Date(container.signatures[0].signingTime).toISOString()
            : "Unknown time";
          console.log(
            `${filename}: ${isFileValid ? "✓ Valid" : "✗ Invalid"} - Signed at: ${signingTime} - By: ${signersList}`,
          );

          // Only log detailed errors if validation failed
          if (!isFileValid) {
            console.log(`  Validation errors in ${filename}:`);
            validationErrors.forEach((error) => console.log(`  - ${error}`));
          }

          // Final assertion
          expect(isFileValid).toBe(true);
        } catch (error) {
          console.error(
            `Error processing ${filename}: ${error instanceof Error ? error.message : String(error)}`,
          );
          throw error; // Re-throw to fail the test
        }
      });
    });
  }
});
