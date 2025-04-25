// tests-browser/validatesamples.spec.ts
import { expect } from "@esm-bundle/chai";
import { parseEdoc } from "../src/core/parser";
import { parseCertificate, getSignerDisplayName } from "../src/core/certificate";
import { verifyChecksums, verifySignature } from "../src/core/verification";

describe("eDoc/ASiC-E Files Validation", () => {
  const fileExtensions = [".edoc", ".asice"];

  // Helper to fetch sample files
  const fetchSample = async (relativePath: string): Promise<ArrayBuffer | null> => {
    try {
      const response = await fetch(relativePath);
      if (!response.ok) {
        console.error(`Failed to fetch ${relativePath}: ${response.status} ${response.statusText}`);
        return null;
      }
      return await response.arrayBuffer();
    } catch (error) {
      console.error(`Error fetching ${relativePath}:`, error);
      return null;
    }
  };

  // Helper to get file list from a directory
  const getFileList = async (baseDir: string): Promise<string[]> => {
    try {
      const response = await fetch(`${baseDir}/filelist.json`);
      if (!response.ok) {
        console.error(`Failed to fetch file list from ${baseDir}: ${response.status}`);
        return [];
      }

      const files = await response.json();
      return files
        .filter((filename: string) =>
          fileExtensions.some((ext) => filename.toLowerCase().endsWith(ext)),
        )
        .map((filename: string) => `${baseDir}/${filename}`);
    } catch (error) {
      console.error(`Error reading file list from ${baseDir}:`, error);
      return [];
    }
  };

  // Helper to verify an eDoc/ASiC-E file
  const verifyEdocFile = async (
    fileBuffer: ArrayBuffer,
  ): Promise<{
    isValid: boolean;
    signerNames: string[];
    signingTime: string;
    validationErrors: string[];
  }> => {
    // Parse the eDoc container
    const container = parseEdoc(new Uint8Array(fileBuffer));

    // Track validation status
    let isValid = container.signatures.length > 0;
    const signerNames: string[] = [];
    const validationErrors: string[] = [];

    // No signatures is an error condition
    if (container.signatures.length === 0) {
      validationErrors.push("No signatures found in container");
      return {
        isValid: false,
        signerNames,
        signingTime: "Unknown time",
        validationErrors,
      };
    }

    // Test each signature in the file
    for (let i = 0; i < container.signatures.length; i++) {
      const signature = container.signatures[i];

      // Get signer info if available
      if (signature.certificatePEM) {
        try {
          const certInfo = await parseCertificate(signature.certificatePEM);
          const signerName = getSignerDisplayName(certInfo);
          signerNames.push(signerName);

          // Verify certificate info
          if (
            !certInfo.subject.commonName &&
            !(certInfo.subject.givenName && certInfo.subject.surname)
          ) {
            isValid = false;
            validationErrors.push(`Signature #${i + 1}: Missing signer information`);
          }
        } catch (error) {
          isValid = false;
          validationErrors.push(
            `Signature #${i + 1}: Error parsing certificate: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      } else {
        isValid = false;
        validationErrors.push(`Signature #${i + 1}: No certificate found`);
      }

      // Verify checksums
      try {
        const checksumResults = await verifyChecksums(signature, container.files);
        if (!checksumResults.isValid) {
          isValid = false;
          const failedChecksums = Object.entries(checksumResults.details)
            .filter(([_, result]) => !result.matches)
            .map(([filename]) => filename);
          validationErrors.push(
            `Signature #${i + 1}: Invalid checksums for: ${failedChecksums.join(", ")}`,
          );
        }
      } catch (error) {
        isValid = false;
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
          isValid = false;
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
        isValid = false;
        validationErrors.push(
          `Signature #${i + 1}: Error during signature verification: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    const signingTime = container.signatures[0]?.signingTime
      ? new Date(container.signatures[0].signingTime).toISOString()
      : "Unknown time";

    return {
      isValid,
      signerNames,
      signingTime,
      validationErrors,
    };
  };

  // Test suite for sensitive samples
  describe("Sensitive Sample Files Validation", function () {
    const sampleDir = "/tests/fixtures/sensitive/valid_samples";
    let files: string[] = [];

    before(async function () {
      files = await getFileList(sampleDir);
      if (files.length === 0) {
        console.log(`No sample files found in ${sampleDir} - tests will be skipped`);
        this.skip();
      } else {
        console.log(`Found ${files.length} files to validate in ${sampleDir}`);
      }
    });

    it(`should access files in ${sampleDir}`, function () {
      expect(files.length).to.be.greaterThan(0);
    });

    it(`should validate all sensitive sample files`, async function () {
      // Skip if no files
      if (files.length === 0) {
        this.skip();
        return;
      }

      // Test each file one by one
      for (const path of files) {
        const filename = path.split("/").pop() || "";

        // Fetch and validate the file
        const fileBuffer = await fetchSample(path);
        if (!fileBuffer) {
          console.log(`Could not fetch file: ${path} - skipping`);
          continue;
        }

        const result = await verifyEdocFile(fileBuffer);

        // Log results concisely
        const signersList =
          result.signerNames.length > 0 ? result.signerNames.join(", ") : "Unknown signer(s)";
        console.warn(
          `📋 VALIDATION RESULT - ${filename}: ${result.isValid ? "✅ Valid" : "❌ Invalid"} - Signed at: ${result.signingTime} - By: ${signersList}`,
        );

        // Only log detailed errors if validation failed
        if (!result.isValid) {
          console.error(`  ⚠️ Validation errors in ${filename}:`);
          result.validationErrors.forEach((error) => console.error(`    - ${error}`));
        }

        // Assertion for each file
        expect(result.isValid, `File ${filename} should be valid`).to.be.true;
      }
    });
  });

  // Test suite for public samples
  describe("Public Sample Files Validation", function () {
    const sampleDir = "/tests/fixtures/valid_samples";
    let files: string[] = [];

    before(async function () {
      files = await getFileList(sampleDir);
      if (files.length === 0) {
        console.log(`No sample files found in ${sampleDir} - tests will be skipped`);
        this.skip();
      } else {
        console.log(`Found ${files.length} files to validate in ${sampleDir}`);
      }
    });

    it(`should access files in ${sampleDir}`, function () {
      expect(files.length).to.be.greaterThan(0);
    });

    it(`should validate all public sample files`, async function () {
      // Skip if no files
      if (files.length === 0) {
        this.skip();
        return;
      }

      // Test each file one by one
      for (const path of files) {
        const filename = path.split("/").pop() || "";

        // Fetch and validate the file
        const fileBuffer = await fetchSample(path);
        if (!fileBuffer) {
          console.log(`Could not fetch file: ${path} - skipping`);
          continue;
        }

        const result = await verifyEdocFile(fileBuffer);

        // Log results concisely
        const signersList =
          result.signerNames.length > 0 ? result.signerNames.join(", ") : "Unknown signer(s)";
        console.warn(
          `📋 VALIDATION RESULT - ${filename}: ${result.isValid ? "✅ Valid" : "❌ Invalid"} - Signed at: ${result.signingTime} - By: ${signersList}`,
        );

        // Only log detailed errors if validation failed
        if (!result.isValid) {
          console.error(`  ⚠️ Validation errors in ${filename}:`);
          result.validationErrors.forEach((error) => console.error(`    - ${error}`));
        }

        // Assertion for each file
        expect(result.isValid, `File ${filename} should be valid`).to.be.true;
      }
    });
  });
});
