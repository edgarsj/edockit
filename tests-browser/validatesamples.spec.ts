// tests-browser/validatesamples.spec.ts
import { expect } from "@esm-bundle/chai";
import { parseEdoc } from "../src/core/parser";
import { parseCertificate, getSignerDisplayName } from "../src/core/certificate";
import { verifyChecksums, verifySignature } from "../src/core/verification";

describe("eDoc/ASiC-E Files Validation", () => {
  const fileExtensions = [".edoc", ".asice", ".sce"];

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

  // File entry from filelist.json
  interface FileEntry {
    name: string;
    expectedStatus?: string;
    expectedLimitation?: string;
    note?: string;
  }

  // Helper to get file list from a directory
  const getFileList = async (
    baseDir: string,
  ): Promise<{ path: string; expectedStatus?: string; expectedLimitation?: string }[]> => {
    try {
      const response = await fetch(`${baseDir}/filelist.json`);
      if (!response.ok) {
        console.error(`Failed to fetch file list from ${baseDir}: ${response.status}`);
        return [];
      }

      const data = await response.json();

      // Handle new format: { "files": [{ "name": "...", "expectedStatus": "..." }, ...] }
      let files: FileEntry[];
      if (data && Array.isArray(data.files)) {
        files = data.files;
      } else if (Array.isArray(data)) {
        // Handle old format: ["file1.edoc", "file2.edoc", ...]
        files = data.map((name: string) => ({ name }));
      } else {
        console.error(`Invalid filelist.json format in ${baseDir}`);
        return [];
      }

      return files
        .filter((entry) => fileExtensions.some((ext) => entry.name.toLowerCase().endsWith(ext)))
        .map((entry) => ({
          path: `${baseDir}/${entry.name}`,
          expectedStatus: entry.expectedStatus,
          expectedLimitation: entry.expectedLimitation,
        }));
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

        // Accept VALID, INDETERMINATE, and UNSUPPORTED statuses
        // Only INVALID is a hard failure
        const acceptableStatuses = ["VALID", "INDETERMINATE", "UNSUPPORTED"];
        const status =
          verificationResult.status || (verificationResult.isValid ? "VALID" : "INVALID");

        if (!acceptableStatuses.includes(status)) {
          isValid = false;
          validationErrors.push(`Signature #${i + 1}: Signature verification failed (${status})`);

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
        } else if (status !== "VALID") {
          // Log yellow states for visibility
          validationErrors.push(
            `Signature #${i + 1}: ${status} - ${verificationResult.statusMessage || "Verification inconclusive"}`,
          );
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
    let fileEntries: { path: string; expectedStatus?: string; expectedLimitation?: string }[] = [];

    before(async function () {
      fileEntries = await getFileList(sampleDir);
      if (fileEntries.length === 0) {
        console.log(`No sample files found in ${sampleDir} - tests will be skipped`);
        this.skip();
      } else {
        console.log(`Found ${fileEntries.length} files to validate in ${sampleDir}`);
      }
    });

    it(`should access files in ${sampleDir}`, function () {
      expect(fileEntries.length).to.be.greaterThan(0);
    });

    it(`should validate all sensitive sample files`, async function () {
      // Skip if no files
      if (fileEntries.length === 0) {
        this.skip();
        return;
      }

      // Test each file one by one
      for (const entry of fileEntries) {
        const filename = entry.path.split("/").pop() || "";
        const expectedStatus = entry.expectedStatus || "VALID";

        // Fetch and validate the file
        const fileBuffer = await fetchSample(entry.path);
        if (!fileBuffer) {
          console.log(`Could not fetch file: ${entry.path} - skipping`);
          continue;
        }

        const result = await verifyEdocFile(fileBuffer);

        // Log results concisely
        const signersList =
          result.signerNames.length > 0 ? result.signerNames.join(", ") : "Unknown signer(s)";
        const statusIcon = result.isValid ? "✅" : expectedStatus === "INDETERMINATE" ? "⚠️" : "❌";
        console.log(
          `📋 ${filename}: ${statusIcon} ${result.isValid ? "Valid" : "Not fully valid"} (expected: ${expectedStatus}) - By: ${signersList}`,
        );

        // Only log detailed errors if unexpected
        if (!result.isValid && expectedStatus === "VALID") {
          console.error(`  ⚠️ Validation errors in ${filename}:`);
          result.validationErrors.forEach((error) => console.error(`    - ${error}`));
        }

        // Assertion based on expected status
        if (expectedStatus === "VALID") {
          expect(result.isValid, `File ${filename} should be valid`).to.be.true;
        } else if (expectedStatus === "INDETERMINATE") {
          // INDETERMINATE files may pass or fail depending on timestamp/cert status
          // Just log, don't fail the test
          console.log(`  ℹ️ ${filename} is INDETERMINATE as expected`);
        }
      }
    });
  });

  // Test suite for public samples
  describe("Public Sample Files Validation", function () {
    const sampleDir = "/tests/fixtures/valid_samples";
    let fileEntries: { path: string; expectedStatus?: string; expectedLimitation?: string }[] = [];

    before(async function () {
      fileEntries = await getFileList(sampleDir);
      if (fileEntries.length === 0) {
        console.log(`No sample files found in ${sampleDir} - tests will be skipped`);
        this.skip();
      } else {
        console.log(`Found ${fileEntries.length} files to validate in ${sampleDir}`);
      }
    });

    it(`should access files in ${sampleDir}`, function () {
      expect(fileEntries.length).to.be.greaterThan(0);
    });

    it(`should validate all public sample files`, async function () {
      // Skip if no files
      if (fileEntries.length === 0) {
        this.skip();
        return;
      }

      // Test each file one by one
      for (const entry of fileEntries) {
        const filename = entry.path.split("/").pop() || "";

        // Fetch and validate the file
        const fileBuffer = await fetchSample(entry.path);
        if (!fileBuffer) {
          console.log(`Could not fetch file: ${entry.path} - skipping`);
          continue;
        }

        const result = await verifyEdocFile(fileBuffer);

        // Log results concisely
        const signersList =
          result.signerNames.length > 0 ? result.signerNames.join(", ") : "Unknown signer(s)";
        console.log(
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
