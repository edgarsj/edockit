import { readFileSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../src/core/parser";
import {
  parseCertificate,
  getSignerDisplayName,
  formatValidityPeriod,
} from "../../src/core/certificate";
import { verifyChecksums, verifySignature, ValidationStatus } from "../../src/core/verification";

// Path to directories containing eDoc samples
const sensitiveSamplesDir = join(__dirname, "../fixtures/sensitive/valid_samples");
const validSamplesDir = join(__dirname, "../fixtures/valid_samples");
const sensitiveSamplesDirExists = existsSync(sensitiveSamplesDir);
const validSamplesDirExists = existsSync(validSamplesDir);

// File entry in filelist.json
interface FileEntry {
  name: string;
  expectedStatus: ValidationStatus;
  expectedLimitation?: string;
  note?: string;
}

// Load filelist.json if it exists
const loadFilelist = (directory: string): FileEntry[] | null => {
  const filelistPath = join(directory, "filelist.json");
  if (!existsSync(filelistPath)) return null;

  try {
    const content = readFileSync(filelistPath, "utf-8");
    const parsed = JSON.parse(content);
    // Support both old format (string[]) and new format ({ files: FileEntry[] })
    if (Array.isArray(parsed)) {
      return parsed.map((name: string) => ({ name, expectedStatus: "VALID" as ValidationStatus }));
    }
    return parsed.files || null;
  } catch {
    return null;
  }
};

// Function to collect files with specific extensions
const collectFiles = (directory: string, extensions: string[]): string[] => {
  if (!existsSync(directory)) return [];

  try {
    return readdirSync(directory)
      .filter((filename) => {
        const lowerFilename = filename.toLowerCase();
        return extensions.some((ext) => lowerFilename.endsWith(ext));
      })
      .map((filename) => join(directory, filename));
  } catch (error) {
    console.error(
      `Error reading directory ${directory}:`,
      error instanceof Error ? error.message : String(error),
    );
    return [];
  }
};

// Function to verify eDoc/ASiC-E files
const verifyEdocFiles = async (
  filePath: string,
): Promise<{
  isValid: boolean;
  status: ValidationStatus;
  limitations?: { code: string }[];
  signerNames: string[];
  signingTime: string;
  validationErrors: string[];
}> => {
  // Read and parse the eDoc file
  const edocBuffer = readFileSync(filePath);
  const container = parseEdoc(edocBuffer);

  // Track validation status
  let isFileValid = container.signatures.length > 0;
  let overallStatus: ValidationStatus = "VALID";
  let allLimitations: { code: string }[] = [];
  let signerNames: string[] = [];
  let validationErrors: string[] = [];

  // No signatures is an error condition
  if (container.signatures.length === 0) {
    validationErrors.push("No signatures found in container");
    return {
      isValid: false,
      status: "INVALID",
      signerNames,
      signingTime: "Unknown time",
      validationErrors,
    };
  }

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

    // Verify full signature (disable revocation checking for faster tests)
    try {
      const verificationResult = await verifySignature(signature, container.files, {
        verifyTime: signature.signingTime,
        checkRevocation: false,
      });

      // Track status from verification result
      if (verificationResult.status !== "VALID") {
        // Update overall status (worst case wins: INVALID > INDETERMINATE > UNSUPPORTED > VALID)
        if (
          verificationResult.status === "INVALID" ||
          (verificationResult.status === "INDETERMINATE" && overallStatus !== "INVALID") ||
          (verificationResult.status === "UNSUPPORTED" &&
            overallStatus !== "INVALID" &&
            overallStatus !== "INDETERMINATE")
        ) {
          overallStatus = verificationResult.status;
        }
      }

      // Collect limitations
      if (verificationResult.limitations) {
        allLimitations.push(...verificationResult.limitations);
      }

      if (!verificationResult.isValid) {
        isFileValid = false;
        validationErrors.push(
          `Signature #${i + 1}: Signature verification failed (${verificationResult.status})`,
        );

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
      overallStatus = "INVALID";
      validationErrors.push(
        `Signature #${i + 1}: Error during signature verification: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const signingTime = container.signatures[0]?.signingTime
    ? new Date(container.signatures[0].signingTime).toISOString()
    : "Unknown time";

  return {
    isValid: isFileValid,
    status: overallStatus,
    limitations: allLimitations.length > 0 ? allLimitations : undefined,
    signerNames,
    signingTime,
    validationErrors,
  };
};

// First test suite for sensitive samples
const describeSensitive = sensitiveSamplesDirExists ? describe : describe.skip;

describeSensitive("Sensitive Samples Batch Verification", () => {
  const sensitiveFiles = collectFiles(sensitiveSamplesDir, [".edoc", ".asice"]);
  const filelist = loadFilelist(sensitiveSamplesDir);

  it("should find the sensitive samples directory", () => {
    expect(sensitiveSamplesDirExists).toBe(true);
  });

  // Skip testing files if none were found
  if (sensitiveFiles.length === 0) {
    it("No .edoc or .asice files found in sensitive directory", () => {
      console.log(
        "No .edoc or .asice files found in sensitive samples directory. Add some to run verification tests.",
      );
      return;
    });
  } else {
    console.log(`Found ${sensitiveFiles.length} eDoc/ASiC-E files in ${sensitiveSamplesDir}`);

    // Tests for each found file
    sensitiveFiles.forEach((filePath) => {
      const filename = filePath.split("/").pop() || "";

      // Find expected status from filelist (default to VALID if not specified)
      const fileEntry = filelist?.find((f) => f.name === filename);
      const expectedStatus = fileEntry?.expectedStatus || "VALID";
      const expectedLimitation = fileEntry?.expectedLimitation;

      it(`should validate sensitive file: ${filename} (expected: ${expectedStatus})`, async () => {
        try {
          const result = await verifyEdocFiles(filePath);

          // Log results concisely
          const signersList =
            result.signerNames.length > 0 ? result.signerNames.join(", ") : "Unknown signer(s)";
          const statusIcon =
            result.status === "VALID" ? "✓" : result.status === "INDETERMINATE" ? "?" : "✗";
          console.log(
            `${filename}: ${statusIcon} ${result.status} - Signed at: ${result.signingTime} - By: ${signersList}`,
          );

          // Log limitations if present
          if (result.limitations && result.limitations.length > 0) {
            console.log(`  Limitations: ${result.limitations.map((l) => l.code).join(", ")}`);
          }

          // Only log detailed errors if unexpected status
          if (result.status !== expectedStatus) {
            console.log(`  Validation errors in ${filename}:`);
            result.validationErrors.forEach((error) => console.log(`  - ${error}`));
          }

          // Assert expected status
          expect(result.status).toBe(expectedStatus);

          // Assert expected limitation if specified
          if (expectedLimitation) {
            expect(result.limitations?.some((l) => l.code === expectedLimitation)).toBe(true);
          }
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

// Second test suite for public samples
const describePublic = validSamplesDirExists ? describe : describe.skip;

describePublic("Public Samples Batch Verification", () => {
  const publicFiles = collectFiles(validSamplesDir, [".edoc", ".asice"]);

  it("should find the public samples directory", () => {
    expect(validSamplesDirExists).toBe(true);
  });

  // Skip testing files if none were found
  if (publicFiles.length === 0) {
    it("No .edoc or .asice files found in public directory", () => {
      console.log(
        "No .edoc or .asice files found in public samples directory. Add some to run verification tests.",
      );
      return;
    });
  } else {
    console.log(`Found ${publicFiles.length} eDoc/ASiC-E files in ${validSamplesDir}`);

    // Tests for each found file
    publicFiles.forEach((filePath) => {
      const filename = filePath.split("/").pop() || "";

      it(`should validate public file: ${filename}`, async () => {
        try {
          const result = await verifyEdocFiles(filePath);

          // Log results concisely
          const signersList =
            result.signerNames.length > 0 ? result.signerNames.join(", ") : "Unknown signer(s)";
          console.log(
            `${filename}: ${result.isValid ? "✓ Valid" : "✗ Invalid"} - Signed at: ${result.signingTime} - By: ${signersList}`,
          );

          // Only log detailed errors if validation failed
          if (!result.isValid) {
            console.log(`  Validation errors in ${filename}:`);
            result.validationErrors.forEach((error) => console.log(`  - ${error}`));
          }

          // Final assertion
          expect(result.isValid).toBe(true);
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
