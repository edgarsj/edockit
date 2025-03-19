import { readFileSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../src/core/parser";
import {
  extractSignerInfo,
  checkCertificateValidity,
} from "../../src/core/certificate";
import { verifyChecksums } from "../../src/core/verification";
import { X509Certificate } from "@peculiar/x509";

describe("eDoc Parser Integration Tests", () => {
  it("should correctly parse a real eDoc file", () => {
    // Read the test file
    const edocPath = join(__dirname, "../fixtures/Sample File.edoc");
    console.log("Reading file from:", edocPath);
    const edocBuffer = readFileSync(edocPath);
    console.log("File size:", edocBuffer.length, "bytes");
    // Parse the eDoc container
    const container = parseEdoc(edocBuffer);

    // Verify the files are present
    const fileNames = Array.from(container.files.keys());
    expect(container.files.has("Sample File.pdf")).toBe(true);
    expect(container.files.has("Sample File.docx")).toBe(true);

    // Verify signatures were found
    expect(container.signatures.length).toBeGreaterThan(0);

    // Check the first signature has basic properties
    const signature = container.signatures[0];
    expect(signature).toHaveProperty("id");
    expect(signature).toHaveProperty("signingTime");
    expect(signature).toHaveProperty("certificate");
    expect(signature).toHaveProperty("signedChecksums");

    // Log some information for manual inspection
    console.log("Files in container:", Array.from(container.files.keys()));
    console.log("Signature ID:", signature.id);
    console.log("Signing time:", signature.signingTime);
    // Extract and verify signer information
    if (signature.certificatePEM) {
      const cert = new X509Certificate(signature.certificatePEM);
      const signerInfo = extractSignerInfo(cert);

      console.log("\nSigner Information:");
      console.log("- Common Name:", signerInfo.commonName);
      console.log("- Organization:", signerInfo.organization);
      console.log("- Country:", signerInfo.country);
      console.log("- Serial Number:", signerInfo.serialNumber);
      console.log("- Valid From:", signerInfo.validFrom.toISOString());
      console.log("- Valid To:", signerInfo.validTo.toISOString());
      console.log("\nIssuer Information:");
      console.log("- Issuer Common Name:", signerInfo.issuer.commonName);
      console.log("- Issuer Organization:", signerInfo.issuer.organization);

      // Verify signer information is not empty
      expect(signerInfo.commonName).toBeTruthy();
      expect(signerInfo.country).toBeTruthy();

      // Check certificate validity (using the signing time, not current time)
      const validityCheck = checkCertificateValidity(
        cert,
        signature.signingTime,
      );
      console.log(
        "\nCertificate validity at signing time:",
        validityCheck.isValid,
      );
      if (!validityCheck.isValid) {
        console.log("Reason:", validityCheck.reason);
      }

      // The certificate should be valid at signing time
      expect(validityCheck.isValid).toBe(true);
    }
    // Verify file checksums
    const checksumResults = verifyChecksums(signature, container.files);
    console.log("\nChecksum verification results:");
    console.log("- All checksums valid:", checksumResults.isValid);

    for (const [filename, result] of Object.entries(checksumResults.details)) {
      console.log(`- ${filename}:`);
      console.log(`  File found: ${result.fileFound}`);
      console.log(`  Checksum matches: ${result.matches}`);
      if (!result.matches && result.fileFound) {
        console.log(`  Expected: ${result.expected}`);
        console.log(`  Actual: ${result.actual}`);
      }
    }

    // Checksums should be valid
    expect(checksumResults.isValid).toBe(true);

    // Verify that signature references include both files
    const references = signature.references;
    console.log("\nFiles referenced in signature:", references);

    const hasPdfRef = references.some((ref) => ref.endsWith(".pdf"));
    const hasDocxRef = references.some((ref) => ref.endsWith(".docx"));

    expect(hasPdfRef).toBe(true);
    expect(hasDocxRef).toBe(true);
  });
});
