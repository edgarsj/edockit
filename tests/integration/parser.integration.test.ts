import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../src/core/parser";
import {
  parseCertificate,
  getSignerDisplayName,
  formatValidityPeriod,
} from "../../src/core/certificate";
import { verifyChecksums, verifySignature } from "../../src/core/verification";

const realSampleEdocFilePath = join(__dirname, "../fixtures/sensitive/Sample File.edoc");
const realSampleEdocfileExists = existsSync(realSampleEdocFilePath);

describe("eDoc Parser and Verification Tests", () => {
  (realSampleEdocfileExists ? it : it.skip)(
    "should parse and verify a real eDoc file",
    async () => {
      // Read the test file
      console.log("Reading file from:", realSampleEdocFilePath);
      const edocBuffer = readFileSync(realSampleEdocFilePath);
      console.log("File size:", edocBuffer.length, "bytes");

      // Parse the eDoc container
      const container = parseEdoc(edocBuffer);

      // Verify the files are present
      const fileNames = Array.from(container.files.keys());
      const hasPdf = fileNames.some((name) => name.endsWith(".pdf"));
      const hasDocx = fileNames.some((name) => name.endsWith(".docx"));

      expect(hasPdf).toBe(true);
      expect(hasDocx).toBe(true);
      console.log("Files in container:", fileNames);

      // Verify signatures were found
      expect(container.signatures.length).toBeGreaterThan(0);
      console.log(`Found ${container.signatures.length} signatures`);

      // Test the first signature
      const signature = container.signatures[0];
      console.log("Signature ID:", signature.id);
      console.log("Signing time:", signature.signingTime);

      // Verify we have the necessary signature data for XML verification
      console.log("\nSignature verification data:");
      console.log("- Has SignedInfo XML:", !!signature.signedInfoXml);
      console.log("- Has SignatureValue:", !!signature.signatureValue);
      console.log("- Has Public Key:", !!signature.publicKey);
      console.log("- Canonicalization Method:", signature.canonicalizationMethod || "default");

      // Parse and verify the certificate
      if (signature.certificatePEM) {
        const certInfo = await parseCertificate(signature.certificatePEM);

        console.log("\nSigner Information:");
        const signerName = getSignerDisplayName(certInfo);
        console.log("- Signer:", signerName);
        console.log("- Country:", certInfo.subject.country);
        if (certInfo.subject.serialNumber) {
          console.log("- Serial Number:", certInfo.subject.serialNumber);
        }
        console.log("- Validity Period:", formatValidityPeriod(certInfo));

        console.log("\nIssuer Information:");
        console.log("- Issuer:", certInfo.issuer.commonName);
        console.log("- Issuer Organization:", certInfo.issuer.organization);

        // Verify certificate and signature information exists
        expect(
          certInfo.subject.commonName || (certInfo.subject.givenName && certInfo.subject.surname),
        ).toBeTruthy();
        expect(certInfo.subject.country).toBeTruthy();
        expect(certInfo.issuer.commonName).toBeTruthy();
      }

      // Verify checksums
      const checksumResults = await verifyChecksums(signature, container.files);
      console.log("\nChecksum verification:");
      console.log("- All checksums valid:", checksumResults.isValid);

      for (const [filename, result] of Object.entries(checksumResults.details)) {
        console.log(
          `- ${filename}: ${result.matches ? "✓" : "✗"} ${result.fileFound ? "" : "(file not found)"}`,
        );
      }

      // Checksums should be valid
      expect(checksumResults.isValid).toBe(true);

      // Perform a complete signature verification (disable revocation for faster tests)
      console.log("\nPerforming complete signature verification...");
      const verificationResult = await verifySignature(signature, container.files, {
        verifyTime: signature.signingTime,
        checkRevocation: false,
      });

      console.log("\nVerification result:");
      console.log("- Overall validity:", verificationResult.isValid);
      console.log("- Certificate valid:", verificationResult.certificate.isValid);

      if (verificationResult.signature) {
        console.log("- XML Signature valid:", verificationResult.signature.isValid);
        if (!verificationResult.signature.isValid && verificationResult.signature.reason) {
          console.log("  Reason:", verificationResult.signature.reason);
        }
      }

      if (verificationResult.errors && verificationResult.errors.length > 0) {
        console.log("Verification errors:");
        for (const error of verificationResult.errors) {
          console.log(`- ${error}`);
        }
      }

      // The verification should pass
      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.certificate.isValid).toBe(true);
      if (verificationResult.signature) {
        expect(verificationResult.signature.isValid).toBe(true);
      }

      // Verify that signature references include both document types
      const references = signature.references;
      console.log("\nFiles referenced in signature:", references);

      const hasPdfRef = references.some((ref) => ref.endsWith(".pdf"));
      const hasDocxRef = references.some((ref) => ref.endsWith(".docx"));

      expect(hasPdfRef).toBe(true);
      expect(hasDocxRef).toBe(true);
    },
  );
});
