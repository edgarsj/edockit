// cypress/e2e/edoc-verification.cy.js
import { parseEdoc } from "../../src/core/parser";
import {
  parseCertificate,
  getSignerDisplayName,
  formatValidityPeriod,
} from "../../src/core/certificate";
import { verifyChecksums, verifySignature } from "../../src/core/verification";

describe("eDoc Parser and Verification Tests", () => {
  it("should parse and verify a real eDoc file", () => {
    cy.task("fileExists", "sensitive/Sample File.edoc").then((exists) => {
      if (!exists) {
        cy.log("Sensitive file not found - skipping test");
        return;
      }

      cy.task("readBinaryFile", "sensitive/Sample File.edoc").then(async (base64Content) => {
        // Convert base64 back to binary
        const edocBuffer = Cypress.Buffer.from(base64Content, "base64");

        // Log file details
        cy.log(`File size: ${edocBuffer.length} bytes`);

        // Parse the eDoc container
        const container = parseEdoc(edocBuffer);

        // Verify the files are present
        const fileNames = Array.from(container.files.keys());
        const hasPdf = fileNames.some((name) => name.endsWith(".pdf"));
        const hasDocx = fileNames.some((name) => name.endsWith(".docx"));

        expect(hasPdf).to.be.true;
        expect(hasDocx).to.be.true;
        cy.log(`Files in container: ${fileNames.join(", ")}`);

        // Verify signatures were found
        expect(container.signatures.length).to.be.greaterThan(0);
        cy.log(`Found ${container.signatures.length} signatures`);

        // Test the first signature
        const signature = container.signatures[0];
        cy.log(`Signature ID: ${signature.id}`);
        cy.log(`Signing time: ${signature.signingTime}`);

        // Verify we have the necessary signature data for XML verification
        cy.log("Signature verification data:");
        cy.log(`- Has SignedInfo XML: ${!!signature.signedInfoXml}`);
        cy.log(`- Has SignatureValue: ${!!signature.signatureValue}`);
        cy.log(`- Has Public Key: ${!!signature.publicKey}`);
        cy.log(`- Canonicalization Method: ${signature.canonicalizationMethod || "default"}`);

        // Parse and verify the certificate
        if (signature.certificatePEM) {
          const certInfo = await parseCertificate(signature.certificatePEM);

          cy.log("Signer Information:");
          const signerName = getSignerDisplayName(certInfo);
          cy.log(`- Signer: ${signerName}`);
          cy.log(`- Country: ${certInfo.subject.country}`);
          if (certInfo.subject.serialNumber) {
            cy.log(`- Serial Number: ${certInfo.subject.serialNumber}`);
          }
          cy.log(`- Validity Period: ${formatValidityPeriod(certInfo)}`);

          cy.log("Issuer Information:");
          cy.log(`- Issuer: ${certInfo.issuer.commonName}`);
          cy.log(`- Issuer Organization: ${certInfo.issuer.organization}`);

          // Verify certificate and signature information exists
          expect(
            certInfo.subject.commonName || (certInfo.subject.givenName && certInfo.subject.surname),
          ).to.be.ok;
          expect(certInfo.subject.country).to.be.ok;
          expect(certInfo.issuer.commonName).to.be.ok;
        }

        // Verify checksums
        const checksumResults = verifyChecksums(signature, container.files);
        cy.log("Checksum verification:");
        cy.log(`- All checksums valid: ${checksumResults.isValid}`);

        for (const [filename, result] of Object.entries(checksumResults.details)) {
          cy.log(
            `- ${filename}: ${result.matches ? "✓" : "✗"} ${result.fileFound ? "" : "(file not found)"}`,
          );
        }

        // Checksums should be valid
        expect(checksumResults.isValid).to.be.true;

        // Perform a complete signature verification
        cy.log("Performing complete signature verification...");
        const verificationResult = await verifySignature(signature, container.files, {
          verifyTime: signature.signingTime,
        });

        cy.log("Verification result:");
        cy.log(`- Overall validity: ${verificationResult.isValid}`);
        cy.log(`- Certificate valid: ${verificationResult.certificate.isValid}`);

        if (verificationResult.signature) {
          cy.log(`- XML Signature valid: ${verificationResult.signature.isValid}`);
          if (!verificationResult.signature.isValid && verificationResult.signature.reason) {
            cy.log(`  Reason: ${verificationResult.signature.reason}`);
          }
        }

        if (verificationResult.errors && verificationResult.errors.length > 0) {
          cy.log("Verification errors:");
          for (const error of verificationResult.errors) {
            cy.log(`- ${error}`);
          }
        }

        // The verification should pass
        expect(verificationResult.isValid).to.be.true;
        expect(verificationResult.certificate.isValid).to.be.true;
        if (verificationResult.signature) {
          expect(verificationResult.signature.isValid).to.be.true;
        }

        // Verify that signature references include both document types
        const references = signature.references;
        cy.log(`Files referenced in signature: ${references}`);

        const hasPdfRef = references.some((ref) => ref.endsWith(".pdf"));
        const hasDocxRef = references.some((ref) => ref.endsWith(".docx"));

        expect(hasPdfRef).to.be.true;
        expect(hasDocxRef).to.be.true;
      });
    });
  });
});
