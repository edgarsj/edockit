import { readFileSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../src/core/parser";
import { verifySignature } from "../../src/core/verification";
import {
  checkCertificateRevocation,
  extractOCSPUrls,
  extractCRLUrls,
} from "../../src/core/revocation";
import { X509Certificate } from "@peculiar/x509";

const sampleFilePath = join(__dirname, "../fixtures/valid_samples/SampleFile.edoc");

describe("Certificate Revocation Checking", () => {
  let container: ReturnType<typeof parseEdoc>;
  let certificate: X509Certificate;

  beforeAll(() => {
    const edocBuffer = readFileSync(sampleFilePath);
    container = parseEdoc(edocBuffer);
    expect(container.signatures.length).toBeGreaterThan(0);

    const sig = container.signatures[0];
    certificate = new X509Certificate(sig.certificatePEM);
  });

  describe("Certificate chain extraction", () => {
    it("should parse the sample file successfully", () => {
      expect(container).toBeDefined();
      expect(container.signatures.length).toBeGreaterThan(0);
    });

    it("should extract certificate from signature", () => {
      const sig = container.signatures[0];
      expect(sig.certificatePEM).toBeDefined();
      expect(sig.certificatePEM).toContain("-----BEGIN CERTIFICATE-----");
    });

    it("should extract certificate chain if available", () => {
      const sig = container.signatures[0];
      // Certificate chain may or may not be present depending on the file
      if (sig.certificateChain) {
        expect(Array.isArray(sig.certificateChain)).toBe(true);
        sig.certificateChain.forEach((cert) => {
          expect(cert).toContain("-----BEGIN CERTIFICATE-----");
        });
      }
    });
  });

  describe("OCSP/CRL URL extraction", () => {
    it("should extract OCSP URLs from certificate", () => {
      const ocspUrls = extractOCSPUrls(certificate);
      // Most certificates have OCSP URLs
      expect(Array.isArray(ocspUrls)).toBe(true);
      console.log("OCSP URLs found:", ocspUrls);
    });

    it("should extract CRL URLs from certificate", () => {
      const crlUrls = extractCRLUrls(certificate);
      // Most certificates have CRL distribution points
      expect(Array.isArray(crlUrls)).toBe(true);
      console.log("CRL URLs found:", crlUrls);
    });
  });

  describe("Revocation check (offline mode)", () => {
    it("should skip revocation when checkRevocation is false", async () => {
      const sig = container.signatures[0];
      const result = await verifySignature(sig, container.files, {
        checkRevocation: false,
      });

      expect(result.certificate.revocation).toBeUndefined();
    });
  });

  describe("Revocation check (online mode)", () => {
    // This test makes real network requests - increase timeout
    it("should perform OCSP/CRL check when enabled", async () => {
      const sig = container.signatures[0];
      const result = await checkCertificateRevocation(sig.certificatePEM, {
        certificateChain: sig.certificateChain,
        ocspTimeout: 10000,
        crlTimeout: 15000,
      });

      console.log("Revocation check result:", {
        status: result.status,
        method: result.method,
        reason: result.reason,
        isValid: result.isValid,
      });

      // Result should have required fields
      expect(result).toHaveProperty("status");
      expect(result).toHaveProperty("isValid");
      expect(result).toHaveProperty("checkedAt");
      expect(["good", "revoked", "unknown", "error"]).toContain(result.status);

      // If we got a definitive answer, method should be set
      if (result.status === "good" || result.status === "revoked") {
        expect(["ocsp", "crl"]).toContain(result.method);
      }
    }, 30000); // 30 second timeout for network requests

    it("should include revocation result in verifySignature when enabled", async () => {
      const sig = container.signatures[0];
      const result = await verifySignature(sig, container.files, {
        checkRevocation: true,
      });

      // Revocation result should be included
      expect(result.certificate.revocation).toBeDefined();
      expect(result.certificate.revocation?.status).toBeDefined();

      console.log("Full verification with revocation:", {
        isValid: result.isValid,
        certValid: result.certificate.isValid,
        revocationStatus: result.certificate.revocation?.status,
        revocationMethod: result.certificate.revocation?.method,
      });
    }, 30000);
  });
});
