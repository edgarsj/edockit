import { expect } from "@esm-bundle/chai";
import { parseEdoc } from "../src/core/parser";
import { checkCertificateRevocation } from "../src/core/revocation/check";
import { extractOCSPUrls } from "../src/core/revocation/ocsp";
import { extractCRLUrls } from "../src/core/revocation/crl";
import { X509Certificate } from "@peculiar/x509";

describe("Certificate Revocation (Browser)", () => {
  const samplePath = "/tests/fixtures/valid_samples/SampleFile.edoc";

  let container: ReturnType<typeof parseEdoc>;
  let certificate: X509Certificate;

  before(async function () {
    try {
      const response = await fetch(samplePath);
      if (!response.ok) {
        console.error(`Failed to fetch ${samplePath}: ${response.status} ${response.statusText}`);
        this.skip();
        return;
      }

      const buffer = await response.arrayBuffer();
      container = parseEdoc(new Uint8Array(buffer));
      expect(container.signatures.length).to.be.greaterThan(0);

      const sig = container.signatures[0];
      certificate = new X509Certificate(sig.certificatePEM);
    } catch (error) {
      console.error("Error setting up revocation tests:", error);
      this.skip();
    }
  });

  describe("OCSP/CRL URL extraction", () => {
    it("should extract OCSP URLs from certificate", function () {
      if (!certificate) {
        this.skip();
        return;
      }

      const ocspUrls = extractOCSPUrls(certificate);
      expect(Array.isArray(ocspUrls)).to.be.true;
      console.log("OCSP URLs found:", ocspUrls);
    });

    it("should extract CRL URLs from certificate", function () {
      if (!certificate) {
        this.skip();
        return;
      }

      const crlUrls = extractCRLUrls(certificate);
      expect(Array.isArray(crlUrls)).to.be.true;
      console.log("CRL URLs found:", crlUrls);
    });
  });

  describe("Revocation check (offline mode)", () => {
    it("should skip revocation when checkRevocation is false", async function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const { verifySignature } = await import("../src/core/verification");
      const sig = container.signatures[0];
      const result = await verifySignature(sig, container.files, {
        checkRevocation: false,
      });

      expect(result.certificate.revocation).to.be.undefined;
    });
  });

  describe("Revocation check (online mode)", () => {
    it("should perform OCSP/CRL check when enabled", async function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

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

      expect(result).to.have.property("status");
      expect(result).to.have.property("isValid");
      expect(result).to.have.property("checkedAt");
      expect(["good", "revoked", "unknown", "error"]).to.contain(result.status);

      if (result.status === "good" || result.status === "revoked") {
        expect(["ocsp", "crl"]).to.contain(result.method);
      }
    });

    it("should include revocation result in verifySignature when enabled", async function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const { verifySignature } = await import("../src/core/verification");
      const sig = container.signatures[0];
      const result = await verifySignature(sig, container.files, {
        checkRevocation: true,
      });

      expect(result.certificate.revocation).to.not.be.undefined;
      expect(result.certificate.revocation?.status).to.not.be.undefined;

      console.log("Full verification with revocation:", {
        isValid: result.isValid,
        certValid: result.certificate.isValid,
        revocationStatus: result.certificate.revocation?.status,
        revocationMethod: result.certificate.revocation?.method,
      });
    });
  });
});
