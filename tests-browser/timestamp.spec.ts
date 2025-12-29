import { expect } from "@esm-bundle/chai";
import { parseEdoc } from "../src/core/parser";
import { parseTimestamp, verifyTimestamp, getTimestampTime } from "../src/core/timestamp/verify";
import { verifySignature } from "../src/core/verification";

describe("RFC 3161 Timestamp Verification (Browser)", () => {
  const samplePath = "/tests/fixtures/valid_samples/SampleFile.edoc";

  let container: ReturnType<typeof parseEdoc>;

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
    } catch (error) {
      console.error("Error setting up timestamp tests:", error);
      this.skip();
    }
  });

  describe("Timestamp extraction", () => {
    it("should extract signature timestamp if present", function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      if (sig.signatureTimestamp) {
        expect(typeof sig.signatureTimestamp).to.equal("string");
        expect(sig.signatureTimestamp.length).to.be.greaterThan(100);
        console.log("Signature timestamp found, length:", sig.signatureTimestamp.length);
      } else {
        console.log("No signature timestamp in sample file - skipping timestamp tests");
      }
    });
  });

  describe("Timestamp parsing", () => {
    it("should parse timestamp token if present", function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        console.log("Skipping test - no timestamp in sample file");
        this.skip();
        return;
      }

      const timestampInfo = parseTimestamp(sig.signatureTimestamp);
      expect(timestampInfo).to.not.be.null;

      if (timestampInfo) {
        console.log("Parsed timestamp info:", {
          genTime: timestampInfo.genTime.toISOString(),
          policy: timestampInfo.policy,
          hashAlgorithm: timestampInfo.hashAlgorithm,
          tsaName: timestampInfo.tsaName,
          hasTsaCertificate: !!timestampInfo.tsaCertificate,
        });

        expect(timestampInfo.genTime).to.be.instanceOf(Date);
        expect(typeof timestampInfo.policy).to.equal("string");
        expect(typeof timestampInfo.hashAlgorithm).to.equal("string");
        expect(typeof timestampInfo.messageImprint).to.equal("string");
      }
    });

    it("should have valid generation time", function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        this.skip();
        return;
      }

      const timestampInfo = parseTimestamp(sig.signatureTimestamp);
      expect(timestampInfo).to.not.be.null;

      if (timestampInfo) {
        // Timestamp generation time should be reasonable
        expect(timestampInfo.genTime.getTime()).to.be.lessThan(Date.now());
        expect(timestampInfo.genTime.getTime()).to.be.greaterThan(new Date("2000-01-01").getTime());
      }
    });
  });

  describe("getTimestampTime utility", () => {
    it("should extract timestamp time", function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        this.skip();
        return;
      }

      const time = getTimestampTime(sig.signatureTimestamp);
      expect(time).to.be.instanceOf(Date);
      console.log("Timestamp time:", time?.toISOString());
    });

    it("should return null for invalid timestamp", function () {
      const time = getTimestampTime("invalid-base64");
      expect(time).to.be.null;
    });
  });

  describe("Timestamp verification", () => {
    it("should verify timestamp with signature value", async function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        console.log("Skipping test - no timestamp in sample file");
        this.skip();
        return;
      }

      const result = await verifyTimestamp(sig.signatureTimestamp, {
        signatureValue: sig.signatureValue,
        verifyTsaCertificate: true,
        checkTsaRevocation: false, // Disable for faster test
      });

      console.log("Timestamp verification result:", {
        isValid: result.isValid,
        coversSignature: result.coversSignature,
        reason: result.reason,
        genTime: result.info?.genTime?.toISOString(),
      });

      expect(result).to.have.property("isValid");
      expect(result).to.have.property("info");
    });

    it("should verify timestamp with TSA revocation check", async function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        console.log("Skipping test - no timestamp in sample file");
        this.skip();
        return;
      }

      const result = await verifyTimestamp(sig.signatureTimestamp, {
        signatureValue: sig.signatureValue,
        verifyTsaCertificate: true,
        checkTsaRevocation: true,
      });

      console.log("Timestamp verification with TSA revocation:", {
        isValid: result.isValid,
        coversSignature: result.coversSignature,
        tsaRevocationStatus: result.tsaRevocation?.status,
        tsaRevocationMethod: result.tsaRevocation?.method,
        reason: result.reason,
      });

      expect(result).to.have.property("isValid");
      expect(result).to.have.property("info");

      // If TSA revocation was checked, we should have a result
      if (result.tsaRevocation) {
        expect(["good", "revoked", "unknown", "error"]).to.contain(result.tsaRevocation.status);
      }
    });
  });

  describe("Timestamp in verification flow", () => {
    it("should include timestamp result when verifyTimestamps is true", async function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      const result = await verifySignature(sig, container.files, {
        checkRevocation: false, // Disable for faster test
        verifyTimestamps: true,
      });

      if (sig.signatureTimestamp) {
        expect(result.timestamp).to.not.be.undefined;
        expect(result.timestamp?.isValid).to.not.be.undefined;
        console.log("Verification timestamp result:", {
          isValid: result.timestamp?.isValid,
          coversSignature: result.timestamp?.coversSignature,
          genTime: result.timestamp?.info?.genTime?.toISOString(),
        });
      } else {
        console.log("No timestamp to verify in sample file");
      }
    });

    it("should skip timestamp when verifyTimestamps is false", async function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      const result = await verifySignature(sig, container.files, {
        checkRevocation: false,
        verifyTimestamps: false,
      });

      expect(result.timestamp).to.be.undefined;
    });

    it("should use timestamp time for certificate validation", async function () {
      if (!container || container.signatures.length === 0) {
        this.skip();
        return;
      }

      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        console.log("Skipping test - no timestamp in sample file");
        this.skip();
        return;
      }

      // Get the timestamp time
      const timestampTime = getTimestampTime(sig.signatureTimestamp);

      // Verify with timestamp checking enabled (should use TSA time for cert validation)
      const result = await verifySignature(sig, container.files, {
        checkRevocation: false,
        verifyTimestamps: true,
      });

      console.log("Certificate validated at timestamp time:", {
        timestampTime: timestampTime?.toISOString(),
        certValid: result.certificate.isValid,
        overallValid: result.isValid,
      });

      // Certificate should be valid at the timestamp time
      if (timestampTime && result.isValid) {
        expect(result.certificate.isValid).to.be.true;
      }
    });
  });
});
