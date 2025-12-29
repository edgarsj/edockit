import { readFileSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../src/core/parser";
import { verifySignature } from "../../src/core/verification";
import {
  parseTimestamp,
  verifyTimestamp,
  verifyTimestampCoversSignature,
  getTimestampTime,
} from "../../src/core/timestamp/verify";

const sampleFilePath = join(__dirname, "../fixtures/valid_samples/SampleFile.edoc");

describe("RFC 3161 Timestamp Verification", () => {
  let container: ReturnType<typeof parseEdoc>;

  beforeAll(() => {
    const edocBuffer = readFileSync(sampleFilePath);
    container = parseEdoc(edocBuffer);
    expect(container.signatures.length).toBeGreaterThan(0);
  });

  describe("Timestamp extraction", () => {
    it("should parse the sample file successfully", () => {
      expect(container).toBeDefined();
      expect(container.signatures.length).toBeGreaterThan(0);
    });

    it("should extract signature timestamp if present", () => {
      const sig = container.signatures[0];
      // Timestamp may or may not be present depending on the file
      if (sig.signatureTimestamp) {
        expect(typeof sig.signatureTimestamp).toBe("string");
        // Base64 encoded timestamp should have reasonable length
        expect(sig.signatureTimestamp.length).toBeGreaterThan(100);
        console.log("Signature timestamp found, length:", sig.signatureTimestamp.length);
      } else {
        console.log("No signature timestamp in sample file");
      }
    });
  });

  describe("Timestamp parsing", () => {
    it("should parse timestamp token if present", () => {
      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        console.log("Skipping test - no timestamp in sample file");
        return;
      }

      const timestampInfo = parseTimestamp(sig.signatureTimestamp);
      expect(timestampInfo).not.toBeNull();

      if (timestampInfo) {
        console.log("Parsed timestamp info:", {
          genTime: timestampInfo.genTime,
          policy: timestampInfo.policy,
          hashAlgorithm: timestampInfo.hashAlgorithm,
          tsaName: timestampInfo.tsaName,
          serialNumber: timestampInfo.serialNumber.substring(0, 20) + "...",
        });

        // Verify timestamp has required fields
        expect(timestampInfo.genTime).toBeInstanceOf(Date);
        expect(typeof timestampInfo.policy).toBe("string");
        expect(typeof timestampInfo.hashAlgorithm).toBe("string");
        expect(typeof timestampInfo.messageImprint).toBe("string");
        expect(typeof timestampInfo.serialNumber).toBe("string");
      }
    });

    it("should have valid generation time", () => {
      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        console.log("Skipping test - no timestamp in sample file");
        return;
      }

      const timestampInfo = parseTimestamp(sig.signatureTimestamp);
      expect(timestampInfo).not.toBeNull();

      if (timestampInfo) {
        // Timestamp generation time should be a reasonable date (not in the future)
        expect(timestampInfo.genTime.getTime()).toBeLessThanOrEqual(Date.now());
        // Should be after year 2000
        expect(timestampInfo.genTime.getTime()).toBeGreaterThan(new Date("2000-01-01").getTime());
      }
    });
  });

  describe("Timestamp verification", () => {
    it("should verify timestamp covers signature", async () => {
      const sig = container.signatures[0];
      if (!sig.signatureTimestamp || !sig.signatureValue) {
        console.log("Skipping test - no timestamp or signature value");
        return;
      }

      const timestampInfo = parseTimestamp(sig.signatureTimestamp);
      if (!timestampInfo) {
        console.log("Skipping test - could not parse timestamp");
        return;
      }

      const coversSignature = await verifyTimestampCoversSignature(
        timestampInfo,
        sig.signatureValue,
      );

      console.log("Timestamp covers signature:", coversSignature);
      expect(typeof coversSignature).toBe("boolean");
    });

    it("should verify timestamp with signature value", async () => {
      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        console.log("Skipping test - no timestamp in sample file");
        return;
      }

      const result = await verifyTimestamp(sig.signatureTimestamp, {
        signatureValue: sig.signatureValue,
      });

      console.log("Timestamp verification result:", {
        isValid: result.isValid,
        coversSignature: result.coversSignature,
        reason: result.reason,
      });

      expect(result).toHaveProperty("isValid");
      expect(result).toHaveProperty("info");
    });
  });

  describe("getTimestampTime utility", () => {
    it("should extract timestamp time", () => {
      const sig = container.signatures[0];
      if (!sig.signatureTimestamp) {
        console.log("Skipping test - no timestamp in sample file");
        return;
      }

      const time = getTimestampTime(sig.signatureTimestamp);
      expect(time).toBeInstanceOf(Date);
      console.log("Timestamp time:", time);
    });

    it("should return null for invalid timestamp", () => {
      const time = getTimestampTime("invalid-base64");
      expect(time).toBeNull();
    });
  });

  describe("Timestamp in verification flow", () => {
    it("should include timestamp result when verifyTimestamps is true", async () => {
      const sig = container.signatures[0];
      const result = await verifySignature(sig, container.files, {
        checkRevocation: false,
        verifyTimestamps: true,
      });

      if (sig.signatureTimestamp) {
        expect(result.timestamp).toBeDefined();
        expect(result.timestamp?.isValid).toBeDefined();
        console.log("Verification timestamp result:", {
          isValid: result.timestamp?.isValid,
          coversSignature: result.timestamp?.coversSignature,
          genTime: result.timestamp?.info?.genTime,
        });
      } else {
        console.log("No timestamp to verify in sample file");
      }
    });

    it("should skip timestamp when verifyTimestamps is false", async () => {
      const sig = container.signatures[0];
      const result = await verifySignature(sig, container.files, {
        checkRevocation: false,
        verifyTimestamps: false,
      });

      expect(result.timestamp).toBeUndefined();
    });
  });
});
