import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import { X509Certificate } from "@peculiar/x509";
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
      if (!sig.signatureTimestamp || !sig.canonicalSignatureValue) {
        console.log("Skipping test - no timestamp or canonical signature value");
        return;
      }

      const timestampInfo = parseTimestamp(sig.signatureTimestamp);
      if (!timestampInfo) {
        console.log("Skipping test - could not parse timestamp");
        return;
      }

      const coversSignature = await verifyTimestampCoversSignature(
        timestampInfo,
        sig.canonicalSignatureValue,
      );

      console.log("Timestamp covers signature:", coversSignature);
      expect(coversSignature).toBe(true);
    });

    it("should verify timestamp with canonical signature value", async () => {
      const sig = container.signatures[0];
      if (!sig.signatureTimestamp || !sig.canonicalSignatureValue) {
        console.log("Skipping test - no timestamp or canonical signature value");
        return;
      }

      const result = await verifyTimestamp(sig.signatureTimestamp, {
        canonicalSignatureValue: sig.canonicalSignatureValue,
      });

      console.log("Timestamp verification result:", {
        isValid: result.isValid,
        coversSignature: result.coversSignature,
        reason: result.reason,
      });

      expect(result.isValid).toBe(true);
      expect(result.coversSignature).toBe(true);
      expect(result).toHaveProperty("info");
    });
  });

  describe("Timestamp token signature on sample files", () => {
    const samplesDir = join(__dirname, "../fixtures/valid_samples");
    const sampleSignatures = readdirSync(samplesDir)
      .filter((name) => /\.(edoc|asice)$/i.test(name))
      .flatMap((name) =>
        parseEdoc(readFileSync(join(samplesDir, name))).signatures.map((sig) => ({ name, sig })),
      )
      .filter(({ sig }) => sig.signatureTimestamp && sig.canonicalSignatureValue);

    it("has sample signatures with timestamps", () => {
      expect(sampleSignatures.length).toBeGreaterThan(1);
    });

    it.each(sampleSignatures.map(({ name, sig }) => [name, sig] as const))(
      "verifies the timestamp token in %s",
      async (_name, sig) => {
        const result = await verifyTimestamp(sig.signatureTimestamp!, {
          canonicalSignatureValue: sig.canonicalSignatureValue,
        });

        expect(result.reason).toBeUndefined();
        expect(result.isValid).toBe(true);
        expect(result.signatureValid).toBe(true);
        expect(result.coversSignature).toBe(true);

        // The identified certificate must be the TSA certificate referenced by the token
        const tsaCert = new X509Certificate(result.info!.tsaCertificate!);
        expect(tsaCert.subject).toMatch(/TSA|TIMESTAMPING/i);
      },
    );

    it("rejects a sample timestamp token used for another signature", async () => {
      const [first, second] = sampleSignatures;
      const result = await verifyTimestamp(first.sig.signatureTimestamp!, {
        canonicalSignatureValue: second.sig.canonicalSignatureValue,
      });

      expect(result.signatureValid).toBe(true);
      expect(result.coversSignature).toBe(false);
      expect(result.isValid).toBe(false);
    });

    it("rejects a sample timestamp token with a modified genTime", async () => {
      const token = sampleSignatures[0].sig.signatureTimestamp!;
      const original = parseTimestamp(token)!;
      const bytes = Buffer.from(token, "base64");

      // GeneralizedTime starts with YYYYMMDDHHMM; change the last minute digit
      const prefix = original.genTime.toISOString().replace(/[-:T]/g, "").slice(0, 12);
      const offset = bytes.indexOf(Buffer.from(prefix, "ascii"));
      expect(offset).toBeGreaterThan(0);
      const minuteDigit = offset + 11;
      bytes[minuteDigit] = bytes[minuteDigit] === 0x30 ? 0x31 : 0x30;
      const modified = bytes.toString("base64");

      expect(parseTimestamp(modified)!.genTime.getTime()).not.toBe(original.genTime.getTime());

      const result = await verifyTimestamp(modified, {
        canonicalSignatureValue: sampleSignatures[0].sig.canonicalSignatureValue,
      });
      expect(result.isValid).toBe(false);
      expect(result.signatureValid).toBe(false);
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
