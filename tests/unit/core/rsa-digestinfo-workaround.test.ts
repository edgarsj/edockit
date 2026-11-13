import { constants, createHash, generateKeyPairSync, privateEncrypt, webcrypto } from "crypto";
import { verifyRsaWithNonStandardDigestInfo } from "../../../src/core/rsa-digestinfo-workaround";

/**
 * Synthetic test vectors for non-standard DigestInfo RSA verification.
 *
 * These vectors were generated with a custom script that creates an RSA signature
 * using non-standard DigestInfo format (missing NULL in AlgorithmIdentifier).
 *
 * Standard DigestInfo:     30 21 30 09 06 05 2b0e03021a 05 00 04 14 [hash]
 * Non-standard DigestInfo: 30 1f 30 07 06 05 2b0e03021a       04 14 [hash]
 *
 * This mimics old Java signing tools (pre-Java 8) that produced non-standard signatures.
 */
const testVectors = {
  // RSA 2048-bit public key (SPKI format, base64)
  publicKeyBase64:
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmFFN33TkjlQGqNXi4x4VTI5mEaWKXrjGle8PtZzWWyGB3t1Yg9/ZBspPtKrtHAOWO564997O0m62YA+2pWZg2FCMohIO6q2HApDZBSN7o3y9YpTl1erpBaPA2ni5GZJOvArcwkSIRMSbDwAVszqkAr0XlvvpuY+QhBU7hycBhyR2Be+xLcysHY3JlR14r/doxgh0isCquTA6EdM5Es08hymKMGWiRUssClY3IwYxr2O4RgMUJu+cFX1U7l+VUXOTn03t20rniP4aQJ+Ns11qiqK72aGYF5XOC4X2EWf1uDH9uubRIQx+dcIgRrW/mS8T9Ile8sak7bsYkLNIw3lHwwIDAQAB",
  // Signature with non-standard DigestInfo (missing NULL in AlgorithmIdentifier)
  signatureBase64:
    "kHXyzYVLPZAp4/zxi3yMhl2e6/vaard926H0nXINtXKG7LwAwfPWzUu6ovv/g6BaH6bzUNJt9heQ1fZi6vCvygRScuf5InTzhQbvMV8jxWktJl0K3XDtO3D0DYM3ArncwxcR6C7rdOWMdD5IRNAyDddCTviQHerkTBUOHFrqaIdNCffHJMGmnn5oqfM/kdcMpogZsa8ySM6WoX8u3gm3wP13B5Ny+iV178G941NrKyf3sYkZPCksA6gAzIK8NWUwbIKG33+/LvHLwBJVSW2SCbkNC+NMqCPVAj5WumoDqtZea5sVqMrcjDzRsCcV286zSh3rAd1mY+7hzcNRJCzP2A==",
  // Test data that was signed
  testData: "Test data for RSA signature with non-standard DigestInfo format",
  // Hash algorithm
  hashAlgorithm: "SHA-1",
};

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = Buffer.from(base64, "base64");
  return binary.buffer.slice(binary.byteOffset, binary.byteOffset + binary.byteLength);
}

function base64ToUint8Array(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

describe("RSA DigestInfo Workaround (Node.js)", () => {
  it("should verify signature with non-standard DigestInfo format", async () => {
    const publicKeyData = base64ToArrayBuffer(testVectors.publicKeyBase64);
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    const dataToVerify = Buffer.from(testVectors.testData);

    const result = await verifyRsaWithNonStandardDigestInfo(
      publicKeyData,
      signatureBytes,
      dataToVerify,
      testVectors.hashAlgorithm,
    );

    expect(result).toBe(true);
  });

  it("should fail verification with tampered data", async () => {
    const publicKeyData = base64ToArrayBuffer(testVectors.publicKeyBase64);
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    const tamperedData = Buffer.from(testVectors.testData + "tampered");

    const result = await verifyRsaWithNonStandardDigestInfo(
      publicKeyData,
      signatureBytes,
      tamperedData,
      testVectors.hashAlgorithm,
    );

    expect(result).toBe(false);
  });

  it("should fail verification with wrong signature", async () => {
    const publicKeyData = base64ToArrayBuffer(testVectors.publicKeyBase64);
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    signatureBytes[0] ^= 0xff; // Corrupt the signature
    const dataToVerify = Buffer.from(testVectors.testData);

    const result = await verifyRsaWithNonStandardDigestInfo(
      publicKeyData,
      signatureBytes,
      dataToVerify,
      testVectors.hashAlgorithm,
    );

    expect(result).toBe(false);
  });

  it("should handle different hash algorithm name formats", async () => {
    const publicKeyData = base64ToArrayBuffer(testVectors.publicKeyBase64);
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    const dataToVerify = Buffer.from(testVectors.testData);

    // Test with various formats of "SHA-1"
    const formats = ["SHA-1", "sha1", "SHA1", "sha-1"];

    for (const format of formats) {
      // Need fresh signature bytes since we don't mutate
      const freshSignatureBytes = base64ToUint8Array(testVectors.signatureBase64);
      const result = await verifyRsaWithNonStandardDigestInfo(
        publicKeyData,
        freshSignatureBytes,
        dataToVerify,
        format,
      );
      expect(result).toBe(true);
    }
  });

  it("should fail with invalid public key", async () => {
    const invalidKeyData = new ArrayBuffer(10); // Invalid key
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    const dataToVerify = Buffer.from(testVectors.testData);

    const result = await verifyRsaWithNonStandardDigestInfo(
      invalidKeyData,
      signatureBytes,
      dataToVerify,
      testVectors.hashAlgorithm,
    );

    expect(result).toBe(false);
  });
});

/**
 * Strictness checks for the recovered block.
 *
 * A throwaway RSA key (e = 3) is generated and raw RSA (no padding) is used to
 * produce signatures over hand-built blocks, so that both well-formed and
 * malformed DigestInfo layouts can be checked. Each case runs against the
 * Node.js path (crypto.publicDecrypt) and the BigInt path used in browsers.
 */
describe("RSA DigestInfo Workaround (strict block layout)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 3,
  });
  const spkiBuffer = publicKey.export({ type: "spki", format: "der" });
  const spki = spkiBuffer.buffer.slice(
    spkiBuffer.byteOffset,
    spkiBuffer.byteOffset + spkiBuffer.byteLength,
  ) as ArrayBuffer;
  const keyLength = 256;

  const data = new TextEncoder().encode("Data covered by the signature");
  const sha1 = new Uint8Array(createHash("sha1").update(data).digest());
  const sha256 = new Uint8Array(createHash("sha256").update(data).digest());

  const SHA1_OID = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
  const SHA256_OID = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

  function digestInfo(oid: number[], hash: Uint8Array, withNull: boolean): number[] {
    const algId = withNull ? [...oid, 0x05, 0x00] : [...oid];
    const algSeq = [0x30, algId.length, ...algId];
    const digest = [0x04, hash.length, ...hash];
    return [0x30, algSeq.length + digest.length, ...algSeq, ...digest];
  }

  /** Build 00 01 FF..FF 00 || payload, filling the block to the key length */
  function padType1(payload: number[]): number[] {
    const ffCount = keyLength - 3 - payload.length;
    return [0x00, 0x01, ...new Array(ffCount).fill(0xff), 0x00, ...payload];
  }

  /** Raw RSA private operation over a full-length block */
  function rawSign(block: number[]): Uint8Array {
    expect(block.length).toBe(keyLength);
    return new Uint8Array(
      privateEncrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, Buffer.from(block)),
    );
  }

  const modes: Array<[string, boolean]> = [
    ["Node.js path", false],
    ["BigInt path", true],
  ];

  describe.each(modes)("%s", (_label, useBigIntPath) => {
    const g = globalThis as any;
    let previousWindow: unknown;

    beforeAll(() => {
      previousWindow = g.window;
      if (useBigIntPath) {
        g.window = { crypto: webcrypto };
      }
    });

    afterAll(() => {
      if (previousWindow === undefined) {
        delete g.window;
      } else {
        g.window = previousWindow;
      }
    });

    const verify = (sig: Uint8Array, hashAlgorithm = "SHA-1") =>
      verifyRsaWithNonStandardDigestInfo(spki, sig, data, hashAlgorithm);

    it("accepts the standard DigestInfo encoding", async () => {
      const sig = rawSign(padType1(digestInfo(SHA1_OID, sha1, true)));
      expect(await verify(sig)).toBe(true);
    });

    it("accepts the DigestInfo encoding without NULL parameters", async () => {
      const sig = rawSign(padType1(digestInfo(SHA1_OID, sha1, false)));
      expect(await verify(sig)).toBe(true);
    });

    it("accepts both encodings for SHA-256", async () => {
      const withNull = rawSign(padType1(digestInfo(SHA256_OID, sha256, true)));
      const withoutNull = rawSign(padType1(digestInfo(SHA256_OID, sha256, false)));
      expect(await verify(withNull, "SHA-256")).toBe(true);
      expect(await verify(withoutNull, "SHA-256")).toBe(true);
    });

    it("rejects a correct DigestInfo followed by extra bytes", async () => {
      const payload = [...digestInfo(SHA1_OID, sha1, false), 0x00, 0x12, 0x34, 0x56];
      expect(await verify(rawSign(padType1(payload)))).toBe(false);
    });

    it("rejects extra bytes between the padding and the DigestInfo", async () => {
      const payload = [0xab, 0xcd, ...digestInfo(SHA1_OID, sha1, true)];
      expect(await verify(rawSign(padType1(payload)))).toBe(false);
    });

    it("rejects a matching digest surrounded by arbitrary bytes", async () => {
      const payload = [
        ...new Array(40).fill(0x5a),
        0x04,
        sha1.length,
        ...sha1,
        ...new Array(40).fill(0xa5),
      ];
      expect(await verify(rawSign(padType1(payload)))).toBe(false);
    });

    it("rejects a bare OCTET STRING without the algorithm identifier", async () => {
      const payload = [0x04, sha1.length, ...sha1];
      expect(await verify(rawSign(padType1(payload)))).toBe(false);
    });

    it("rejects a DigestInfo whose OID does not match the expected hash", async () => {
      // SHA-256 OID wrapping the SHA-1 value
      const payload = digestInfo(SHA256_OID, sha1, true);
      expect(await verify(rawSign(padType1(payload)))).toBe(false);
      // SHA-1 DigestInfo checked as SHA-256
      const sig = rawSign(padType1(digestInfo(SHA1_OID, sha1, true)));
      expect(await verify(sig, "SHA-256")).toBe(false);
    });

    it("rejects a DigestInfo with non-minimal length encoding", async () => {
      // Outer SEQUENCE length written in long form (81 xx) instead of short form
      const inner = digestInfo(SHA1_OID, sha1, false).slice(2);
      const payload = [0x30, 0x81, inner.length, ...inner];
      expect(await verify(rawSign(padType1(payload)))).toBe(false);
    });

    it("rejects padding that contains bytes other than 0xFF", async () => {
      const block = padType1(digestInfo(SHA1_OID, sha1, true));
      block[20] = 0x7f;
      expect(await verify(rawSign(block))).toBe(false);
    });

    it("rejects padding shorter than eight 0xFF bytes", async () => {
      // 00 01 FF*4 00, then filler, then the DigestInfo
      const di = digestInfo(SHA1_OID, sha1, true);
      const filler = new Array(keyLength - 7 - di.length).fill(0x00);
      const block = [0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, ...filler, ...di];
      expect(await verify(rawSign(block))).toBe(false);
    });

    it("rejects block type 2", async () => {
      const block = padType1(digestInfo(SHA1_OID, sha1, true));
      block[1] = 0x02;
      expect(await verify(rawSign(block))).toBe(false);
    });

    it("rejects unsupported hash algorithm names", async () => {
      const sig = rawSign(padType1(digestInfo(SHA1_OID, sha1, true)));
      expect(await verify(sig, "MD5")).toBe(false);
    });
  });
});
