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
