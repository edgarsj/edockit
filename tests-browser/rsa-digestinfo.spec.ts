import { expect } from "@esm-bundle/chai";
import { verifyRsaWithNonStandardDigestInfo } from "../src/core/rsa-digestinfo-workaround";

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
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

describe("RSA DigestInfo Workaround (Browser)", () => {
  it("should verify signature with non-standard DigestInfo format", async () => {
    const publicKeyData = base64ToArrayBuffer(testVectors.publicKeyBase64);
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    const dataToVerify = new TextEncoder().encode(testVectors.testData);

    const result = await verifyRsaWithNonStandardDigestInfo(
      publicKeyData,
      signatureBytes,
      dataToVerify,
      testVectors.hashAlgorithm,
    );

    expect(result).to.equal(true);
  });

  it("should fail verification with tampered data", async () => {
    const publicKeyData = base64ToArrayBuffer(testVectors.publicKeyBase64);
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    const tamperedData = new TextEncoder().encode(testVectors.testData + "tampered");

    const result = await verifyRsaWithNonStandardDigestInfo(
      publicKeyData,
      signatureBytes,
      tamperedData,
      testVectors.hashAlgorithm,
    );

    expect(result).to.equal(false);
  });

  it("should fail verification with wrong signature", async () => {
    const publicKeyData = base64ToArrayBuffer(testVectors.publicKeyBase64);
    // Corrupt the signature
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    signatureBytes[0] ^= 0xff;
    const dataToVerify = new TextEncoder().encode(testVectors.testData);

    const result = await verifyRsaWithNonStandardDigestInfo(
      publicKeyData,
      signatureBytes,
      dataToVerify,
      testVectors.hashAlgorithm,
    );

    expect(result).to.equal(false);
  });

  it("should handle different hash algorithm name formats", async () => {
    const publicKeyData = base64ToArrayBuffer(testVectors.publicKeyBase64);
    const signatureBytes = base64ToUint8Array(testVectors.signatureBase64);
    const dataToVerify = new TextEncoder().encode(testVectors.testData);

    // Test with various formats of "SHA-1"
    const formats = ["SHA-1", "sha1", "SHA1", "sha-1"];

    for (const format of formats) {
      const result = await verifyRsaWithNonStandardDigestInfo(
        publicKeyData,
        signatureBytes,
        dataToVerify,
        format,
      );
      expect(result, `Failed with format: ${format}`).to.equal(true);
    }
  });
});

/**
 * Strictness checks for the recovered block (browser BigInt path).
 * A throwaway key is generated with Web Crypto; signatures over hand-built
 * blocks are produced with raw BigInt RSA using the exported private exponent.
 */
describe("RSA DigestInfo Workaround (Browser, strict block layout)", () => {
  const SHA1_OID = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
  const data = new TextEncoder().encode("Data covered by the signature");

  let spki: ArrayBuffer;
  let n: bigint;
  let d: bigint;
  let keyLength: number;
  let sha1: Uint8Array;

  function b64urlToBigInt(value: string): bigint {
    const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    let result = BigInt(0);
    for (let i = 0; i < binary.length; i++) {
      result = (result << BigInt(8)) | BigInt(binary.charCodeAt(i));
    }
    return result;
  }

  function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = BigInt(1);
    base %= mod;
    while (exp > BigInt(0)) {
      if (exp & BigInt(1)) result = (result * base) % mod;
      exp >>= BigInt(1);
      base = (base * base) % mod;
    }
    return result;
  }

  function digestInfo(oid: number[], hash: Uint8Array, withNull: boolean): number[] {
    const algId = withNull ? [...oid, 0x05, 0x00] : [...oid];
    const algSeq = [0x30, algId.length, ...algId];
    const digest = [0x04, hash.length, ...hash];
    return [0x30, algSeq.length + digest.length, ...algSeq, ...digest];
  }

  function signPadded(payload: number[]): Uint8Array {
    const ffCount = keyLength - 3 - payload.length;
    const block = [0x00, 0x01, ...new Array(ffCount).fill(0xff), 0x00, ...payload];
    let m = BigInt(0);
    for (const byte of block) m = (m << BigInt(8)) | BigInt(byte);
    let s = modPow(m, d, n);
    const out = new Uint8Array(keyLength);
    for (let i = keyLength - 1; i >= 0; i--) {
      out[i] = Number(s & BigInt(0xff));
      s >>= BigInt(8);
    }
    return out;
  }

  before(async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-1",
      },
      true,
      ["sign", "verify"],
    );
    spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    n = b64urlToBigInt(jwk.n as string);
    d = b64urlToBigInt(jwk.d as string);
    keyLength = 256;
    sha1 = new Uint8Array(await crypto.subtle.digest("SHA-1", data));
  });

  it("accepts the standard and the no-NULL DigestInfo encodings", async () => {
    const withNull = signPadded(digestInfo(SHA1_OID, sha1, true));
    const withoutNull = signPadded(digestInfo(SHA1_OID, sha1, false));
    expect(await verifyRsaWithNonStandardDigestInfo(spki, withNull, data, "SHA-1")).to.equal(true);
    expect(await verifyRsaWithNonStandardDigestInfo(spki, withoutNull, data, "SHA-1")).to.equal(
      true,
    );
  });

  it("rejects a correct DigestInfo followed by extra bytes", async () => {
    const sig = signPadded([...digestInfo(SHA1_OID, sha1, false), 0x00, 0x12, 0x34]);
    expect(await verifyRsaWithNonStandardDigestInfo(spki, sig, data, "SHA-1")).to.equal(false);
  });

  it("rejects a matching digest surrounded by arbitrary bytes", async () => {
    const payload = [...new Array(40).fill(0x5a), 0x04, sha1.length, ...sha1, 0xa5, 0xa5];
    const sig = signPadded(payload);
    expect(await verifyRsaWithNonStandardDigestInfo(spki, sig, data, "SHA-1")).to.equal(false);
  });
});
