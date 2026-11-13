/**
 * RSA DigestInfo Workaround
 *
 * Some older signing tools (particularly pre-Java 8) produced RSA signatures with
 * non-standard DigestInfo format - missing the NULL parameter in AlgorithmIdentifier.
 *
 * Standard DigestInfo for SHA-1:  30 21 30 09 06 05 2b0e03021a 05 00 04 14 [hash]
 * Non-standard (missing NULL):    30 1f 30 07 06 05 2b0e03021a       04 14 [hash]
 *
 * Web Crypto API's subtle.verify() is strict and rejects the non-standard format.
 * This module provides a fallback that manually performs RSA verification using
 * BigInt math, which works in both browser and Node.js environments.
 *
 * The recovered block must be well-formed PKCS#1 v1.5 type 1 padding followed by
 * exactly one of the two encodings above for the expected hash algorithm and value.
 * Any other content (different OID, extra or missing bytes) is rejected.
 */

/**
 * Parse RSA public key from SPKI format to extract modulus and exponent
 */
function parseRSAPublicKey(spkiData: ArrayBuffer): { n: bigint; e: bigint } | null {
  const bytes = new Uint8Array(spkiData);

  // SPKI structure:
  // SEQUENCE {
  //   SEQUENCE { algorithm OID, parameters (NULL or absent) }
  //   BIT STRING { RSAPublicKey }
  // }
  // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }

  let pos = 0;

  // Helper to read ASN.1 length
  const readLength = (): number => {
    const first = bytes[pos++];
    if ((first & 0x80) === 0) {
      return first;
    }
    const numBytes = first & 0x7f;
    let length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | bytes[pos++];
    }
    return length;
  };

  // Helper to read INTEGER as BigInt
  const readInteger = (): bigint => {
    if (bytes[pos++] !== 0x02) return BigInt(0); // INTEGER tag
    const len = readLength();
    let value = BigInt(0);
    for (let i = 0; i < len; i++) {
      value = (value << BigInt(8)) | BigInt(bytes[pos++]);
    }
    return value;
  };

  try {
    // Outer SEQUENCE
    if (bytes[pos++] !== 0x30) return null;
    readLength();

    // AlgorithmIdentifier SEQUENCE
    if (bytes[pos++] !== 0x30) return null;
    const algoLen = readLength();
    pos += algoLen; // Skip algorithm identifier

    // BIT STRING containing RSAPublicKey
    if (bytes[pos++] !== 0x03) return null;
    readLength();
    pos++; // Skip unused bits byte

    // RSAPublicKey SEQUENCE
    if (bytes[pos++] !== 0x30) return null;
    readLength();

    // Read modulus and exponent
    const n = readInteger();
    const e = readInteger();

    return { n, e };
  } catch {
    return null;
  }
}

/**
 * Perform modular exponentiation: base^exp mod mod
 * Uses square-and-multiply algorithm for efficiency
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = BigInt(1);
  base = base % mod;
  while (exp > 0) {
    if (exp % BigInt(2) === BigInt(1)) {
      result = (result * base) % mod;
    }
    exp = exp >> BigInt(1);
    base = (base * base) % mod;
  }
  return result;
}

/**
 * Convert Uint8Array to BigInt
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = BigInt(0);
  for (const byte of bytes) {
    result = (result << BigInt(8)) | BigInt(byte);
  }
  return result;
}

/**
 * Convert BigInt to Uint8Array with specified length
 */
function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const result = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(value & BigInt(0xff));
    value = value >> BigInt(8);
  }
  return result;
}

/**
 * Verify PKCS#1 v1.5 signature padding and extract DigestInfo
 * @param decrypted The decrypted signature block
 * @returns The DigestInfo bytes, or null if padding is invalid
 */
function extractDigestInfoFromPKCS1(decrypted: Uint8Array): Uint8Array | null {
  // PKCS#1 v1.5 signature format:
  // 0x00 0x01 [0xFF padding] 0x00 [DigestInfo]
  if (decrypted[0] !== 0x00 || decrypted[1] !== 0x01) {
    return null;
  }

  // Find the 0x00 separator after padding
  let separatorIndex = -1;
  for (let i = 2; i < decrypted.length; i++) {
    if (decrypted[i] === 0x00) {
      separatorIndex = i;
      break;
    }
    if (decrypted[i] !== 0xff) {
      return null; // Invalid padding byte
    }
  }

  if (separatorIndex === -1 || separatorIndex < 10) {
    return null; // No separator found or padding too short
  }

  return decrypted.slice(separatorIndex + 1);
}

/**
 * DER-encoded OBJECT IDENTIFIER contents for the supported hash algorithms
 */
const HASH_ALGORITHM_OIDS: Record<string, number[]> = {
  sha1: [0x2b, 0x0e, 0x03, 0x02, 0x1a],
  sha256: [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
  sha384: [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
  sha512: [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
};

/**
 * Normalize a hash algorithm name ("SHA-256", "sha256", ...) to a lookup key
 */
function normalizeHashName(hashAlgorithm: string): string {
  return hashAlgorithm.toLowerCase().replace(/-/g, "");
}

/**
 * Build the DER encoding of DigestInfo for the given hash.
 *
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm AlgorithmIdentifier,  -- SEQUENCE { OID, NULL (optional) }
 *   digest OCTET STRING
 * }
 *
 * All supported encodings are shorter than 128 bytes, so short-form lengths suffice.
 */
function encodeDigestInfo(oid: number[], hash: Uint8Array, withNullParams: boolean): Uint8Array {
  const algorithmId = [0x06, oid.length, ...oid];
  if (withNullParams) {
    algorithmId.push(0x05, 0x00);
  }
  const algorithmSeq = [0x30, algorithmId.length, ...algorithmId];
  const digest = [0x04, hash.length, ...hash];
  return new Uint8Array([0x30, algorithmSeq.length + digest.length, ...algorithmSeq, ...digest]);
}

/**
 * Compare two byte arrays without early exit on the first difference
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Check that the recovered DigestInfo is exactly one of the accepted encodings
 * for the expected hash: the standard DER form (with NULL parameters) or the
 * legacy form without the NULL parameters. No other bytes may be present.
 */
function digestInfoMatches(
  digestInfo: Uint8Array,
  oid: number[],
  expectedHash: Uint8Array,
): boolean {
  const standard = encodeDigestInfo(oid, expectedHash, true);
  const withoutNull = encodeDigestInfo(oid, expectedHash, false);
  // Evaluate both so timing does not depend on which form matched
  const matchesStandard = bytesEqual(digestInfo, standard);
  const matchesWithoutNull = bytesEqual(digestInfo, withoutNull);
  return matchesStandard || matchesWithoutNull;
}

/**
 * Detects if code is running in a browser environment
 */
function isBrowser(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.crypto !== "undefined" &&
    typeof window.crypto.subtle !== "undefined"
  );
}

/**
 * Verify RSA signature with non-standard DigestInfo format.
 *
 * This function performs RSA signature verification that tolerates
 * non-standard DigestInfo formats (missing NULL in AlgorithmIdentifier).
 *
 * - Node.js: Uses native crypto.publicDecrypt() for speed
 * - Browser: Uses BigInt math (Web Crypto doesn't expose raw RSA)
 *
 * @param publicKeyData SPKI-formatted public key
 * @param signatureBytes Raw signature bytes
 * @param dataToVerify The data that was signed
 * @param hashAlgorithm Hash algorithm name (e.g., "SHA-1", "SHA-256")
 * @returns true if signature is valid, false otherwise
 */
export async function verifyRsaWithNonStandardDigestInfo(
  publicKeyData: ArrayBuffer,
  signatureBytes: Uint8Array,
  dataToVerify: Uint8Array,
  hashAlgorithm: string,
): Promise<boolean> {
  try {
    const hashKey = normalizeHashName(hashAlgorithm);
    const oid = HASH_ALGORITHM_OIDS[hashKey];
    if (!oid) {
      return false;
    }

    let digestInfo: Uint8Array | null;

    if (isBrowser()) {
      // Browser: Use BigInt math (Web Crypto doesn't expose raw RSA decryption)
      const keyParams = parseRSAPublicKey(publicKeyData);
      if (!keyParams) {
        return false;
      }

      const { n, e } = keyParams;
      if (n <= BigInt(0) || e <= BigInt(0)) {
        return false;
      }
      const keyLength = Math.ceil(n.toString(16).length / 2);

      const signatureInt = bytesToBigInt(signatureBytes);
      // RSAVP1: the signature representative must be smaller than the modulus
      if (signatureInt >= n) {
        return false;
      }
      const decryptedInt = modPow(signatureInt, e, n);
      const decrypted = bigIntToBytes(decryptedInt, keyLength);

      digestInfo = extractDigestInfoFromPKCS1(decrypted);
    } else {
      // Node.js: Use native crypto.publicDecrypt() for speed
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require("crypto");

      const publicKey = nodeCrypto.createPublicKey({
        key: Buffer.from(publicKeyData),
        format: "der",
        type: "spki",
      });

      const decrypted = nodeCrypto.publicDecrypt(
        { key: publicKey, padding: nodeCrypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(signatureBytes),
      );

      // Node's publicDecrypt checks and strips the PKCS#1 v1.5 type 1 padding
      // (00 01 FF..FF 00 with at least 8 FF bytes) and returns the DigestInfo directly
      digestInfo = new Uint8Array(decrypted);
    }

    if (!digestInfo) {
      return false;
    }

    // Compute expected hash
    let expectedHash: Uint8Array;
    if (isBrowser()) {
      // Web Crypto names: SHA-1, SHA-256, SHA-384, SHA-512
      const hashName = hashKey.toUpperCase().replace(/^SHA(\d)/, "SHA-$1");
      const hashBuffer = await window.crypto.subtle.digest(hashName, new Uint8Array(dataToVerify));
      expectedHash = new Uint8Array(hashBuffer);
    } else {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require("crypto");
      expectedHash = new Uint8Array(
        nodeCrypto.createHash(hashKey).update(Buffer.from(dataToVerify)).digest(),
      );
    }

    // The recovered block must be exactly one of the accepted DigestInfo encodings
    return digestInfoMatches(digestInfo, oid, expectedHash);
  } catch {
    return false;
  }
}
