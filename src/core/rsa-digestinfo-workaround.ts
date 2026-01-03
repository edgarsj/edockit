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
 * Extract hash from DigestInfo structure
 * Handles both standard (with NULL) and non-standard (without NULL) formats
 */
function extractHashFromDigestInfo(
  digestInfo: Uint8Array,
  expectedHashLength: number,
): Uint8Array | null {
  // DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
  // Look for OCTET STRING tag (0x04) followed by the hash
  for (let i = 0; i < digestInfo.length - 1; i++) {
    if (digestInfo[i] === 0x04) {
      const len = digestInfo[i + 1];
      if (len === expectedHashLength && i + 2 + len <= digestInfo.length) {
        return digestInfo.slice(i + 2, i + 2 + len);
      }
    }
  }
  return null;
}

/**
 * Get hash length in bytes for a given algorithm
 */
function getHashLength(hashAlgorithm: string): number {
  const algo = hashAlgorithm.toLowerCase().replace("-", "");
  switch (algo) {
    case "sha1":
      return 20;
    case "sha256":
      return 32;
    case "sha384":
      return 48;
    case "sha512":
      return 64;
    default:
      return 32;
  }
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
    let digestInfo: Uint8Array | null;

    if (isBrowser()) {
      // Browser: Use BigInt math (Web Crypto doesn't expose raw RSA decryption)
      const keyParams = parseRSAPublicKey(publicKeyData);
      if (!keyParams) {
        return false;
      }

      const { n, e } = keyParams;
      const keyLength = Math.ceil(n.toString(16).length / 2);

      const signatureInt = bytesToBigInt(signatureBytes);
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

      // Node's publicDecrypt already strips PKCS#1 padding, returns DigestInfo directly
      digestInfo = new Uint8Array(decrypted);
    }

    if (!digestInfo) {
      return false;
    }

    // Extract hash from DigestInfo (tolerates missing NULL)
    const hashLength = getHashLength(hashAlgorithm);
    const extractedHash = extractHashFromDigestInfo(digestInfo, hashLength);
    if (!extractedHash) {
      return false;
    }

    // Compute expected hash
    let expectedHash: Uint8Array;
    if (isBrowser()) {
      // Normalize to Web Crypto format: SHA-1, SHA-256, SHA-384, SHA-512
      let hashName = hashAlgorithm.toUpperCase().replace(/-/g, "");
      hashName = hashName.replace(/^SHA(\d)/, "SHA-$1");
      const hashBuffer = await window.crypto.subtle.digest(hashName, dataToVerify);
      expectedHash = new Uint8Array(hashBuffer);
    } else {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require("crypto");
      const hashName = hashAlgorithm.toLowerCase().replace("-", "");
      expectedHash = nodeCrypto.createHash(hashName).update(Buffer.from(dataToVerify)).digest();
    }

    // Compare hashes (constant-time comparison)
    if (extractedHash.length !== expectedHash.length) {
      return false;
    }
    let diff = 0;
    for (let i = 0; i < extractedHash.length; i++) {
      diff |= extractedHash[i] ^ expectedHash[i];
    }

    return diff === 0;
  } catch {
    return false;
  }
}
