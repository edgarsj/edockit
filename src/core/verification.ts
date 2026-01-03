import { X509Certificate } from "@peculiar/x509";
// Import crypto dynamically only when needed in Node environment
import { checkCertificateValidity, CertificateInfo, parseCertificate } from "./certificate";
import { createXMLParser, querySelector } from "../utils/xmlParser";
import { XMLCanonicalizer, CANONICALIZATION_METHODS } from "./canonicalization/XMLCanonicalizer";
import { SignatureInfo } from "./parser";
import { fixRSAModulusPadding } from "./rsa-modulus-padding-fix";
import { checkCertificateRevocation } from "./revocation/check";
import { RevocationResult, RevocationCheckOptions } from "./revocation/types";
import { verifyTimestamp, getTimestampTime } from "./timestamp/verify";
import { TimestampVerificationResult } from "./timestamp/types";
import { base64ToUint8Array } from "../utils/encoding";

/**
 * Options for verification process
 */
export interface VerificationOptions {
  checkCertificateValidity?: boolean;
  verifySignatures?: boolean;
  verifyChecksums?: boolean;
  verifyTime?: Date;
  /** Check certificate revocation via OCSP/CRL (default: true) */
  checkRevocation?: boolean;
  /** Options for revocation checking (timeouts, etc.) */
  revocationOptions?: RevocationCheckOptions;
  /** Verify RFC 3161 timestamp if present (default: true) */
  verifyTimestamps?: boolean;
}

/**
 * Result of a checksum verification
 */
export interface ChecksumVerificationResult {
  isValid: boolean;
  details: Record<
    string,
    {
      expected: string;
      actual: string;
      matches: boolean;
      fileFound: boolean;
    }
  >;
}

/**
 * Result of a signature verification
 */
export interface SignatureVerificationResult {
  isValid: boolean;
  reason?: string;
  /** True if verification failed due to platform limitation (e.g., RSA >4096 in Safari) */
  unsupportedPlatform?: boolean;
  errorDetails?: {
    category: string;
    originalMessage: string;
    algorithm: any;
    environment: string;
    keyLength: number;
  };
}

/**
 * Result of a certificate verification
 */
export interface CertificateVerificationResult {
  isValid: boolean;
  reason?: string;
  info?: CertificateInfo;
  /** Revocation check result (if checkRevocation was enabled) */
  revocation?: RevocationResult;
}

/**
 * Validation status for granular verification results
 * - VALID: Signature cryptographically valid, all checks pass
 * - INVALID: Definitely wrong (bad checksum, tampered content, crypto failure with supported key)
 * - INDETERMINATE: Can't conclude (expired cert without POE, missing chain, revocation unknown)
 * - UNSUPPORTED: Platform can't verify (e.g., RSA >4096 bits in Safari/WebKit)
 */
export type ValidationStatus = "VALID" | "INVALID" | "INDETERMINATE" | "UNSUPPORTED";

/**
 * Describes a limitation that prevented full verification
 */
export interface ValidationLimitation {
  /** Machine-readable code (e.g., 'RSA_KEY_SIZE_UNSUPPORTED', 'CERT_EXPIRED_NO_POE') */
  code: string;
  /** Human-readable description */
  description: string;
  /** Platform where this limitation applies (e.g., 'Safari/WebKit') */
  platform?: string;
}

/**
 * Complete verification result
 */
export interface VerificationResult {
  /** Whether the signature is valid (for backwards compatibility) */
  isValid: boolean;
  /** Granular validation status */
  status: ValidationStatus;
  /** Human-readable status explanation */
  statusMessage?: string;
  /** Limitations that prevented full verification (for INDETERMINATE/UNSUPPORTED) */
  limitations?: ValidationLimitation[];
  certificate: CertificateVerificationResult;
  checksums: ChecksumVerificationResult;
  signature?: SignatureVerificationResult;
  /** Timestamp verification result (if timestamp present and verifyTimestamps enabled) */
  timestamp?: TimestampVerificationResult;
  errors?: string[];
}

/**
 * Detects if code is running in a browser environment
 * @returns true if in browser, false otherwise
 */
function isBrowser(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.crypto !== "undefined" &&
    typeof window.crypto.subtle !== "undefined"
  );
}

/**
 * Detects if running in Safari/WebKit browser
 * Safari/WebKit handles RSA key DER encoding correctly and doesn't need the modulus padding fix
 * This also detects Playwright's headless WebKit
 * @returns true if Safari/WebKit, false otherwise
 */
function isWebKit(): boolean {
  if (typeof navigator === "undefined") return false;
  const ua = navigator.userAgent;
  // Detect WebKit-based browsers (Safari, or Playwright WebKit which includes "AppleWebKit" but not Chrome)
  const hasWebKit = /AppleWebKit/.test(ua);
  const isChromium = /Chrome/.test(ua) || /Chromium/.test(ua) || /Edg/.test(ua);
  return hasWebKit && !isChromium;
}

/**
 * Get RSA modulus length in bits from SPKI public key data
 * @param publicKeyData The SPKI-formatted public key
 * @returns Modulus length in bits, or 0 if not RSA or can't determine
 */
function getRSAModulusLength(publicKeyData: ArrayBuffer): number {
  const keyBytes = new Uint8Array(publicKeyData);

  // Check for RSA OID (1.2.840.113549.1.1.1)
  const RSA_OID = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
  let oidPosition = -1;

  for (let i = 0; i <= keyBytes.length - RSA_OID.length; i++) {
    let match = true;
    for (let j = 0; j < RSA_OID.length; j++) {
      if (keyBytes[i + j] !== RSA_OID[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      oidPosition = i;
      break;
    }
  }

  if (oidPosition === -1) return 0; // Not RSA

  // Find BIT STRING containing the key
  let bitStringPos = -1;
  for (let i = oidPosition + RSA_OID.length; i < keyBytes.length; i++) {
    if (keyBytes[i] === 0x03) {
      bitStringPos = i;
      break;
    }
  }
  if (bitStringPos === -1) return 0;

  // Skip BIT STRING header to find inner SEQUENCE
  let pos = bitStringPos + 1;
  if ((keyBytes[pos] & 0x80) === 0) {
    pos += 1; // short length
  } else {
    pos += 1 + (keyBytes[pos] & 0x7f); // long length
  }
  pos += 1; // skip unused bits byte

  if (keyBytes[pos] !== 0x30) return 0; // Should be SEQUENCE

  // Skip inner SEQUENCE header to find modulus INTEGER
  pos += 1;
  if ((keyBytes[pos] & 0x80) === 0) {
    pos += 1;
  } else {
    pos += 1 + (keyBytes[pos] & 0x7f);
  }

  if (keyBytes[pos] !== 0x02) return 0; // Should be INTEGER (modulus)

  // Get modulus length
  pos += 1;
  let modulusLength = 0;
  if ((keyBytes[pos] & 0x80) === 0) {
    modulusLength = keyBytes[pos];
  } else {
    const numLenBytes = keyBytes[pos] & 0x7f;
    for (let i = 0; i < numLenBytes; i++) {
      modulusLength = (modulusLength << 8) | keyBytes[pos + 1 + i];
    }
  }

  // Modulus might have leading 0x00 padding byte, subtract if present
  // Return bits (bytes * 8), accounting for padding
  return modulusLength * 8;
}

/**
 * Check if RSA key size is supported in the current platform
 * Safari/WebKit only supports RSA keys up to 4096 bits
 */
function isRSAKeySizeSupported(modulusLengthBits: number): boolean {
  if (!isBrowser()) return true; // Node.js supports all sizes
  if (!isWebKit()) return true; // Chrome/Firefox support large keys
  // Safari/WebKit: max 4096 bits
  return modulusLengthBits <= 4096;
}

/**
 * Compute a digest (hash) of file content with browser/node compatibility
 * @param fileContent The file content as Uint8Array
 * @param algorithm The digest algorithm to use (e.g., 'SHA-256')
 * @returns Promise with Base64-encoded digest
 */
export async function computeDigest(fileContent: Uint8Array, algorithm: string): Promise<string> {
  // Normalize algorithm name
  const normalizedAlgo = algorithm.replace(/-/g, "").toLowerCase();
  let hashAlgo: string;

  // Map algorithm URIs to crypto algorithm names
  if (normalizedAlgo.includes("sha256")) {
    hashAlgo = "sha256";
  } else if (normalizedAlgo.includes("sha1")) {
    hashAlgo = "sha1";
  } else if (normalizedAlgo.includes("sha384")) {
    hashAlgo = "sha384";
  } else if (normalizedAlgo.includes("sha512")) {
    hashAlgo = "sha512";
  } else {
    throw new Error(`Unsupported digest algorithm: ${algorithm}`);
  }

  if (isBrowser()) {
    return browserDigest(fileContent, hashAlgo);
  } else {
    return nodeDigest(fileContent, hashAlgo);
  }
}

/**
 * Compute digest using Web Crypto API in browser
 * @param fileContent Uint8Array of file content
 * @param hashAlgo Normalized hash algorithm name
 * @returns Promise with Base64-encoded digest
 */
async function browserDigest(fileContent: Uint8Array, hashAlgo: string): Promise<string> {
  // Map to Web Crypto API algorithm names
  const browserAlgoMap: Record<string, string> = {
    sha1: "SHA-1",
    sha256: "SHA-256",
    sha384: "SHA-384",
    sha512: "SHA-512",
  };

  const browserAlgo = browserAlgoMap[hashAlgo];
  if (!browserAlgo) {
    throw new Error(`Unsupported browser digest algorithm: ${hashAlgo}`);
  }

  const hashBuffer = await window.crypto.subtle.digest(browserAlgo, fileContent);

  // Convert ArrayBuffer to Base64
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));

  return hashBase64;
}

/**
 * Compute digest using Node.js crypto module
 * @param fileContent Uint8Array of file content
 * @param hashAlgo Normalized hash algorithm name
 * @returns Promise with Base64-encoded digest
 */
function nodeDigest(fileContent: Uint8Array, hashAlgo: string): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      // Dynamically import Node.js crypto
      const crypto = require("crypto");
      const hash = crypto.createHash(hashAlgo);
      hash.update(Buffer.from(fileContent));
      resolve(hash.digest("base64"));
    } catch (error) {
      reject(
        new Error(
          `Node digest computation failed: ${error instanceof Error ? error.message : String(error)}`,
        ),
      );
    }
  });
}

/**
 * Parse digest algorithm URI to normalized algorithm name
 * @param algorithmUri The algorithm URI (e.g., http://www.w3.org/2001/04/xmlenc#sha256)
 * @returns Normalized algorithm name (e.g., SHA-256)
 */
function parseDigestAlgorithmUri(algorithmUri: string): string {
  const uri = algorithmUri.toLowerCase();
  if (uri.includes("sha512")) return "SHA-512";
  if (uri.includes("sha384")) return "SHA-384";
  if (uri.includes("sha256")) return "SHA-256";
  if (uri.includes("sha1")) return "SHA-1";
  return "SHA-256"; // Default fallback
}

/**
 * Verify checksums of files against signature
 * @param signature The signature information
 * @param files Map of filenames to file contents
 * @returns Promise with verification results for each file
 */
export async function verifyChecksums(
  signature: {
    signedChecksums: Record<string, string>;
    digestAlgorithms?: Record<string, string>;
    algorithm?: string;
  },
  files: Map<string, Uint8Array>,
): Promise<ChecksumVerificationResult> {
  const results: Record<
    string,
    {
      expected: string;
      actual: string;
      matches: boolean;
      fileFound: boolean;
    }
  > = {};

  let allValid = true;

  // Default digest algorithm from signature algorithm (fallback if per-file not available)
  let defaultDigestAlgorithm = "SHA-256";
  if (signature.algorithm) {
    if (signature.algorithm.includes("sha1")) {
      defaultDigestAlgorithm = "SHA-1";
    } else if (signature.algorithm.includes("sha384")) {
      defaultDigestAlgorithm = "SHA-384";
    } else if (signature.algorithm.includes("sha512")) {
      defaultDigestAlgorithm = "SHA-512";
    }
  }

  const checksumPromises = Object.entries(signature.signedChecksums).map(
    async ([filename, expectedChecksum]) => {
      // Get the per-file digest algorithm, or fall back to default
      const digestAlgorithm = signature.digestAlgorithms?.[filename]
        ? parseDigestAlgorithmUri(signature.digestAlgorithms[filename])
        : defaultDigestAlgorithm;

      // Check if file exists in the container
      const fileContent = files.get(filename);

      if (!fileContent) {
        // File not found - this could be due to URI encoding or path format
        // Try to find by file basename
        const basename = filename.includes("/") ? filename.split("/").pop() : filename;

        let foundMatch = false;
        if (basename) {
          for (const [containerFilename, content] of files.entries()) {
            if (containerFilename.endsWith(basename)) {
              // Found a match by basename
              const actualChecksum = await computeDigest(content, digestAlgorithm);
              const matches = expectedChecksum === actualChecksum;

              results[filename] = {
                expected: expectedChecksum,
                actual: actualChecksum,
                matches,
                fileFound: true,
              };

              if (!matches) allValid = false;
              foundMatch = true;
              break;
            }
          }
        }

        if (!foundMatch) {
          // Really not found
          results[filename] = {
            expected: expectedChecksum,
            actual: "",
            matches: false,
            fileFound: false,
          };
          allValid = false;
        }
      } else {
        // File found directly - verify checksum
        const actualChecksum = await computeDigest(fileContent, digestAlgorithm);
        const matches = expectedChecksum === actualChecksum;

        results[filename] = {
          expected: expectedChecksum,
          actual: actualChecksum,
          matches,
          fileFound: true,
        };

        if (!matches) allValid = false;
      }
    },
  );

  // Wait for all checksums to be verified
  await Promise.all(checksumPromises);

  return {
    isValid: allValid,
    details: results,
  };
}

/**
 * Verify certificate validity
 * @param certificatePEM PEM-formatted certificate
 * @param verifyTime Time to check validity against
 * @returns Certificate verification result
 */
export async function verifyCertificate(
  certificatePEM: string,
  verifyTime: Date = new Date(),
): Promise<CertificateVerificationResult> {
  try {
    const cert = new X509Certificate(certificatePEM);
    const validityResult = checkCertificateValidity(cert, verifyTime);

    // Parse certificate info
    const certInfo = await parseCertificate(certificatePEM);

    return {
      isValid: validityResult.isValid,
      reason: validityResult.reason,
      info: certInfo,
    };
  } catch (error) {
    return {
      isValid: false,
      reason: `Certificate parsing error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Get the expected component size for an ECDSA curve
 */
function getEcdsaComponentSize(namedCurve?: string): number {
  switch (namedCurve) {
    case "P-256":
      return 32;
    case "P-384":
      return 48;
    case "P-521":
      return 66;
    default:
      return 32; // Default to P-256
  }
}

/**
 * Normalize ECDSA signature to IEEE P1363 format (raw R||S) expected by Web Crypto API
 * Handles both raw format with potential padding and DER-encoded signatures
 */
function normalizeEcdsaSignature(signatureBytes: Uint8Array, namedCurve?: string): Uint8Array {
  const componentSize = getEcdsaComponentSize(namedCurve);
  const expectedLength = componentSize * 2;

  // If already correct length, return as-is
  if (signatureBytes.length === expectedLength) {
    return signatureBytes;
  }

  // Check if it's DER-encoded (starts with SEQUENCE tag 0x30)
  if (signatureBytes[0] === 0x30) {
    return derToRawEcdsa(signatureBytes, componentSize);
  }

  // Handle raw R||S with potential leading zeros
  // Some implementations pad R and S with leading zeros
  if (signatureBytes.length > expectedLength) {
    const halfLength = signatureBytes.length / 2;
    if (Number.isInteger(halfLength)) {
      const r = signatureBytes.slice(0, halfLength);
      const s = signatureBytes.slice(halfLength);

      // Normalize R and S to exact component size
      const normalizedR = normalizeComponent(r, componentSize);
      const normalizedS = normalizeComponent(s, componentSize);

      const result = new Uint8Array(expectedLength);
      result.set(normalizedR, 0);
      result.set(normalizedS, componentSize);
      return result;
    }
  }

  // Return as-is if we can't normalize
  return signatureBytes;
}

/**
 * Normalize a single ECDSA component (R or S) to exact size
 * Strips leading zeros or pads with leading zeros as needed
 */
function normalizeComponent(component: Uint8Array, size: number): Uint8Array {
  // Strip leading zeros
  let start = 0;
  while (start < component.length - 1 && component[start] === 0) {
    start++;
  }
  const stripped = component.slice(start);

  if (stripped.length === size) {
    return stripped;
  } else if (stripped.length < size) {
    // Pad with leading zeros
    const padded = new Uint8Array(size);
    padded.set(stripped, size - stripped.length);
    return padded;
  } else {
    // Component too large - take the last 'size' bytes
    return stripped.slice(stripped.length - size);
  }
}

/**
 * Convert DER-encoded ECDSA signature to raw IEEE P1363 format
 */
function derToRawEcdsa(derSignature: Uint8Array, componentSize: number): Uint8Array {
  // DER structure: SEQUENCE { INTEGER r, INTEGER s }
  // 0x30 len 0x02 rLen r... 0x02 sLen s...

  let offset = 0;

  // Skip SEQUENCE tag
  if (derSignature[offset++] !== 0x30) {
    throw new Error("Invalid DER signature: missing SEQUENCE tag");
  }

  // Skip sequence length (may be 1 or 2 bytes)
  const seqLen = derSignature[offset++];
  if (seqLen & 0x80) {
    offset += seqLen & 0x7f; // Skip length bytes
  }

  // Parse R
  if (derSignature[offset++] !== 0x02) {
    throw new Error("Invalid DER signature: missing INTEGER tag for R");
  }
  const rLen = derSignature[offset++];
  const r = derSignature.slice(offset, offset + rLen);
  offset += rLen;

  // Parse S
  if (derSignature[offset++] !== 0x02) {
    throw new Error("Invalid DER signature: missing INTEGER tag for S");
  }
  const sLen = derSignature[offset++];
  const s = derSignature.slice(offset, offset + sLen);

  // Normalize and concatenate
  const result = new Uint8Array(componentSize * 2);
  result.set(normalizeComponent(r, componentSize), 0);
  result.set(normalizeComponent(s, componentSize), componentSize);
  return result;
}

/**
 * Safely get the crypto.subtle implementation in either browser or Node.js
 * @returns The SubtleCrypto interface
 */
function getCryptoSubtle(): SubtleCrypto {
  if (isBrowser()) {
    return window.crypto.subtle;
  } else {
    // In Node.js environment
    return crypto.subtle;
  }
}

/**
 * Verify the XML signature specifically using SignedInfo and SignatureValue
 * @param signatureXml The XML string of the SignedInfo element
 * @param signatureValue The base64-encoded signature value
 * @param publicKeyData The public key raw data
 * @param algorithm Key algorithm details
 * @param canonicalizationMethod The canonicalization method used
 * @returns Signature verification result
 */
export async function verifySignedInfo(
  signatureXml: string,
  signatureValue: string,
  publicKeyData: ArrayBuffer,
  algorithm: { name: string; hash: string; namedCurve?: string },
  canonicalizationMethod?: string,
): Promise<SignatureVerificationResult> {
  try {
    // Parse the SignedInfo XML
    const parser = createXMLParser();
    const xmlDoc = parser.parseFromString(signatureXml, "application/xml");
    const signedInfo = querySelector(xmlDoc, "ds:SignedInfo") as any;

    if (!signedInfo) {
      return {
        isValid: false,
        reason: "SignedInfo element not found in provided XML",
      };
    }

    // Determine canonicalization method
    const c14nMethod = canonicalizationMethod || CANONICALIZATION_METHODS.default;

    // Canonicalize the SignedInfo element
    const canonicalizedSignedInfo = XMLCanonicalizer.canonicalize(signedInfo, c14nMethod);

    // Clean up signature value (remove whitespace)
    const cleanSignatureValue = signatureValue.replace(/\s+/g, "");

    // Convert base64 signature to binary
    let signatureBytes: Uint8Array;

    try {
      signatureBytes = base64ToUint8Array(cleanSignatureValue);
    } catch (error) {
      return {
        isValid: false,
        reason: `Failed to decode signature value: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    // For ECDSA, normalize signature to IEEE P1363 format (raw R||S) expected by Web Crypto
    if (algorithm.name === "ECDSA") {
      signatureBytes = normalizeEcdsaSignature(signatureBytes, algorithm.namedCurve);
    }

    // Import the public key
    let publicKey;
    try {
      const subtle = getCryptoSubtle();
      const isRSA = algorithm.name === "RSASSA-PKCS1-v1_5" || algorithm.name === "RSA-PSS";

      // Check RSA key size support before attempting import
      if (isRSA) {
        const modulusLengthBits = getRSAModulusLength(publicKeyData);
        if (modulusLengthBits > 0 && !isRSAKeySizeSupported(modulusLengthBits)) {
          return {
            isValid: false,
            unsupportedPlatform: true,
            reason: `RSA key size (${modulusLengthBits} bits) not supported in this browser`,
            errorDetails: {
              category: "RSA_KEY_SIZE_UNSUPPORTED",
              originalMessage: `Safari/WebKit only supports RSA keys up to 4096 bits`,
              algorithm: { ...algorithm },
              environment: "browser",
              keyLength: publicKeyData.byteLength,
            },
          };
        }
      }

      if (isBrowser() && isRSA) {
        // Try importing original key first, then try with padding fix if it fails
        // This handles browser differences (Chrome vs Safari/WebKit)
        try {
          publicKey = await subtle.importKey("spki", publicKeyData, algorithm, false, ["verify"]);
        } catch {
          // Original key failed, try with modulus padding fix
          const fixedKeyData = fixRSAModulusPadding(publicKeyData);
          publicKey = await subtle.importKey("spki", fixedKeyData, algorithm, false, ["verify"]);
        }
      } else {
        publicKey = await subtle.importKey("spki", publicKeyData, algorithm, false, ["verify"]);
      }
    } catch (unknownError: unknown) {
      // First cast to Error type if applicable
      const error = unknownError instanceof Error ? unknownError : new Error(String(unknownError));

      // Determine detailed error reason
      let detailedReason = "Unknown reason";
      let errorCategory = "KEY_IMPORT_ERROR";

      // Categorize the error
      if (error.name === "DataError") {
        detailedReason = "Key data format is invalid or incompatible";
        errorCategory = "INVALID_KEY_FORMAT";
      } else if (error.name === "NotSupportedError") {
        detailedReason = "Algorithm or parameters not supported";
        errorCategory = "UNSUPPORTED_ALGORITHM";
      } else if (error.message.includes("namedCurve")) {
        detailedReason = "Missing or invalid namedCurve parameter";
        errorCategory = "INVALID_CURVE";
      } else if (error.message.includes("hash")) {
        detailedReason = "Incompatible or unsupported hash algorithm";
        errorCategory = "INVALID_HASH";
      }

      // Add ECDSA-specific diagnostics
      if (algorithm.name === "ECDSA") {
        const keyLength = publicKeyData.byteLength;
        detailedReason += ` (Key length: ${keyLength})`;
      }

      return {
        isValid: false,
        reason: `Failed to import public key: ${detailedReason}`,
        errorDetails: {
          category: errorCategory,
          originalMessage: error.message,
          algorithm: { ...algorithm },
          environment: isBrowser() ? "browser" : "node",
          keyLength: publicKeyData.byteLength,
        },
      };
    }

    // Verify the signature
    const signedData = new TextEncoder().encode(canonicalizedSignedInfo);

    try {
      const subtle = getCryptoSubtle();
      const result = await subtle.verify(algorithm, publicKey, signatureBytes, signedData);

      return {
        isValid: result,
        reason: result ? undefined : "Signature verification failed",
      };
    } catch (error) {
      return {
        isValid: false,
        reason: `Signature verification error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  } catch (error) {
    return {
      isValid: false,
      reason: `SignedInfo verification error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Verify a complete signature (certificate, checksums, and signature)
 * @param signatureInfo Signature information
 * @param files File contents
 * @param options Verification options
 * @returns Complete verification result
 */
export async function verifySignature(
  signatureInfo: SignatureInfo,
  files: Map<string, Uint8Array>,
  options: VerificationOptions = {},
): Promise<VerificationResult> {
  const errors: string[] = [];
  let timestampResult: TimestampVerificationResult | undefined;

  // Verify timestamp first (if present) to get trusted time for cert validation
  let trustedSigningTime: Date = options.verifyTime || signatureInfo.signingTime;

  if (signatureInfo.signatureTimestamp && options.verifyTimestamps !== false) {
    timestampResult = await verifyTimestamp(signatureInfo.signatureTimestamp, {
      canonicalSignatureValue: signatureInfo.canonicalSignatureValue,
      verifyTsaCertificate: true,
      revocationOptions: options.revocationOptions,
    });

    if (timestampResult.isValid && timestampResult.info) {
      // Use timestamp time as the trusted signing time
      trustedSigningTime = timestampResult.info.genTime;
    } else if (!timestampResult.isValid) {
      errors.push(`Timestamp verification failed: ${timestampResult.reason || "Unknown reason"}`);
    }
  }

  // Verify certificate (time validity) - use trusted timestamp time if available
  const certResult = await verifyCertificate(signatureInfo.certificatePEM, trustedSigningTime);

  // If certificate validation failed, add detailed error
  if (!certResult.isValid) {
    const certErrorMsg = `Certificate validation error: ${certResult.reason || "Unknown reason"}`;
    errors.push(certErrorMsg);
  }

  // Check certificate revocation (default: enabled)
  if (options.checkRevocation !== false && certResult.isValid) {
    try {
      const revocationResult = await checkCertificateRevocation(signatureInfo.certificatePEM, {
        certificateChain: signatureInfo.certificateChain,
        ...options.revocationOptions,
      });

      certResult.revocation = revocationResult;

      // If certificate is revoked, check if signature was made before revocation (LTV)
      if (revocationResult.status === "revoked") {
        const revokedAt = revocationResult.revokedAt;
        const hasValidRevocationTime = revokedAt && revokedAt.getTime() > 0;

        // Long-Term Validation: if we have a trusted timestamp proving the signature
        // was made before revocation, the signature is still valid
        if (hasValidRevocationTime && trustedSigningTime < revokedAt) {
          // Signature was made before revocation - still valid (LTV)
          certResult.revocation.isValid = true;
          certResult.revocation.reason = `Certificate was revoked on ${revokedAt.toISOString()}, but signature was made on ${trustedSigningTime.toISOString()} (before revocation)`;
        } else {
          // Signature was made after revocation or no valid revocation date available
          certResult.isValid = false;
          const revokedAtStr = hasValidRevocationTime ? ` on ${revokedAt.toISOString()}` : "";
          certResult.reason =
            revocationResult.reason || `Certificate has been revoked${revokedAtStr}`;
          errors.push(revocationResult.reason || `Certificate revoked${revokedAtStr}`);
        }
      }
      // Note: 'unknown' status is a soft fail - certificate remains valid
      // but user can check revocation.status to see the actual status
    } catch (error) {
      // Revocation check failed - soft fail, add to result but don't invalidate
      certResult.revocation = {
        isValid: false,
        status: "error",
        method: "none",
        reason: `Revocation check failed: ${error instanceof Error ? error.message : String(error)}`,
        checkedAt: new Date(),
      };
    }
  }

  // Verify checksums
  const checksumResult =
    options.verifyChecksums !== false
      ? await verifyChecksums(signatureInfo, files)
      : { isValid: true, details: {} };

  // If checksum validation failed, add detailed error
  if (!checksumResult.isValid) {
    const failedChecksums = Object.entries(checksumResult.details)
      .filter(([_, details]) => !details.matches)
      .map(([filename]) => filename)
      .join(", ");

    errors.push(`Checksum validation failed for files: ${failedChecksums}`);
  }

  // Verify XML signature if we have the necessary components
  let signatureResult: SignatureVerificationResult = { isValid: true };

  if (
    options.verifySignatures !== false &&
    signatureInfo.rawXml &&
    signatureInfo.signatureValue &&
    signatureInfo.publicKey
  ) {
    // Determine algorithm
    const algorithm = signatureInfo.algorithm || "";
    const keyAlgorithm: any = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    };
    if (algorithm.includes("ecdsa") && signatureInfo.publicKey.namedCurve) {
      keyAlgorithm.namedCurve = signatureInfo.publicKey.namedCurve;
      keyAlgorithm.name = "ECDSA";
    }
    if (algorithm.includes("ecdsa-sha256")) {
      keyAlgorithm.hash = "SHA-256";
    } else if (algorithm.includes("ecdsa-sha384")) {
      keyAlgorithm.hash = "SHA-384";
    } else if (algorithm.includes("ecdsa-sha512")) {
      keyAlgorithm.hash = "SHA-512";
    } else if (algorithm.includes("rsa-sha1")) {
      keyAlgorithm.hash = "SHA-1";
    } else if (algorithm.includes("rsa-pss")) {
      keyAlgorithm.name = "RSA-PSS";
      keyAlgorithm.saltLength = 32; // Default salt length (adjust based on hash size)
      if (algorithm.includes("sha384")) {
        keyAlgorithm.hash = "SHA-384";
        keyAlgorithm.saltLength = 48;
      } else if (algorithm.includes("sha512")) {
        keyAlgorithm.hash = "SHA-512";
        keyAlgorithm.saltLength = 64;
      } else {
        keyAlgorithm.hash = "SHA-256"; // Default
      }
    } else if (algorithm.includes("rsa-sha384")) {
      keyAlgorithm.hash = "SHA-384";
    } else if (algorithm.includes("rsa-sha512")) {
      keyAlgorithm.hash = "SHA-512";
    }
    signatureResult = await verifySignedInfo(
      signatureInfo.rawXml,
      signatureInfo.signatureValue,
      signatureInfo.publicKey.rawData,
      keyAlgorithm,
      signatureInfo.canonicalizationMethod,
    );

    // If signature validation failed, add detailed error
    if (!signatureResult.isValid) {
      // Format a detailed error message with the error details
      let detailedErrorMessage = signatureResult.reason || "XML signature verification failed";

      // Add error details if available
      if (signatureResult.errorDetails) {
        const details = signatureResult.errorDetails;
        detailedErrorMessage += ` [Category: ${details.category}, Environment: ${details.environment}`;
        if (details.algorithm) {
          detailedErrorMessage += `, Algorithm: ${details.algorithm.name}`;
          if (details.algorithm.namedCurve) {
            detailedErrorMessage += `, Curve: ${details.algorithm.namedCurve}`;
          }
        }
        if (details.keyLength) {
          detailedErrorMessage += `, Key length: ${details.keyLength} bytes`;
        }
        detailedErrorMessage += `]`;
      }
      errors.push(detailedErrorMessage);
    }
  } else if (options.verifySignatures !== false) {
    // Missing information for signature verification
    const missingComponents = [];
    if (!signatureInfo.rawXml) missingComponents.push("Signature XML");
    if (!signatureInfo.signatureValue) missingComponents.push("SignatureValue");
    if (!signatureInfo.publicKey) missingComponents.push("Public Key");

    errors.push(`Cannot verify XML signature: missing ${missingComponents.join(", ")}`);
    signatureResult = {
      isValid: false,
      reason: `Missing required components: ${missingComponents.join(", ")}`,
    };
  }

  // Determine overall validity
  // Timestamp failure only affects validity if timestamp was present and verification was enabled
  const timestampValid =
    !signatureInfo.signatureTimestamp ||
    options.verifyTimestamps === false ||
    (timestampResult?.isValid ?? true);

  const isValid =
    certResult.isValid && checksumResult.isValid && signatureResult.isValid && timestampValid;

  // Determine validation status and limitations
  let status: ValidationStatus = "VALID";
  let statusMessage: string | undefined;
  const limitations: ValidationLimitation[] = [];

  if (!isValid) {
    // Check for platform unsupported (RSA key size)
    if (signatureResult.unsupportedPlatform) {
      status = "UNSUPPORTED";
      statusMessage = signatureResult.reason;
      limitations.push({
        code: "RSA_KEY_SIZE_UNSUPPORTED",
        description: signatureResult.reason || "RSA key size not supported",
        platform: "Safari/WebKit",
      });
    }
    // Check for checksum failure (definitely invalid)
    else if (!checksumResult.isValid) {
      status = "INVALID";
      statusMessage = "File integrity check failed";
    }
    // Check for signature crypto failure with supported key
    else if (!signatureResult.isValid && !signatureResult.unsupportedPlatform) {
      status = "INVALID";
      statusMessage = signatureResult.reason || "Signature verification failed";
    }
    // Check for certificate issues
    else if (!certResult.isValid) {
      // If cert expired and no valid timestamp, it's indeterminate
      if (certResult.reason?.includes("expired") && !timestampResult?.isValid) {
        status = "INDETERMINATE";
        statusMessage = "Certificate expired and no valid timestamp proof";
        limitations.push({
          code: "CERT_EXPIRED_NO_POE",
          description:
            "Certificate has expired and there is no valid timestamp to prove signature was made when certificate was valid",
        });
      } else if (certResult.revocation?.status === "revoked") {
        status = "INVALID";
        statusMessage = "Certificate has been revoked";
      } else {
        status = "INDETERMINATE";
        statusMessage = certResult.reason || "Certificate validation inconclusive";
      }
    }
    // Revocation unknown
    else if (certResult.revocation?.status === "unknown") {
      status = "INDETERMINATE";
      statusMessage = "Certificate revocation status could not be determined";
      limitations.push({
        code: "REVOCATION_UNKNOWN",
        description:
          certResult.revocation.reason || "Could not check certificate revocation status",
      });
    }
    // Fallback
    else {
      status = "INVALID";
      statusMessage = errors[0] || "Verification failed";
    }
  }

  // Return the complete result
  return {
    isValid,
    status,
    statusMessage,
    limitations: limitations.length > 0 ? limitations : undefined,
    certificate: certResult,
    checksums: checksumResult,
    signature: options.verifySignatures !== false ? signatureResult : undefined,
    timestamp: timestampResult,
    errors: errors.length > 0 ? errors : undefined,
  };
}
