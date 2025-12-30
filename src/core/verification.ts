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
 * Complete verification result
 */
export interface VerificationResult {
  isValid: boolean;
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

    // Import the public key
    let publicKey;
    try {
      const subtle = getCryptoSubtle();
      if (isBrowser() && algorithm.name === "RSASSA-PKCS1-v1_5") {
        // console.log("Browser environment detected, applying RSA key fix");
        publicKeyData = fixRSAModulusPadding(publicKeyData);
      }
      publicKey = await subtle.importKey("spki", publicKeyData, algorithm, false, ["verify"]);
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
      signatureValue: signatureInfo.signatureValue,
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

      // If certificate is revoked, mark certificate as invalid
      if (revocationResult.status === "revoked") {
        certResult.isValid = false;
        certResult.reason = revocationResult.reason || "Certificate has been revoked";
        errors.push(`Certificate revoked: ${revocationResult.reason || "No reason provided"}`);
      }
      // Note: 'unknown' status is a soft fail - certificate remains valid
      // but user can check revocation.status to see if it couldn't be verified
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

  // Return the complete result
  return {
    isValid,
    certificate: certResult,
    checksums: checksumResult,
    signature: options.verifySignatures !== false ? signatureResult : undefined,
    timestamp: timestampResult,
    errors: errors.length > 0 ? errors : undefined,
  };
}
