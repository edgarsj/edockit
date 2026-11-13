import { X509Certificate } from "@peculiar/x509";
// Import crypto dynamically only when needed in Node environment
import { checkCertificateValidity, CertificateInfo, parseCertificate } from "./certificate";
import { createXMLParser, querySelector } from "../utils/xmlParser";
import { XMLCanonicalizer, CANONICALIZATION_METHODS } from "./canonicalization/XMLCanonicalizer";
import { SignatureInfo } from "./parser";
import { parseSignatureElement } from "./parser/signatureParser";
import {
  DSIG_NS,
  getSignatureParts,
  getSingleDsigChild,
  isElementNamed,
  locateTopLevelSignatures,
} from "./parser/signatureStructure";
import { verifySignedProperties } from "./signedReferences";
import { fixRSAModulusPadding } from "./rsa-modulus-padding-fix";
import { checkCertificateRevocation } from "./revocation/check";
import { extractCertsFromOCSPResponses } from "./revocation/ocsp";
import { RevocationResult, RevocationCheckOptions } from "./revocation/types";
import { verifyTimestamp } from "./timestamp/verify";
import { TimestampVerificationResult } from "./timestamp/types";
import { base64ToUint8Array } from "../utils/encoding";
import { verifyRsaWithNonStandardDigestInfo } from "./rsa-digestinfo-workaround";
import {
  extractCertificateIdentityFromCertificate,
  extractIssuerIdentityFromCertificate,
} from "./trustedlist/identity";
import type { TrustListMatch, TrustListProvider } from "./trustedlist/contract";
import type { TrustedListFetchOptions } from "./trustedlist/types";

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
  /** Include a structured verification checklist in the result (default: false) */
  includeChecklist?: boolean;
  /** Trusted-list provider used for issuer and timestamp authority trust checks */
  trustListProvider?: TrustListProvider;
  /** Options used when fetching issuer certificates needed for stronger trust-list matching */
  trustedListFetchOptions?: TrustedListFetchOptions;
  /** Allow DN-only trusted-list matches to be treated as positive evidence */
  allowWeakDnOnlyTrustMatch?: boolean;
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

export type ChecklistStatus = "pass" | "fail" | "skipped" | "indeterminate";

export type ChecklistCheck =
  | "document_integrity"
  | "signature_valid"
  | "certificate_valid_at_signing_time"
  | "timestamp_present"
  | "timestamp_valid"
  | "timestamp_authority_trusted_at_signing_time"
  | "certificate_not_revoked_at_signing_time"
  | "issuer_trusted_at_signing_time";

export interface ChecklistItem {
  check: ChecklistCheck;
  label: string;
  status: ChecklistStatus;
  detail?: string;
  country?: string;
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
  checklist?: ChecklistItem[];
  trustListMatch?: TrustListMatch;
  timestampTrustListMatch?: TrustListMatch;
  errors?: string[];
}

function createChecklistItem(
  check: ChecklistCheck,
  label: string,
  status: ChecklistStatus,
  detail?: string,
  country?: string,
): ChecklistItem {
  return {
    check,
    label,
    status,
    ...(detail ? { detail } : {}),
    ...(country ? { country } : {}),
  };
}

function getFailedChecksumDetail(checksumResult: ChecksumVerificationResult): string {
  const failedChecksums = Object.entries(checksumResult.details)
    .filter(([_, details]) => !details.matches)
    .map(([filename]) => filename)
    .join(", ");

  return failedChecksums
    ? `Checksum validation failed for files: ${failedChecksums}`
    : "Checksum validation failed";
}

function buildTrustChecklistItem(
  check: ChecklistCheck,
  label: string,
  match: TrustListMatch | undefined,
  error: string | undefined,
  fallbackDetail: string,
  allowWeakDnOnlyTrustMatch: boolean,
): ChecklistItem {
  if (error) {
    return createChecklistItem(check, label, "indeterminate", error);
  }

  if (!match) {
    return createChecklistItem(check, label, "indeterminate", fallbackDetail);
  }

  if (match.confidence === "dn_only" && !allowWeakDnOnlyTrustMatch) {
    return createChecklistItem(
      check,
      label,
      "indeterminate",
      match.detail || fallbackDetail,
      match.country,
    );
  }

  if (match.trustedAtTime === true) {
    return createChecklistItem(check, label, "pass", match.detail, match.country);
  }

  if (match.trustedAtTime === false || !match.found) {
    return createChecklistItem(check, label, "fail", match.detail, match.country);
  }

  return createChecklistItem(
    check,
    label,
    "indeterminate",
    match.detail || fallbackDetail,
    match.country,
  );
}

function buildVerificationChecklist({
  options,
  signatureInfo,
  certificateValidityAtSigningTime,
  certificateResult,
  checksumResult,
  signatureResult,
  timestampResult,
  overallStatus,
  trustListMatch,
  trustListError,
  timestampTrustListMatch,
  timestampTrustListError,
}: {
  options: VerificationOptions;
  signatureInfo: SignatureInfo;
  certificateValidityAtSigningTime: { isValid: boolean; reason?: string };
  certificateResult: CertificateVerificationResult;
  checksumResult: ChecksumVerificationResult;
  signatureResult: SignatureVerificationResult;
  timestampResult?: TimestampVerificationResult;
  overallStatus: ValidationStatus;
  trustListMatch?: TrustListMatch;
  trustListError?: string;
  timestampTrustListMatch?: TrustListMatch;
  timestampTrustListError?: string;
}): ChecklistItem[] {
  const checklist: ChecklistItem[] = [];

  if (options.verifyChecksums === false) {
    checklist.push(
      createChecklistItem(
        "document_integrity",
        "Document integrity",
        "skipped",
        "Checksum verification not enabled",
      ),
    );
  } else {
    checklist.push(
      createChecklistItem(
        "document_integrity",
        "Document integrity",
        checksumResult.isValid ? "pass" : "fail",
        checksumResult.isValid ? undefined : getFailedChecksumDetail(checksumResult),
      ),
    );
  }

  if (options.verifySignatures === false) {
    checklist.push(
      createChecklistItem(
        "signature_valid",
        "Signature cryptographically valid",
        "skipped",
        "Signature verification not enabled",
      ),
    );
  } else if (signatureResult.unsupportedPlatform) {
    checklist.push(
      createChecklistItem(
        "signature_valid",
        "Signature cryptographically valid",
        "indeterminate",
        signatureResult.reason || "Signature verification is not supported on this platform",
      ),
    );
  } else {
    checklist.push(
      createChecklistItem(
        "signature_valid",
        "Signature cryptographically valid",
        signatureResult.isValid ? "pass" : "fail",
        signatureResult.isValid ? undefined : signatureResult.reason,
      ),
    );
  }

  if (certificateValidityAtSigningTime.isValid) {
    checklist.push(
      createChecklistItem(
        "certificate_valid_at_signing_time",
        "Certificate valid at trusted signing time",
        "pass",
      ),
    );
  } else {
    checklist.push(
      createChecklistItem(
        "certificate_valid_at_signing_time",
        "Certificate valid at trusted signing time",
        overallStatus === "INDETERMINATE" ? "indeterminate" : "fail",
        certificateValidityAtSigningTime.reason || certificateResult.reason,
      ),
    );
  }

  if (signatureInfo.signatureTimestamp) {
    checklist.push(createChecklistItem("timestamp_present", "Signature timestamp present", "pass"));
  } else {
    checklist.push(
      createChecklistItem(
        "timestamp_present",
        "Signature timestamp present",
        "skipped",
        "Signature timestamp not present",
      ),
    );
  }

  if (!signatureInfo.signatureTimestamp) {
    checklist.push(
      createChecklistItem(
        "timestamp_valid",
        "Timestamp valid and bound to signature",
        "skipped",
        "Signature timestamp not present",
      ),
    );
  } else if (options.verifyTimestamps === false) {
    checklist.push(
      createChecklistItem(
        "timestamp_valid",
        "Timestamp valid and bound to signature",
        "skipped",
        "Timestamp verification not enabled",
      ),
    );
  } else if (!timestampResult) {
    checklist.push(
      createChecklistItem(
        "timestamp_valid",
        "Timestamp valid and bound to signature",
        "indeterminate",
        "Timestamp verification did not return a result",
      ),
    );
  } else if (timestampResult.coversSignature === false) {
    checklist.push(
      createChecklistItem(
        "timestamp_valid",
        "Timestamp valid and bound to signature",
        "fail",
        timestampResult.reason || "Timestamp token does not cover the signature value",
      ),
    );
  } else if (!timestampResult.isValid) {
    checklist.push(
      createChecklistItem(
        "timestamp_valid",
        "Timestamp valid and bound to signature",
        "fail",
        timestampResult.reason || "Timestamp verification failed",
      ),
    );
  } else if (timestampResult.coversSignature === true) {
    checklist.push(
      createChecklistItem("timestamp_valid", "Timestamp valid and bound to signature", "pass"),
    );
  } else {
    checklist.push(
      createChecklistItem(
        "timestamp_valid",
        "Timestamp valid and bound to signature",
        "indeterminate",
        timestampResult.reason ||
          "Timestamp token verified, but signature binding could not be confirmed",
      ),
    );
  }

  if (!signatureInfo.signatureTimestamp) {
    checklist.push(
      createChecklistItem(
        "timestamp_authority_trusted_at_signing_time",
        "Timestamp authority trusted at signing time",
        "skipped",
        "Signature timestamp not present",
      ),
    );
  } else if (options.verifyTimestamps === false) {
    checklist.push(
      createChecklistItem(
        "timestamp_authority_trusted_at_signing_time",
        "Timestamp authority trusted at signing time",
        "skipped",
        "Timestamp verification not enabled",
      ),
    );
  } else if (!options.trustListProvider) {
    checklist.push(
      createChecklistItem(
        "timestamp_authority_trusted_at_signing_time",
        "Timestamp authority trusted at signing time",
        "skipped",
        "Trusted-list provider not configured",
      ),
    );
  } else if (!timestampResult?.info?.tsaCertificate) {
    checklist.push(
      createChecklistItem(
        "timestamp_authority_trusted_at_signing_time",
        "Timestamp authority trusted at signing time",
        "indeterminate",
        timestampResult?.reason || "Timestamp verification did not produce a TSA certificate",
      ),
    );
  } else {
    checklist.push(
      buildTrustChecklistItem(
        "timestamp_authority_trusted_at_signing_time",
        "Timestamp authority trusted at signing time",
        timestampTrustListMatch,
        timestampTrustListError,
        "Timestamp authority trust check did not return a result",
        options.allowWeakDnOnlyTrustMatch === true,
      ),
    );
  }

  if (options.checkRevocation === false) {
    checklist.push(
      createChecklistItem(
        "certificate_not_revoked_at_signing_time",
        "Certificate not revoked at signing time",
        "skipped",
        "Revocation check not enabled",
      ),
    );
  } else if (!certificateResult.revocation) {
    checklist.push(
      createChecklistItem(
        "certificate_not_revoked_at_signing_time",
        "Certificate not revoked at signing time",
        "skipped",
        "Revocation check was not performed",
      ),
    );
  } else if (
    certificateResult.revocation.status === "good" ||
    certificateResult.revocation.isValid
  ) {
    checklist.push(
      createChecklistItem(
        "certificate_not_revoked_at_signing_time",
        "Certificate not revoked at signing time",
        "pass",
        certificateResult.revocation.reason,
      ),
    );
  } else if (
    certificateResult.revocation.status === "unknown" ||
    certificateResult.revocation.status === "error"
  ) {
    checklist.push(
      createChecklistItem(
        "certificate_not_revoked_at_signing_time",
        "Certificate not revoked at signing time",
        "indeterminate",
        certificateResult.revocation.reason,
      ),
    );
  } else {
    checklist.push(
      createChecklistItem(
        "certificate_not_revoked_at_signing_time",
        "Certificate not revoked at signing time",
        "fail",
        certificateResult.revocation.reason,
      ),
    );
  }

  if (!options.trustListProvider) {
    checklist.push(
      createChecklistItem(
        "issuer_trusted_at_signing_time",
        "Issuer trusted at signing time",
        "skipped",
        "Trusted-list provider not configured",
      ),
    );
  } else {
    checklist.push(
      buildTrustChecklistItem(
        "issuer_trusted_at_signing_time",
        "Issuer trusted at signing time",
        trustListMatch,
        trustListError,
        "Issuer trust check did not return a result",
        options.allowWeakDnOnlyTrustMatch === true,
      ),
    );
  }

  return checklist;
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

  const hashBuffer = await window.crypto.subtle.digest(browserAlgo, new Uint8Array(fileContent));

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
            if (containerFilename === basename || containerFilename.endsWith(`/${basename}`)) {
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
  let signedInfo: Element;
  try {
    // Locate the SignedInfo strictly: either the document element itself, or
    // the ds:SignedInfo child of the document's top-level ds:Signature.
    const parser = createXMLParser();
    const xmlDoc = parser.parseFromString(signatureXml, "application/xml");
    const root = xmlDoc.documentElement;
    if (isElementNamed(root, DSIG_NS, "SignedInfo")) {
      signedInfo = root;
    } else {
      const signatures = locateTopLevelSignatures(xmlDoc);
      if (signatures.length !== 1) {
        return {
          isValid: false,
          reason:
            signatures.length === 0
              ? "SignedInfo element not found in provided XML"
              : "Expected exactly one top-level Signature element",
        };
      }
      signedInfo = getSignatureParts(signatures[0]).signedInfo;
    }
  } catch (error) {
    return {
      isValid: false,
      reason: `SignedInfo verification error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  return verifySignedInfoElement(
    signedInfo,
    signatureValue,
    publicKeyData,
    algorithm,
    canonicalizationMethod,
  );
}

function getInclusiveNamespacePrefixList(methodElement: Element | null): string[] | undefined {
  if (!methodElement) {
    return undefined;
  }
  for (let i = 0; i < methodElement.childNodes.length; i++) {
    const child = methodElement.childNodes[i] as Element;
    if (child.nodeType === 1 && child.localName === "InclusiveNamespaces") {
      const prefixList = child.getAttribute("PrefixList")?.trim();
      return prefixList ? prefixList.split(/\s+/).filter(Boolean) : undefined;
    }
  }
  return undefined;
}

/**
 * Verify the signature value over a specific ds:SignedInfo element.
 */
export async function verifySignedInfoElement(
  signedInfo: Element,
  signatureValue: string,
  publicKeyData: ArrayBuffer,
  algorithm: { name: string; hash: string; namedCurve?: string },
  canonicalizationMethod?: string,
): Promise<SignatureVerificationResult> {
  try {
    // Determine canonicalization method
    const c14nMethod = canonicalizationMethod || CANONICALIZATION_METHODS.default;

    // Canonicalize the SignedInfo element
    const canonicalizedSignedInfo = XMLCanonicalizer.canonicalize(signedInfo, c14nMethod, {
      inclusiveNamespacePrefixList: getInclusiveNamespacePrefixList(
        getSingleDsigChild(signedInfo, "CanonicalizationMethod"),
      ),
    });

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
      const result = await subtle.verify(
        algorithm,
        publicKey,
        new Uint8Array(signatureBytes),
        new Uint8Array(signedData),
      );

      if (result) {
        return {
          isValid: true,
        };
      }

      // Standard verification failed - try fallback for RSA signatures
      // Some older signatures use non-standard DigestInfo format (missing NULL in AlgorithmIdentifier)
      if (algorithm.name === "RSASSA-PKCS1-v1_5") {
        const fallbackResult = await verifyRsaWithNonStandardDigestInfo(
          publicKeyData,
          signatureBytes,
          signedData,
          algorithm.hash,
        );
        if (fallbackResult) {
          return {
            isValid: true,
          };
        }
      }

      return {
        isValid: false,
        reason: "Signature verification failed",
      };
    } catch (error) {
      // Try fallback for RSA signatures when subtle.verify throws
      if (algorithm.name === "RSASSA-PKCS1-v1_5") {
        const fallbackResult = await verifyRsaWithNonStandardDigestInfo(
          publicKeyData,
          signatureBytes,
          signedData,
          algorithm.hash,
        );
        if (fallbackResult) {
          return {
            isValid: true,
          };
        }
      }

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

function resolveKeyAlgorithm(signatureInfo: SignatureInfo): any {
  const algorithm = signatureInfo.algorithm || "";
  const keyAlgorithm: any = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
  };
  if (algorithm.includes("ecdsa") && signatureInfo.publicKey?.namedCurve) {
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
  return keyAlgorithm;
}

function formatSignatureError(signatureResult: SignatureVerificationResult): string {
  let detailedErrorMessage = signatureResult.reason || "XML signature verification failed";
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
  return detailedErrorMessage;
}

interface LocatedSignature {
  doc: Document;
  element: Element;
  info: SignatureInfo;
}

/**
 * Re-locate the signature inside its raw XML and re-derive every
 * security-relevant field from that exact element, so that the SignedInfo
 * that is verified, the references that are checked and the certificate that
 * is used all come from the same ds:Signature.
 */
function locateSignature(signatureInfo: SignatureInfo): LocatedSignature {
  const doc = createXMLParser().parseFromString(signatureInfo.rawXml!, "application/xml");
  const signatures = locateTopLevelSignatures(doc);
  if (signatures.length === 0) {
    throw new Error("No top-level Signature element found");
  }

  let element = signatures[0];
  if (signatures.length > 1) {
    const byId = signatures.filter((sig) => sig.getAttribute("Id") === signatureInfo.id);
    if (byId.length !== 1) {
      throw new Error("Could not unambiguously identify the signature in its document");
    }
    element = byId[0];
  }

  const reparsed = parseSignatureElement(element, doc);
  return { doc, element, info: { ...signatureInfo, ...reparsed, rawXml: signatureInfo.rawXml } };
}

function getRevocationFetchOptions(options: VerificationOptions): TrustedListFetchOptions {
  return (
    options.trustedListFetchOptions ?? {
      timeout: options.revocationOptions?.ocspTimeout,
      proxyUrl: options.revocationOptions?.proxyUrl,
    }
  );
}

/**
 * Verify a complete signature (certificate, checksums, and signature)
 * @param signatureInfo Signature information
 * @param files File contents
 * @param options Verification options
 * @returns Complete verification result
 */
export async function verifySignature(
  inputSignatureInfo: SignatureInfo,
  files: Map<string, Uint8Array>,
  options: VerificationOptions = {},
): Promise<VerificationResult> {
  const errors: string[] = [];
  let timestampResult: TimestampVerificationResult | undefined;
  let trustListMatch: TrustListMatch | undefined;
  let trustListError: string | undefined;
  let timestampTrustListMatch: TrustListMatch | undefined;
  let timestampTrustListError: string | undefined;
  let issuerVerified = false;
  let issuerSignatureMismatch = false;

  // Re-derive all fields from the raw XML of the signature (when available).
  let located: LocatedSignature | undefined;
  let structureError: string | undefined;
  if (inputSignatureInfo.rawXml) {
    try {
      located = locateSignature(inputSignatureInfo);
    } catch (error) {
      structureError = `Invalid signature structure: ${error instanceof Error ? error.message : String(error)}`;
    }
  }
  const signatureInfo = located?.info ?? inputSignatureInfo;

  // Verify the signature value and the signed properties first: nothing else
  // in the signature can be relied upon unless these hold.
  let signatureResult: SignatureVerificationResult = { isValid: true };
  let signedPropertiesTime: Date | undefined;

  if (structureError) {
    signatureResult = { isValid: false, reason: structureError };
    errors.push(structureError);
  } else if (
    options.verifySignatures !== false &&
    located &&
    signatureInfo.signatureValue &&
    signatureInfo.publicKey
  ) {
    const parts = getSignatureParts(located.element);
    signatureResult = await verifySignedInfoElement(
      parts.signedInfo,
      signatureInfo.signatureValue,
      signatureInfo.publicKey.rawData,
      resolveKeyAlgorithm(signatureInfo),
      signatureInfo.canonicalizationMethod,
    );

    if (signatureResult.isValid) {
      const signerCertificateDer = new Uint8Array(
        new X509Certificate(signatureInfo.certificatePEM).rawData,
      );
      const signedProperties = await verifySignedProperties(
        located.doc,
        located.element,
        parts.references,
        signerCertificateDer,
        (data, algorithmUri) => computeDigest(data, algorithmUri),
      );
      if (signedProperties.isValid) {
        signedPropertiesTime = signedProperties.signingTime;
      } else {
        signatureResult = {
          isValid: false,
          reason: `Signed properties verification failed: ${signedProperties.reason || "unknown reason"}`,
        };
      }
    }

    if (!signatureResult.isValid) {
      errors.push(formatSignatureError(signatureResult));
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

  // The claimed signing time is only meaningful once the signed properties
  // have been verified. It is reported, but never used as proof of time.
  if (signedPropertiesTime) {
    signatureInfo.signingTime = signedPropertiesTime;
  }

  // Verify the timestamp (if present). Only a valid timestamp that covers this
  // signature - and, when a trusted list is configured, comes from a trusted
  // timestamp authority - provides proof of existence.
  const validationTime = options.verifyTime ?? new Date();
  let proofOfExistenceTime: Date | undefined;

  if (signatureInfo.signatureTimestamp && options.verifyTimestamps !== false) {
    timestampResult = await verifyTimestamp(signatureInfo.signatureTimestamp, {
      canonicalSignatureValue: signatureInfo.canonicalSignatureValue,
      verifyTsaCertificate: true,
      revocationOptions: options.revocationOptions,
    });

    if (!timestampResult.isValid) {
      errors.push(`Timestamp verification failed: ${timestampResult.reason || "Unknown reason"}`);
    }

    if (
      options.trustListProvider &&
      timestampResult.isValid &&
      timestampResult.info?.tsaCertificate &&
      timestampResult.info.genTime
    ) {
      try {
        const tsaIdentity = await extractCertificateIdentityFromCertificate(
          timestampResult.info.tsaCertificate,
        );

        timestampTrustListMatch = await options.trustListProvider.match({
          purpose: "timestamp_tsa",
          subjectDn: tsaIdentity.subjectDn,
          skiHex: tsaIdentity.subjectKeyIdentifierHex,
          spkiSha256Hex: tsaIdentity.spkiSha256Hex,
          time: timestampResult.info.genTime,
        });
      } catch (error) {
        timestampTrustListError = `Timestamp authority trusted-list check failed: ${error instanceof Error ? error.message : String(error)}`;
        errors.push(timestampTrustListError);
      }
    }

    const timestampTrusted =
      !options.trustListProvider ||
      (timestampTrustListMatch?.trustedAtTime === true &&
        timestampTrustListMatch.confidence === "exact");

    if (
      timestampResult.isValid &&
      timestampResult.coversSignature === true &&
      timestampResult.info?.genTime &&
      timestampTrusted
    ) {
      proofOfExistenceTime = timestampResult.info.genTime;
    }
  }

  // Certificate validity and revocation are evaluated at the proven signing
  // time when there is proof of existence, otherwise at the validation time.
  const trustedSigningTime: Date = proofOfExistenceTime ?? validationTime;

  // Verify certificate (time validity)
  const certResult = await verifyCertificate(signatureInfo.certificatePEM, trustedSigningTime);
  const certificateValidityAtSigningTime = {
    isValid: certResult.isValid,
    reason: certResult.reason,
  };

  if (!certResult.isValid) {
    errors.push(`Certificate validation error: ${certResult.reason || "Unknown reason"}`);
  }

  // Certificates embedded in the signature or in its embedded OCSP responses
  // are candidate issuers. Candidates are only used once they are shown to
  // have signed the certificate.
  const issuerCandidates = [
    ...(signatureInfo.certificateChain ?? []),
    ...extractCertsFromOCSPResponses(signatureInfo.revocationValues?.ocsp ?? []),
  ];

  // Check certificate revocation (default: enabled)
  if (options.checkRevocation !== false && certResult.isValid) {
    try {
      const revocationResult = await checkCertificateRevocation(signatureInfo.certificatePEM, {
        certificateChain: issuerCandidates.length > 0 ? issuerCandidates : undefined,
        ...options.revocationOptions,
      });

      certResult.revocation = revocationResult;

      if (revocationResult.status === "revoked") {
        const revokedAt = revocationResult.revokedAt;
        const hasValidRevocationTime = revokedAt && revokedAt.getTime() > 0;

        // Long-term validation: only proof of existence (a trusted timestamp)
        // can show that the signature was created before revocation.
        if (proofOfExistenceTime && hasValidRevocationTime && proofOfExistenceTime < revokedAt) {
          certResult.revocation.isValid = true;
          certResult.revocation.reason = `Certificate was revoked on ${revokedAt.toISOString()}, but the signature is proven to exist on ${proofOfExistenceTime.toISOString()} (before revocation)`;
        } else {
          certResult.isValid = false;
          const revokedAtStr = hasValidRevocationTime ? ` on ${revokedAt.toISOString()}` : "";
          certResult.reason =
            revocationResult.reason || `Certificate has been revoked${revokedAtStr}`;
          errors.push(revocationResult.reason || `Certificate revoked${revokedAtStr}`);
        }
      }
    } catch (error) {
      certResult.revocation = {
        isValid: false,
        status: "error",
        method: "none",
        reason: `Revocation check failed: ${error instanceof Error ? error.message : String(error)}`,
        checkedAt: new Date(),
      };
    }
  }

  if (options.trustListProvider) {
    try {
      const issuerIdentity = await extractIssuerIdentityFromCertificate(
        signatureInfo.certificatePEM,
        {
          certificateChain: issuerCandidates,
          fetchOptions: getRevocationFetchOptions(options),
        },
      );
      issuerVerified = !!issuerIdentity.issuerCertificate;
      issuerSignatureMismatch = issuerIdentity.issuerSignatureMismatch === true;

      trustListMatch = await options.trustListProvider.match({
        purpose: "signature_issuer",
        subjectDn: issuerIdentity.issuerSubjectDn,
        skiHex: issuerIdentity.authorityKeyIdentifierHex,
        spkiSha256Hex: issuerIdentity.issuerCertificate?.spkiSha256Hex,
        time: trustedSigningTime,
      });
    } catch (error) {
      trustListError = `Trusted list check failed: ${error instanceof Error ? error.message : String(error)}`;
      errors.push(trustListError);
    }
  }

  // Verify checksums
  let checksumResult: ChecksumVerificationResult =
    options.verifyChecksums !== false
      ? await verifyChecksums(signatureInfo, files)
      : { isValid: true, details: {} };
  if (
    options.verifyChecksums !== false &&
    Object.keys(signatureInfo.signedChecksums).length === 0
  ) {
    checksumResult = { isValid: false, details: {} };
  }
  const checksumFailureDetail = checksumResult.isValid
    ? undefined
    : Object.keys(checksumResult.details).length === 0
      ? "Signature does not cover any files"
      : getFailedChecksumDetail(checksumResult);

  if (checksumFailureDetail) {
    errors.push(checksumFailureDetail);
  }

  // Determine overall validity
  // Timestamp failure only affects validity if timestamp was present and verification was enabled
  const timestampValid =
    !signatureInfo.signatureTimestamp ||
    options.verifyTimestamps === false ||
    (timestampResult?.isValid ?? true);

  let isValid =
    certResult.isValid && checksumResult.isValid && signatureResult.isValid && timestampValid;

  // Determine validation status and limitations
  let status: ValidationStatus = "VALID";
  let statusMessage: string | undefined;
  const limitations: ValidationLimitation[] = [];

  if (!isValid) {
    if (signatureResult.unsupportedPlatform) {
      status = "UNSUPPORTED";
      statusMessage = signatureResult.reason;
      limitations.push({
        code: "RSA_KEY_SIZE_UNSUPPORTED",
        description: signatureResult.reason || "RSA key size not supported",
        platform: "Safari/WebKit",
      });
    } else if (!checksumResult.isValid) {
      status = "INVALID";
      statusMessage = checksumFailureDetail || "File integrity check failed";
    } else if (!signatureResult.isValid) {
      status = "INVALID";
      statusMessage = signatureResult.reason || "Signature verification failed";
    } else if (!certResult.isValid) {
      if (certResult.reason?.includes("expired") && !proofOfExistenceTime) {
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
    } else if (timestampResult && !timestampResult.isValid) {
      status = "INDETERMINATE";
      statusMessage = timestampResult.reason || "Timestamp verification failed";
      limitations.push({
        code: "TIMESTAMP_VERIFICATION_FAILED",
        description:
          timestampResult.reason || "Could not verify timestamp to establish proof of existence",
      });
    } else {
      status = "INVALID";
      statusMessage = errors[0] || "Verification failed";
    }
  }

  const downgrade = (code: string, message: string, description = message) => {
    status = "INDETERMINATE";
    isValid = false;
    statusMessage = message;
    limitations.push({ code, description });
  };

  if (status === "VALID") {
    // Revocation must be positively established when it was requested.
    const revocationStatus = certResult.revocation?.status;
    if (
      options.checkRevocation !== false &&
      revocationStatus !== "good" &&
      revocationStatus !== "revoked"
    ) {
      downgrade(
        "REVOCATION_UNKNOWN",
        "Certificate revocation status could not be determined",
        certResult.revocation?.reason || "Could not check certificate revocation status",
      );
    }
  }

  if ((status === "VALID" || status === "INDETERMINATE") && issuerSignatureMismatch) {
    // The issuer named in the signer certificate is available, but its key did
    // not sign the signer certificate.
    status = "INVALID";
    isValid = false;
    statusMessage = "Signer certificate was not issued by the certificate authority it names";
  }

  if (status === "VALID") {
    if (!options.trustListProvider) {
      downgrade(
        "TRUST_NOT_CHECKED",
        "Signer certificate trust was not checked (no trusted-list provider configured)",
      );
    } else if (!trustListMatch && trustListError) {
      downgrade("TRUST_LIST_CHECK_FAILED", "Trusted list check failed", trustListError);
    } else if (!trustListMatch || !trustListMatch.found || trustListMatch.trustedAtTime === false) {
      downgrade(
        "ISSUER_NOT_TRUSTED",
        trustListMatch?.found
          ? "Signer issuer found in trusted list but was not trusted at signing time"
          : "Signer issuer not found in trusted list",
      );
    } else if (!issuerVerified || trustListMatch.confidence !== "exact") {
      downgrade(
        "ISSUER_NOT_VERIFIED",
        "Signer certificate could not be cryptographically linked to a trusted-list certificate",
        issuerVerified
          ? "The certificate that issued the signer certificate is not the certificate listed in the trusted list"
          : "The issuer certificate was not available to verify the signer certificate's signature",
      );
    } else if (trustListMatch.trustedAtTime !== true) {
      downgrade("ISSUER_NOT_TRUSTED", "Signer issuer trust at signing time could not be confirmed");
    }
  }

  if (
    status === "VALID" &&
    options.trustListProvider &&
    timestampResult?.isValid &&
    !proofOfExistenceTime
  ) {
    downgrade(
      "TIMESTAMP_AUTHORITY_NOT_TRUSTED",
      "Timestamp authority is not trusted",
      timestampTrustListError ||
        timestampTrustListMatch?.detail ||
        "Timestamp authority not found in trusted list",
    );
  }

  const checklist = options.includeChecklist
    ? buildVerificationChecklist({
        options,
        signatureInfo,
        certificateValidityAtSigningTime,
        certificateResult: certResult,
        checksumResult,
        signatureResult,
        timestampResult,
        overallStatus: status,
        trustListMatch,
        trustListError,
        timestampTrustListMatch,
        timestampTrustListError,
      })
    : undefined;

  return {
    isValid,
    status,
    statusMessage,
    limitations: limitations.length > 0 ? limitations : undefined,
    certificate: certResult,
    checksums: checksumResult,
    signature: options.verifySignatures !== false ? signatureResult : undefined,
    timestamp: timestampResult,
    checklist,
    trustListMatch,
    timestampTrustListMatch,
    errors: errors.length > 0 ? errors : undefined,
  };
}
