import { createHash } from "crypto";
import { X509Certificate } from "@peculiar/x509";
import {
  checkCertificateValidity,
  CertificateInfo,
  parseCertificate,
} from "./certificate";
import { createXMLParser } from "../utils/xmlParser";
import { XMLCanonicalizer } from "./canonicalization/XMLCanonicalizer";

/**
 * Options for verification process
 */
export interface VerificationOptions {
  checkCertificateValidity?: boolean;
  verifySignatures?: boolean;
  verifyChecksums?: boolean;
  verifyTime?: Date;
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
}

/**
 * Result of a certificate verification
 */
export interface CertificateVerificationResult {
  isValid: boolean;
  reason?: string;
  info?: CertificateInfo;
}

/**
 * Complete verification result
 */
export interface VerificationResult {
  isValid: boolean;
  certificate: CertificateVerificationResult;
  checksums: ChecksumVerificationResult;
  signature?: SignatureVerificationResult;
  errors?: string[];
}

/**
 * Compute a digest (hash) of file content
 * @param fileContent The file content as Uint8Array
 * @param algorithm The digest algorithm to use (e.g., 'SHA-256')
 * @returns Base64-encoded digest
 */
export function computeDigest(
  fileContent: Uint8Array,
  algorithm: string,
): string {
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

  // Compute the digest
  const hash = createHash(hashAlgo);
  hash.update(fileContent);
  return hash.digest("base64");
}

/**
 * Verify checksums of files against signature
 * @param signature The signature information
 * @param files Map of filenames to file contents
 * @returns Verification results for each file
 */
export function verifyChecksums(
  signature: { signedChecksums: Record<string, string>; algorithm?: string },
  files: Map<string, Uint8Array>,
): ChecksumVerificationResult {
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

  // Determine hash algorithm from signature algorithm or use default
  let digestAlgorithm = "SHA-256";
  if (signature.algorithm) {
    if (signature.algorithm.includes("sha1")) {
      digestAlgorithm = "SHA-1";
    } else if (signature.algorithm.includes("sha384")) {
      digestAlgorithm = "SHA-384";
    } else if (signature.algorithm.includes("sha512")) {
      digestAlgorithm = "SHA-512";
    }
  }

  // Verify each checksum
  for (const [filename, expectedChecksum] of Object.entries(
    signature.signedChecksums,
  )) {
    // Check if file exists in the container
    const fileContent = files.get(filename);

    if (!fileContent) {
      // File not found - this could be due to URI encoding or path format
      // Try to find by file basename
      const basename = filename.includes("/")
        ? filename.split("/").pop()
        : filename;

      let foundMatch = false;
      if (basename) {
        for (const [containerFilename, content] of files.entries()) {
          if (containerFilename.endsWith(basename)) {
            // Found a match by basename
            const actualChecksum = computeDigest(content, digestAlgorithm);
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
      const actualChecksum = computeDigest(fileContent, digestAlgorithm);
      const matches = expectedChecksum === actualChecksum;

      results[filename] = {
        expected: expectedChecksum,
        actual: actualChecksum,
        matches,
        fileFound: true,
      };

      if (!matches) allValid = false;
    }
  }

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
 * Verify an XML digital signature
 * @param signatureXml XML signature content
 * @param publicKeyData Public key to verify with
 * @returns Signature verification result
 */
export async function verifyXMLSignature(
  signatureXml: string,
  publicKeyData: ArrayBuffer,
  algorithm: { name: string; hash: string; namedCurve?: string },
): Promise<SignatureVerificationResult> {
  try {
    // Parse the signature XML
    const parser = createXMLParser();
    const xmlDoc = parser.parseFromString(signatureXml, "application/xml");

    // Find SignedInfo element
    const signedInfo =
      xmlDoc.getElementsByTagName("SignedInfo")[0] ||
      xmlDoc.getElementsByTagName("ds:SignedInfo")[0];

    if (!signedInfo) {
      return { isValid: false, reason: "SignedInfo element not found" };
    }

    // Canonicalize SignedInfo
    // First find canonicalization method
    const c14nMethodEl =
      signedInfo.getElementsByTagName("CanonicalizationMethod")[0] ||
      signedInfo.getElementsByTagName("ds:CanonicalizationMethod")[0];

    let c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
    if (c14nMethodEl) {
      c14nMethod = c14nMethodEl.getAttribute("Algorithm") || c14nMethod;
    }

    // Canonicalize the SignedInfo element
    const canonicalizer = XMLCanonicalizer.fromMethod(c14nMethod);
    const canonicalizedSignedInfo = canonicalizer.canonicalize(
      signedInfo as any,
    );

    // Get signature value
    const signatureValueEl =
      xmlDoc.getElementsByTagName("SignatureValue")[0] ||
      xmlDoc.getElementsByTagName("ds:SignatureValue")[0];

    if (!signatureValueEl) {
      return { isValid: false, reason: "SignatureValue element not found" };
    }

    const signatureValue =
      signatureValueEl.textContent?.replace(/\s+/g, "") || "";

    // Convert base64 signature to binary
    const signatureBytes = Uint8Array.from(atob(signatureValue), (c) =>
      c.charCodeAt(0),
    );

    // Import the public key
    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyData,
      algorithm,
      false,
      ["verify"],
    );

    // Verify the signature
    const signedData = new TextEncoder().encode(canonicalizedSignedInfo);
    const result = await crypto.subtle.verify(
      algorithm,
      publicKey,
      signatureBytes.buffer,
      signedData,
    );

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
}

/**
 * Verify a complete signature (certificate, checksums, and signature)
 * @param signatureInfo Signature information
 * @param files File contents
 * @param options Verification options
 * @returns Complete verification result
 */
export async function verifySignature(
  signatureInfo: {
    certificate: string;
    certificatePEM: string;
    publicKey?: {
      algorithm: string;
      namedCurve?: string;
      rawData: ArrayBuffer;
    };
    signedChecksums: Record<string, string>;
    algorithm?: string;
    signingTime: Date;
  },
  files: Map<string, Uint8Array>,
  options: VerificationOptions = {},
): Promise<VerificationResult> {
  const errors: string[] = [];

  // Verify certificate
  const certResult = await verifyCertificate(
    signatureInfo.certificatePEM,
    options.verifyTime || signatureInfo.signingTime,
  );

  // Verify checksums
  const checksumResult =
    options.verifyChecksums !== false
      ? verifyChecksums(signatureInfo, files)
      : { isValid: true, details: {} };

  // Determine overall validity
  let isValid = certResult.isValid && checksumResult.isValid;

  // Return the complete result
  return {
    isValid,
    certificate: certResult,
    checksums: checksumResult,
    errors: errors.length > 0 ? errors : undefined,
  };
}
