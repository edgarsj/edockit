// src/core/timestamp/verify.ts

import { X509Certificate } from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { ContentInfo, SignedData } from "@peculiar/asn1-cms";
import { TSTInfo } from "@peculiar/asn1-tsp";
import { Name } from "@peculiar/asn1-x509";
import { TimestampInfo, TimestampVerificationResult, TimestampVerificationOptions } from "./types";
import { checkCertificateRevocation } from "../revocation/check";
import { RevocationResult } from "../revocation/types";
import {
  arrayBufferToHex,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  arrayBufferToPEM,
} from "../../utils/encoding";

/**
 * OID for SignedData content type
 */
const id_signedData = "1.2.840.113549.1.7.2";

/**
 * OID for TSTInfo content type
 */
const id_ct_TSTInfo = "1.2.840.113549.1.9.16.1.4";

/**
 * Get hash algorithm name from OID
 */
function getHashAlgorithmName(oid: string): string {
  const hashAlgorithms: Record<string, string> = {
    "1.3.14.3.2.26": "SHA-1",
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512",
  };
  return hashAlgorithms[oid] || oid;
}

/**
 * Common OID to attribute name mappings for X.500 distinguished names
 */
const oidToAttributeName: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.5": "serialNumber",
  "1.2.840.113549.1.9.1": "emailAddress",
};

/**
 * Format an X.500 Name (directoryName) to a readable string
 * @param name The Name object to format
 * @returns Formatted string like "CN=Example, O=Company, C=US"
 */
function formatDirectoryName(name: Name): string {
  const parts: string[] = [];
  for (const rdn of name) {
    for (const attr of rdn) {
      const attrName = oidToAttributeName[attr.type] || attr.type;
      // attr.value can be various ASN.1 string types
      const value = attr.value?.toString() || "";
      if (value) {
        parts.push(`${attrName}=${value}`);
      }
    }
  }
  return parts.join(", ");
}

/**
 * Parse RFC 3161 TimeStampToken from base64
 * @param timestampBase64 Base64-encoded timestamp token
 * @returns Parsed timestamp info or null if parsing fails
 */
export function parseTimestamp(timestampBase64: string): TimestampInfo | null {
  try {
    const tokenBuffer = base64ToArrayBuffer(timestampBase64);

    // Parse as ContentInfo (TimeStampToken extends ContentInfo)
    const contentInfo = AsnConvert.parse(tokenBuffer, ContentInfo);

    // Verify it's SignedData
    if (contentInfo.contentType !== id_signedData) {
      console.warn("Timestamp is not SignedData");
      return null;
    }

    // Parse SignedData
    const signedData = AsnConvert.parse(contentInfo.content, SignedData);

    // Verify encapsulated content is TSTInfo
    if (signedData.encapContentInfo.eContentType !== id_ct_TSTInfo) {
      console.warn("SignedData does not contain TSTInfo");
      return null;
    }

    // Parse TSTInfo
    if (!signedData.encapContentInfo.eContent) {
      console.warn("No eContent in SignedData");
      return null;
    }

    // Extract buffer from EncapsulatedContent - it may be in .single (OctetString) or .any (ArrayBuffer)
    const eContent = signedData.encapContentInfo.eContent;
    let tstInfoBuffer: ArrayBuffer;
    if (eContent.single) {
      // OctetString has a buffer property
      tstInfoBuffer = eContent.single.buffer;
    } else if (eContent.any) {
      tstInfoBuffer = eContent.any;
    } else {
      // Try to serialize the whole thing if it's already ASN.1 parsed
      tstInfoBuffer = AsnConvert.serialize(eContent);
    }

    const tstInfo = AsnConvert.parse(tstInfoBuffer, TSTInfo);

    // Extract TSA certificate if present
    let tsaCertificate: string | undefined;
    if (signedData.certificates && signedData.certificates.length > 0) {
      // Get the first certificate (usually the TSA cert)
      const cert = signedData.certificates[0];
      if ("certificate" in cert && cert.certificate) {
        tsaCertificate = arrayBufferToPEM(AsnConvert.serialize(cert.certificate));
      }
    }

    // Extract TSA name if present
    let tsaName: string | undefined;
    if (tstInfo.tsa) {
      if (tstInfo.tsa.directoryName) {
        tsaName = formatDirectoryName(tstInfo.tsa.directoryName);
      } else if (tstInfo.tsa.uniformResourceIdentifier) {
        tsaName = tstInfo.tsa.uniformResourceIdentifier;
      }
    }

    // Calculate accuracy in seconds (if provided)
    let accuracy: number | undefined;
    if (tstInfo.accuracy) {
      accuracy =
        (tstInfo.accuracy.seconds || 0) +
        (tstInfo.accuracy.millis || 0) / 1000 +
        (tstInfo.accuracy.micros || 0) / 1000000;
    }

    return {
      genTime: tstInfo.genTime,
      policy: tstInfo.policy,
      serialNumber: arrayBufferToHex(tstInfo.serialNumber),
      hashAlgorithm: getHashAlgorithmName(tstInfo.messageImprint.hashAlgorithm.algorithm),
      messageImprint: arrayBufferToHex(tstInfo.messageImprint.hashedMessage.buffer),
      tsaName,
      tsaCertificate,
      accuracy,
    };
  } catch (error) {
    console.error(
      "Failed to parse timestamp:",
      error instanceof Error ? error.message : String(error),
    );
    return null;
  }
}

/**
 * Compute hash of data using Web Crypto API
 */
async function computeHash(data: ArrayBuffer, algorithm: string): Promise<ArrayBuffer> {
  const algoMap: Record<string, string> = {
    "SHA-1": "SHA-1",
    "SHA-256": "SHA-256",
    "SHA-384": "SHA-384",
    "SHA-512": "SHA-512",
  };

  const webCryptoAlgo = algoMap[algorithm];
  if (!webCryptoAlgo) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }

  if (typeof crypto !== "undefined" && crypto.subtle) {
    return crypto.subtle.digest(webCryptoAlgo, data);
  }

  // Node.js fallback
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodeCrypto = require("crypto");
  const hash = nodeCrypto.createHash(algorithm.toLowerCase().replace("-", ""));
  hash.update(Buffer.from(data));
  return hash.digest().buffer;
}

/**
 * Verify that timestamp covers the signature value
 *
 * Per XAdES (ETSI EN 319 132-1), the SignatureTimeStamp covers the canonicalized
 * ds:SignatureValue XML element, not just its base64 content.
 *
 * @param timestampInfo Parsed timestamp info
 * @param canonicalSignatureValue Canonicalized ds:SignatureValue XML element
 * @returns True if the timestamp covers the signature
 */
export async function verifyTimestampCoversSignature(
  timestampInfo: TimestampInfo,
  canonicalSignatureValue: string,
): Promise<boolean> {
  try {
    const messageImprintLower = timestampInfo.messageImprint.toLowerCase();
    const encoder = new TextEncoder();

    const canonicalBytes = encoder.encode(canonicalSignatureValue);
    const canonicalHash = await computeHash(
      canonicalBytes.buffer as ArrayBuffer,
      timestampInfo.hashAlgorithm,
    );
    const canonicalHashHex = arrayBufferToHex(canonicalHash);

    return canonicalHashHex.toLowerCase() === messageImprintLower;
  } catch (error) {
    console.error(
      "Failed to verify timestamp coverage:",
      error instanceof Error ? error.message : String(error),
    );
    return false;
  }
}

/**
 * Verify an RFC 3161 timestamp token
 * @param timestampBase64 Base64-encoded timestamp token
 * @param options Verification options
 * @returns Timestamp verification result
 */
export async function verifyTimestamp(
  timestampBase64: string,
  options: TimestampVerificationOptions = {},
): Promise<TimestampVerificationResult> {
  // Parse the timestamp
  const info = parseTimestamp(timestampBase64);
  if (!info) {
    return {
      isValid: false,
      reason: "Failed to parse timestamp token",
    };
  }

  // Verify timestamp covers the signature if provided
  let coversSignature: boolean | undefined;
  let coversSignatureReason: string | undefined;
  if (options.canonicalSignatureValue) {
    coversSignature = await verifyTimestampCoversSignature(info, options.canonicalSignatureValue);
    if (!coversSignature) {
      coversSignatureReason = "Could not verify timestamp covers signature (hash mismatch)";
    }
  }

  // Verify TSA certificate if requested
  let tsaRevocation: RevocationResult | undefined;

  if (options.verifyTsaCertificate && info.tsaCertificate) {
    try {
      const tsaCert = new X509Certificate(info.tsaCertificate);

      // Check TSA certificate was valid at timestamp generation time
      if (info.genTime < tsaCert.notBefore || info.genTime > tsaCert.notAfter) {
        return {
          isValid: false,
          info,
          coversSignature,
          reason: `TSA certificate was not valid at timestamp time (${info.genTime.toISOString()})`,
        };
      }

      // Check TSA certificate revocation if requested
      if (options.checkTsaRevocation !== false) {
        try {
          tsaRevocation = await checkCertificateRevocation(tsaCert, options.revocationOptions);

          // If TSA certificate is revoked, the timestamp is invalid
          if (tsaRevocation.status === "revoked") {
            return {
              isValid: false,
              info,
              coversSignature,
              tsaRevocation,
              reason: `TSA certificate has been revoked: ${tsaRevocation.reason || "No reason provided"}`,
            };
          }
          // Note: 'unknown' status is a soft fail - timestamp remains valid
          // but user can check tsaRevocation.status to see the actual status
        } catch (error) {
          // Revocation check failed - soft fail, add to result but don't invalidate
          tsaRevocation = {
            isValid: false,
            status: "error",
            method: "none",
            reason: `TSA revocation check failed: ${error instanceof Error ? error.message : String(error)}`,
            checkedAt: new Date(),
          };
        }
      }
    } catch (error) {
      return {
        isValid: false,
        info,
        coversSignature,
        reason: `Failed to verify TSA certificate: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  return {
    isValid: true,
    info,
    coversSignature,
    tsaRevocation,
    reason: coversSignatureReason,
  };
}

/**
 * Get the trusted timestamp time from a signature
 * This should be used instead of the self-declared signingTime for certificate validation
 * @param timestampBase64 Base64-encoded timestamp token
 * @returns The timestamp generation time, or null if parsing fails
 */
export function getTimestampTime(timestampBase64: string): Date | null {
  const info = parseTimestamp(timestampBase64);
  return info?.genTime || null;
}
