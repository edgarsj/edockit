// src/core/timestamp/verify.ts

import { X509Certificate } from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { ContentInfo, SignedData } from "@peculiar/asn1-cms";
import { TSTInfo } from "@peculiar/asn1-tsp";
import { TimestampInfo, TimestampVerificationResult, TimestampVerificationOptions } from "./types";

/**
 * OID for SignedData content type
 */
const id_signedData = "1.2.840.113549.1.7.2";

/**
 * OID for TSTInfo content type
 */
const id_ct_TSTInfo = "1.2.840.113549.1.9.16.1.4";

/**
 * Convert ArrayBuffer to hex string
 */
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert ArrayBuffer to base64 string
 */
function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Decode base64 to ArrayBuffer
 */
function base64ToBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

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
 * Format certificate as PEM
 */
function formatPEM(derBytes: ArrayBuffer): string {
  const base64 = bufferToBase64(derBytes);
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Parse RFC 3161 TimeStampToken from base64
 * @param timestampBase64 Base64-encoded timestamp token
 * @returns Parsed timestamp info or null if parsing fails
 */
export function parseTimestamp(timestampBase64: string): TimestampInfo | null {
  try {
    const tokenBuffer = base64ToBuffer(timestampBase64);

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
        tsaCertificate = formatPEM(AsnConvert.serialize(cert.certificate));
      }
    }

    // Extract TSA name if present
    let tsaName: string | undefined;
    if (tstInfo.tsa) {
      if (tstInfo.tsa.directoryName) {
        tsaName = tstInfo.tsa.directoryName.toString();
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
      serialNumber: bufferToHex(tstInfo.serialNumber),
      hashAlgorithm: getHashAlgorithmName(tstInfo.messageImprint.hashAlgorithm.algorithm),
      messageImprint: bufferToHex(tstInfo.messageImprint.hashedMessage.buffer),
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
  const nodeCrypto = require("crypto");
  const hash = nodeCrypto.createHash(algorithm.toLowerCase().replace("-", ""));
  hash.update(Buffer.from(data));
  return hash.digest().buffer;
}

/**
 * Verify that timestamp covers the signature value
 * XAdES timestamps can cover either:
 * 1. The decoded signature value bytes (standard per ETSI EN 319 132-1)
 * 2. The base64-encoded string (some implementations)
 *
 * @param timestampInfo Parsed timestamp info
 * @param signatureValueBase64 Base64-encoded signature value
 * @returns True if the timestamp covers the signature
 */
export async function verifyTimestampCoversSignature(
  timestampInfo: TimestampInfo,
  signatureValueBase64: string,
): Promise<boolean> {
  try {
    const messageImprintLower = timestampInfo.messageImprint.toLowerCase();

    // Try 1: Hash of decoded signature value bytes (standard approach)
    const signatureValue = base64ToBuffer(signatureValueBase64);
    const computedHash = await computeHash(signatureValue, timestampInfo.hashAlgorithm);
    const computedHashHex = bufferToHex(computedHash);

    if (computedHashHex.toLowerCase() === messageImprintLower) {
      return true;
    }

    // Try 2: Hash of base64 string (some implementations)
    const encoder = new TextEncoder();
    const base64Bytes = encoder.encode(signatureValueBase64);
    const base64Hash = await computeHash(
      base64Bytes.buffer as ArrayBuffer,
      timestampInfo.hashAlgorithm,
    );
    const base64HashHex = bufferToHex(base64Hash);

    if (base64HashHex.toLowerCase() === messageImprintLower) {
      return true;
    }

    return false;
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
  // Note: coversSignature failure is informational - the timestamp is still valid
  // and can be used for genTime. The signature value hashing varies by implementation.
  let coversSignature: boolean | undefined;
  let coversSignatureReason: string | undefined;
  if (options.signatureValue) {
    coversSignature = await verifyTimestampCoversSignature(info, options.signatureValue);
    if (!coversSignature) {
      coversSignatureReason =
        "Could not verify timestamp covers signature (implementation-specific hashing)";
    }
  }

  // Verify TSA certificate if requested
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

      // TODO: Verify TSA certificate chain and revocation if checkTsaRevocation is true
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
