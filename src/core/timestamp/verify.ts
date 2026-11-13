// src/core/timestamp/verify.ts

import { X509Certificate } from "@peculiar/x509";
import { Name } from "@peculiar/asn1-x509";
import { TimestampInfo, TimestampVerificationResult, TimestampVerificationOptions } from "./types";
import {
  DecodedTimestampToken,
  RawCertificate,
  decodeTimestampToken,
  findSignerCertificate,
  getHashAlgorithmName,
  toRawCertificate,
  verifyTokenSignature,
} from "./cms";
import { checkCertificateRevocation } from "../revocation/check";
import { RevocationResult } from "../revocation/types";
import { arrayBufferToHex, arrayBufferToPEM } from "../../utils/encoding";

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

function certificateToPEM(cert: RawCertificate): string {
  const der = cert.der;
  return arrayBufferToPEM(
    der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer,
  );
}

/**
 * Build the public TimestampInfo from a decoded token
 * @param tsaCertificate The certificate identified by the SignerInfo (if any)
 */
function buildTimestampInfo(
  token: DecodedTimestampToken,
  tsaCertificate: RawCertificate | undefined,
): TimestampInfo {
  const { tstInfo } = token;

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
    tsaCertificate: tsaCertificate ? certificateToPEM(tsaCertificate) : undefined,
    accuracy,
  };
}

/**
 * Parse RFC 3161 TimeStampToken from base64
 *
 * This only decodes the token; it does not verify its signature. Use
 * verifyTimestamp() before relying on any of the returned values.
 * `tsaCertificate` is the embedded certificate referenced by the SignerInfo
 * (issuerAndSerialNumber or subjectKeyIdentifier), if present.
 *
 * @param timestampBase64 Base64-encoded timestamp token
 * @returns Parsed timestamp info or null if parsing fails
 */
export function parseTimestamp(timestampBase64: string): TimestampInfo | null {
  try {
    const token = decodeTimestampToken(timestampBase64);
    const signerInfo = token.signerInfos[0];
    const tsaCertificate = signerInfo
      ? findSignerCertificate(signerInfo.sid, token.certificates)
      : undefined;
    return buildTimestampInfo(token, tsaCertificate);
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
 * Note: this only compares the message imprint; it does not check the token
 * signature. verifyTimestamp() performs both checks.
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
 *
 * The token is valid only when:
 * - the TSA certificate referenced by the SignerInfo can be located (in the
 *   token or in options.certificates)
 * - the CMS signature verifies with that certificate's public key, the signed
 *   content-type is id-ct-TSTInfo, the message-digest matches the TSTInfo, and
 *   any ESS signing-certificate attribute matches the TSA certificate
 * - the TSA certificate has the id-kp-timeStamping extended key usage
 * - the message imprint matches options.canonicalSignatureValue (when given)
 * - with verifyTsaCertificate: the TSA certificate was within its validity
 *   period at genTime and is not revoked
 *
 * Whether the TSA itself is trusted is not decided here; callers should check
 * info.tsaCertificate against a trust source (e.g. the EU trusted lists).
 *
 * @param timestampBase64 Base64-encoded timestamp token
 * @param options Verification options
 * @returns Timestamp verification result
 */
export async function verifyTimestamp(
  timestampBase64: string,
  options: TimestampVerificationOptions = {},
): Promise<TimestampVerificationResult> {
  let token: DecodedTimestampToken;
  try {
    token = decodeTimestampToken(timestampBase64);
  } catch (error) {
    console.error(
      "Failed to parse timestamp:",
      error instanceof Error ? error.message : String(error),
    );
    return {
      isValid: false,
      reason: "Failed to parse timestamp token",
    };
  }

  const extraCertificates: RawCertificate[] = [];
  for (const cert of options.certificates ?? []) {
    try {
      extraCertificates.push(toRawCertificate(cert));
    } catch {
      // Ignore unparseable candidates; they cannot be the TSA certificate
    }
  }

  // Verify the CMS signature and identify the TSA certificate
  const tokenCheck = await verifyTokenSignature(token, extraCertificates);
  const info = buildTimestampInfo(token, tokenCheck.tsaCertificate);
  const signatureValid = tokenCheck.signatureValid;

  const problems: string[] = [];
  if (!signatureValid) {
    problems.push(tokenCheck.reason || "Timestamp token signature is invalid");
  }

  // RFC 3161 2.3: the TSA certificate must carry the id-kp-timeStamping EKU.
  // A certificate without it is not authorised to issue timestamps, so the
  // token is treated as invalid (all known qualified TSAs set it).
  if (tokenCheck.tsaCertificate && !tokenCheck.hasTimeStampingUsage) {
    problems.push("TSA certificate does not have the timeStamping extended key usage");
  }

  // Verify timestamp covers the signature if provided
  let coversSignature: boolean | undefined;
  if (options.canonicalSignatureValue) {
    coversSignature = await verifyTimestampCoversSignature(info, options.canonicalSignatureValue);
    if (!coversSignature) {
      problems.push("Could not verify timestamp covers signature (hash mismatch)");
    }
  }

  if (problems.length > 0) {
    return {
      isValid: false,
      info,
      coversSignature,
      signatureValid,
      reason: problems.join("; "),
    };
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
          signatureValid,
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
              signatureValid,
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
        signatureValid,
        reason: `Failed to verify TSA certificate: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  return {
    isValid: true,
    info,
    coversSignature,
    signatureValid,
    tsaRevocation,
  };
}

/**
 * Get the timestamp time from a signature
 *
 * Note: this only decodes the token. The returned time should only be treated
 * as trusted after verifyTimestamp() has returned isValid: true.
 *
 * @param timestampBase64 Base64-encoded timestamp token
 * @returns The timestamp generation time, or null if parsing fails
 */
export function getTimestampTime(timestampBase64: string): Date | null {
  const info = parseTimestamp(timestampBase64);
  return info?.genTime || null;
}
