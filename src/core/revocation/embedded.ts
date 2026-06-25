// src/core/revocation/embedded.ts

import { X509Certificate } from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { OCSPResponse, OCSPResponseStatus, BasicOCSPResponse } from "@peculiar/asn1-ocsp";
import { RevocationResult } from "./types";
import { parseCRL, isSerialInCRL } from "./crl";
import { base64ToArrayBuffer, arrayBufferToHex } from "../../utils/encoding";

/**
 * Normalize a serial number (hex) for comparison: lowercase, no leading zeros.
 */
function normalizeSerial(hex: string): string {
  return hex.toLowerCase().replace(/^0+(?=.)/, "") || "0";
}

/**
 * Evaluate one embedded OCSP response (base64 DER) against the signer certificate.
 * Returns a definitive RevocationResult (good/revoked) or null if the response is
 * unusable / does not cover this certificate.
 */
function checkEmbeddedOCSPResponse(
  serialHex: string,
  base64Der: string,
  atTime: Date,
): RevocationResult | null {
  let responseData: ArrayBuffer;
  try {
    responseData = base64ToArrayBuffer(base64Der);
  } catch {
    return null;
  }

  try {
    const response = AsnConvert.parse(responseData, OCSPResponse);
    if (response.responseStatus !== OCSPResponseStatus.successful || !response.responseBytes) {
      return null;
    }

    const basicResponse = AsnConvert.parse(
      response.responseBytes.response.buffer,
      BasicOCSPResponse,
    );

    const target = normalizeSerial(serialHex);
    for (const single of basicResponse.tbsResponseData.responses) {
      if (normalizeSerial(arrayBufferToHex(single.certID.serialNumber)) !== target) {
        continue;
      }

      const certStatus = single.certStatus;
      if (certStatus.good !== undefined) {
        return {
          isValid: true,
          status: "good",
          method: "ocsp",
          fromEmbedded: true,
          reason: "Not revoked at signing time (embedded OCSP response)",
          checkedAt: atTime,
        };
      }
      if (certStatus.revoked) {
        return {
          isValid: false,
          status: "revoked",
          method: "ocsp",
          fromEmbedded: true,
          reason:
            certStatus.revoked.revocationReason !== undefined
              ? `Certificate revoked (reason: ${certStatus.revoked.revocationReason})`
              : "Certificate revoked",
          revokedAt: certStatus.revoked.revocationTime,
          checkedAt: atTime,
        };
      }
      // 'unknown' status: not definitive.
      return null;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Evaluate one embedded CRL (base64 DER) against the signer certificate.
 */
function checkEmbeddedCRL(
  serialHex: string,
  base64Der: string,
  atTime: Date,
): RevocationResult | null {
  let der: ArrayBuffer;
  try {
    der = base64ToArrayBuffer(base64Der);
  } catch {
    return null;
  }

  const crl = parseCRL(der);
  if (!crl) {
    return null;
  }

  const check = isSerialInCRL(crl, serialHex);
  if (check.isRevoked) {
    return {
      isValid: false,
      status: "revoked",
      method: "crl",
      fromEmbedded: true,
      reason:
        check.reason !== undefined
          ? `Certificate revoked (reason code: ${check.reason})`
          : "Certificate revoked",
      revokedAt: check.revokedAt,
      checkedAt: atTime,
    };
  }

  return {
    isValid: true,
    status: "good",
    method: "crl",
    fromEmbedded: true,
    reason: "Not revoked at signing time (embedded CRL)",
    checkedAt: atTime,
  };
}

/**
 * Check certificate revocation using embedded XAdES LTV material (OCSP first,
 * then CRL), evaluated at the given time. Returns a definitive result or null
 * when no embedded material conclusively covers the certificate (caller should
 * then fall back to a live OCSP/CRL check).
 *
 * @param cert Signer certificate to check
 * @param embedded Embedded OCSP/CRL values (base64-encoded DER)
 * @param atTime Evaluation moment ("at signing time")
 */
export function checkRevocationFromEmbedded(
  cert: X509Certificate,
  embedded: { ocsp?: string[]; crl?: string[] },
  atTime: Date,
): RevocationResult | null {
  const serialHex = cert.serialNumber;

  for (const base64Der of embedded.ocsp ?? []) {
    const result = checkEmbeddedOCSPResponse(serialHex, base64Der, atTime);
    if (result && (result.status === "good" || result.status === "revoked")) {
      return result;
    }
  }

  for (const base64Der of embedded.crl ?? []) {
    const result = checkEmbeddedCRL(serialHex, base64Der, atTime);
    if (result && (result.status === "good" || result.status === "revoked")) {
      return result;
    }
  }

  return null;
}
