// src/core/revocation/crl.ts

import { X509Certificate, X509Crl, CRLDistributionPointsExtension } from "@peculiar/x509";
import { RevocationResult } from "./types";
import { fetchCRL } from "./fetch";
import { arrayBufferToBase64 } from "../../utils/encoding";

/**
 * OID for CRL Distribution Points extension
 */
const id_ce_cRLDistributionPoints = "2.5.29.31";

/**
 * Extract CRL distribution point URLs from certificate
 * @param cert X509Certificate to extract CRL URLs from
 * @returns Array of CRL distribution URLs
 */
export function extractCRLUrls(cert: X509Certificate): string[] {
  try {
    const crlExt = cert.getExtension(
      id_ce_cRLDistributionPoints,
    ) as CRLDistributionPointsExtension | null;

    if (!crlExt) {
      return [];
    }

    const urls: string[] = [];

    for (const dp of crlExt.distributionPoints) {
      // Check distributionPoint field
      if (dp.distributionPoint) {
        const dpName = dp.distributionPoint;
        // fullName contains GeneralNames
        if ("fullName" in dpName && dpName.fullName) {
          for (const gn of dpName.fullName) {
            // uniformResourceIdentifier is the URL
            if (gn.uniformResourceIdentifier) {
              const url = gn.uniformResourceIdentifier;
              // Only include HTTP(S) URLs - skip LDAP and other protocols
              if (url.startsWith("http://") || url.startsWith("https://")) {
                urls.push(url);
              }
            }
          }
        }
      }
    }

    return urls;
  } catch {
    return [];
  }
}

/**
 * Check if a certificate serial number is in the CRL
 * @param crl X509Crl to check
 * @param serialNumber Certificate serial number (hex string)
 * @returns Object with isRevoked status and optional revocation date
 */
export function isSerialInCRL(
  crl: X509Crl,
  serialNumber: string,
): { isRevoked: boolean; revokedAt?: Date; reason?: number } {
  // Normalize serial number (remove leading zeros but keep at least one digit, lowercase)
  const normalizedSerial = serialNumber.toLowerCase().replace(/^0+(?=.)/, "") || "0";

  for (const entry of crl.entries) {
    const entrySerial = entry.serialNumber.toLowerCase().replace(/^0+(?=.)/, "") || "0";
    if (entrySerial === normalizedSerial) {
      return {
        isRevoked: true,
        revokedAt: entry.revocationDate,
        reason: entry.reason,
      };
    }
  }

  return { isRevoked: false };
}

/**
 * Parse CRL from DER or PEM data
 * @param data CRL data (DER or PEM)
 * @returns X509Crl or null if parsing fails
 */
export function parseCRL(data: ArrayBuffer): X509Crl | null {
  try {
    // Try parsing as DER first
    return new X509Crl(data);
  } catch {
    try {
      // Try converting to PEM
      const base64 = arrayBufferToBase64(data);
      const lines = base64.match(/.{1,64}/g) || [];
      const pem = `-----BEGIN X509 CRL-----\n${lines.join("\n")}\n-----END X509 CRL-----`;
      return new X509Crl(pem);
    } catch {
      return null;
    }
  }
}

/**
 * Check certificate revocation via CRL
 * @param cert Certificate to check
 * @param options CRL check options
 * @returns Revocation result
 */
export async function checkCRL(
  cert: X509Certificate,
  options: { timeout?: number; proxyUrl?: string } = {},
): Promise<RevocationResult> {
  const { timeout = 10000, proxyUrl } = options;
  const now = new Date();

  // Get CRL URLs
  const crlUrls = extractCRLUrls(cert);
  if (crlUrls.length === 0) {
    return {
      isValid: false,
      status: "unknown",
      method: "crl",
      reason: "Certificate has no CRL distribution point",
      checkedAt: now,
    };
  }

  // Try each CRL URL
  const errors: string[] = [];

  for (const url of crlUrls) {
    try {
      const result = await fetchCRL(url, timeout, proxyUrl);

      if (!result.ok || !result.data) {
        errors.push(`${url}: ${result.error || "Failed to fetch"}`);
        continue;
      }

      // Parse CRL
      const crl = parseCRL(result.data);
      if (!crl) {
        errors.push(`${url}: Failed to parse CRL data`);
        continue;
      }

      // Check if certificate serial is in CRL
      const revocationCheck = isSerialInCRL(crl, cert.serialNumber);

      if (revocationCheck.isRevoked) {
        return {
          isValid: false,
          status: "revoked",
          method: "crl",
          reason:
            revocationCheck.reason !== undefined
              ? `Certificate revoked (reason code: ${revocationCheck.reason})`
              : "Certificate revoked",
          revokedAt: revocationCheck.revokedAt,
          checkedAt: now,
        };
      }

      // Certificate not in CRL = good
      return {
        isValid: true,
        status: "good",
        method: "crl",
        checkedAt: now,
      };
    } catch (error) {
      errors.push(`${url}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // All CRL checks failed
  return {
    isValid: false,
    status: "error",
    method: "crl",
    reason: `All CRL checks failed: ${errors.join("; ")}`,
    checkedAt: now,
  };
}
