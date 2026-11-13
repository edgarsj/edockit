// src/core/revocation/crl.ts

import {
  X509Certificate,
  X509Crl,
  CRLDistributionPointsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
} from "@peculiar/x509";
import { AsnParser } from "@peculiar/asn1-schema";
import { CertificateList } from "@peculiar/asn1-x509";
import { fromBER } from "asn1js";
import { RevocationResult, MAX_URLS_PER_CERTIFICATE, REVOCATION_CLOCK_SKEW_MS } from "./types";
import { fetchCRL, DEFAULT_MAX_CRL_BYTES } from "./fetch";
import { resolveIssuerCertificate } from "./ocsp";
import { arrayBufferToBase64, base64ToArrayBuffer } from "../../utils/encoding";

/**
 * OID for CRL Distribution Points extension
 */
const id_ce_cRLDistributionPoints = "2.5.29.31";

/**
 * OID for Key Usage extension
 */
const id_ce_keyUsage = "2.5.29.15";

/**
 * OID for Delta CRL Indicator extension
 */
const id_ce_deltaCRLIndicator = "2.5.29.27";

/**
 * Upper bound on ASN.1 nodes when parsing large CRLs.
 *
 * asn1js enforces a DoS guard (DEFAULT_MAX_NODES = 10000) that rejects national
 * CRLs with tens of thousands of revoked entries (e.g. the Latvian LV eID ICA
 * CRL has ~13k entries -> well over 10k nodes). @peculiar/x509's X509Crl does not
 * expose the limit, so the large-CRL fallback in parseCRL() raises it here while
 * still keeping a realistic ceiling so a maliciously huge CRL is rejected.
 */
const MAX_CRL_ASN1_NODES = 5_000_000;

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
              const lower = url.toLowerCase();
              if (lower.startsWith("http://") || lower.startsWith("https://")) {
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
 * Convert CRL bytes to a DER ArrayBuffer, decoding from PEM if necessary.
 */
function crlBytesToDer(data: ArrayBuffer): ArrayBuffer {
  // Detect a PEM armor by inspecting the leading bytes ("-----BEGIN").
  const head = new Uint8Array(data, 0, Math.min(data.byteLength, 16));
  let prefix = "";
  for (const byte of head) {
    prefix += String.fromCharCode(byte);
  }

  if (prefix.includes("-----BEGIN")) {
    const pem = new TextDecoder().decode(data);
    const base64 = pem
      .replace(/-----BEGIN[^-]+-----/g, "")
      .replace(/-----END[^-]+-----/g, "")
      .replace(/\s+/g, "");
    return base64ToArrayBuffer(base64);
  }

  return data;
}

/**
 * Parse a large CRL that exceeds asn1js's default node cap.
 *
 * X509Crl's constructor parses with asn1js defaults, so we decode the DER
 * ourselves with a raised (but bounded) node limit and then hand the already
 * decoded structure to X509Crl, which accepts a CertificateList directly.
 */
function parseLargeCRL(data: ArrayBuffer): X509Crl | null {
  try {
    const der = crlBytesToDer(data);
    const asn1 = fromBER(der, { maxNodes: MAX_CRL_ASN1_NODES });
    if (asn1.offset === -1 || !asn1.result) {
      return null;
    }
    const certList = AsnParser.fromASN(asn1.result, CertificateList);
    return new X509Crl(certList);
  } catch {
    return null;
  }
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
      // National CRLs can exceed asn1js's default node cap; retry with a raised limit.
      return parseLargeCRL(data);
    }
  }
}

/**
 * Options for validating a CRL
 */
export interface CRLValidationOptions {
  /** Time to validate against (default: now) */
  now?: Date;
  /** Allowed clock difference in ms (default: REVOCATION_CLOCK_SKEW_MS) */
  clockSkewMs?: number;
}

/**
 * Validate that a CRL was issued by `issuer` for `cert` and is current.
 *
 * Checks the issuer name, the CRL signature against the issuer key, the
 * issuer's cRLSign key usage (when a key usage extension is present), and
 * thisUpdate/nextUpdate. Delta CRLs are not supported.
 *
 * @returns null when the CRL is usable, otherwise a reason
 */
export async function validateCRL(
  crl: X509Crl,
  cert: X509Certificate,
  issuer: X509Certificate,
  options: CRLValidationOptions = {},
): Promise<string | null> {
  const now = (options.now ?? new Date()).getTime();
  const skewMs = options.clockSkewMs ?? REVOCATION_CLOCK_SKEW_MS;

  if (crl.issuer !== cert.issuer || crl.issuer !== issuer.subject) {
    return "CRL issuer does not match the certificate issuer";
  }

  const keyUsage = issuer.getExtension(id_ce_keyUsage) as KeyUsagesExtension | null;
  if (keyUsage && (keyUsage.usages & KeyUsageFlags.cRLSign) === 0) {
    return "Issuer certificate is not allowed to sign CRLs";
  }

  if (crl.getExtension(id_ce_deltaCRLIndicator)) {
    return "Delta CRLs are not supported";
  }

  let signatureOk = false;
  try {
    signatureOk = await crl.verify({ publicKey: issuer.publicKey });
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) {
    return "CRL signature does not verify with the issuer key";
  }

  if (crl.thisUpdate.getTime() > now + skewMs) {
    return "CRL thisUpdate is in the future";
  }
  if (!crl.nextUpdate) {
    return "CRL has no nextUpdate";
  }
  if (crl.nextUpdate.getTime() < now - skewMs) {
    return `CRL is stale (nextUpdate ${crl.nextUpdate.toISOString()})`;
  }

  return null;
}

/**
 * Check certificate revocation via CRL
 * @param cert Certificate to check
 * @param options CRL check options. The issuer certificate is needed to verify
 *   the CRL; if not supplied it is resolved from `certificateChain` or AIA.
 * @returns Revocation result
 */
export async function checkCRL(
  cert: X509Certificate,
  options: {
    timeout?: number;
    proxyUrl?: string;
    issuerCertificate?: X509Certificate | null;
    certificateChain?: string[];
    maxBytes?: number;
  } = {},
): Promise<RevocationResult> {
  const { timeout = 10000, proxyUrl, certificateChain, maxBytes = DEFAULT_MAX_CRL_BYTES } = options;
  const now = new Date();

  // Get CRL URLs
  const crlUrls = extractCRLUrls(cert).slice(0, MAX_URLS_PER_CERTIFICATE);
  if (crlUrls.length === 0) {
    return {
      isValid: false,
      status: "unknown",
      method: "crl",
      reason: "Certificate has no CRL distribution point",
      checkedAt: now,
    };
  }

  const issuer =
    options.issuerCertificate ??
    (await resolveIssuerCertificate(cert, { certificateChain, timeout, proxyUrl }));
  if (!issuer) {
    return {
      isValid: false,
      status: "unknown",
      method: "crl",
      reason: "Could not find or fetch issuer certificate to verify the CRL",
      checkedAt: now,
    };
  }

  // Try each CRL URL
  const errors: string[] = [];
  let validationProblem = false;

  for (const url of crlUrls) {
    try {
      const result = await fetchCRL(url, timeout, proxyUrl, maxBytes);

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

      const problem = await validateCRL(crl, cert, issuer);
      if (problem) {
        validationProblem = true;
        errors.push(`${url}: ${problem}`);
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

      // Certificate not in a verified, current CRL = good
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
    status: validationProblem ? "unknown" : "error",
    method: "crl",
    reason: `All CRL checks failed: ${errors.join("; ")}`,
    checkedAt: now,
  };
}
