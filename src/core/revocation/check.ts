// src/core/revocation/check.ts

import { X509Certificate } from "@peculiar/x509";
import { RevocationResult, RevocationCheckOptions, DEFAULT_REVOCATION_OPTIONS } from "./types";
import { checkOCSP } from "./ocsp";
import { checkCRL } from "./crl";

/**
 * Check certificate revocation status using OCSP (primary) and CRL (fallback)
 *
 * Strategy:
 * 1. Try OCSP first (faster, real-time)
 * 2. If OCSP fails or returns unknown, try CRL as fallback
 * 3. If both fail, return 'unknown' status (soft fail)
 *
 * @param cert Certificate to check (X509Certificate or PEM string)
 * @param options Revocation check options
 * @returns RevocationResult with status and details
 */
export async function checkCertificateRevocation(
  cert: X509Certificate | string,
  options: RevocationCheckOptions = {},
): Promise<RevocationResult> {
  const now = new Date();

  // Merge with defaults
  const opts = {
    ...DEFAULT_REVOCATION_OPTIONS,
    ...options,
  };

  // Parse certificate if string
  let x509Cert: X509Certificate;
  try {
    x509Cert = typeof cert === "string" ? new X509Certificate(cert) : cert;
  } catch (error) {
    return {
      isValid: false,
      status: "error",
      method: "none",
      reason: `Failed to parse certificate: ${error instanceof Error ? error.message : String(error)}`,
      checkedAt: now,
    };
  }

  // Track results from attempted methods
  let ocspResult: RevocationResult | null = null;
  let crlResult: RevocationResult | null = null;

  // Try OCSP first
  if (opts.ocspEnabled) {
    ocspResult = await checkOCSP(x509Cert, null, {
      timeout: opts.ocspTimeout,
      certificateChain: opts.certificateChain,
      proxyUrl: options.proxyUrl,
    });

    // If OCSP gives a definitive answer (good or revoked), use it
    if (ocspResult.status === "good" || ocspResult.status === "revoked") {
      return ocspResult;
    }

    // OCSP returned unknown or error - try CRL as fallback
  }

  // Try CRL
  if (opts.crlEnabled) {
    crlResult = await checkCRL(x509Cert, {
      timeout: opts.crlTimeout,
      proxyUrl: options.proxyUrl,
    });

    // If CRL gives a definitive answer, use it
    if (crlResult.status === "good" || crlResult.status === "revoked") {
      return crlResult;
    }
  }

  // Both methods failed or disabled - return consistent structure
  const errors: string[] = [];
  if (ocspResult?.reason) errors.push(`OCSP: ${ocspResult.reason}`);
  if (crlResult?.reason) errors.push(`CRL: ${crlResult.reason}`);

  return {
    isValid: false,
    status: "unknown",
    method: "none",
    reason: errors.length > 0 ? errors.join("; ") : "No revocation checking method available",
    checkedAt: now,
  };
}

/**
 * Check multiple certificates' revocation status
 * @param certs Array of certificates (X509Certificate or PEM strings)
 * @param options Revocation check options
 * @returns Array of RevocationResults in same order as input
 */
export async function checkCertificatesRevocation(
  certs: (X509Certificate | string)[],
  options: RevocationCheckOptions = {},
): Promise<RevocationResult[]> {
  return Promise.all(certs.map((cert) => checkCertificateRevocation(cert, options)));
}
