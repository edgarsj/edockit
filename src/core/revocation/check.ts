// src/core/revocation/check.ts

import { X509Certificate } from "@peculiar/x509";
import { RevocationResult, RevocationCheckOptions, DEFAULT_REVOCATION_OPTIONS } from "./types";
import { checkOCSP, extractOCSPUrls, resolveIssuerCertificate } from "./ocsp";
import { checkCRL, extractCRLUrls } from "./crl";

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

  // The issuer certificate is needed to build OCSP requests and to verify OCSP
  // responses and CRLs. Resolve it once, only if a method will use it.
  let issuerLookup: Promise<X509Certificate | null> | undefined;
  const getIssuer = () => {
    if (!issuerLookup) {
      issuerLookup = resolveIssuerCertificate(x509Cert, {
        certificateChain: opts.certificateChain,
        timeout: opts.ocspTimeout,
        proxyUrl: options.proxyUrl,
      });
    }
    return issuerLookup;
  };
  const issuerUnavailable = (method: "ocsp" | "crl"): RevocationResult => ({
    isValid: false,
    status: "unknown",
    method,
    reason: "Could not find or fetch issuer certificate",
    checkedAt: now,
  });

  // Try OCSP first
  if (opts.ocspEnabled) {
    const hasOcspUrls = extractOCSPUrls(x509Cert).length > 0;
    const issuer = hasOcspUrls ? await getIssuer() : null;
    ocspResult =
      hasOcspUrls && !issuer
        ? issuerUnavailable("ocsp")
        : await checkOCSP(x509Cert, issuer, {
            timeout: opts.ocspTimeout,
            certificateChain: opts.certificateChain,
            proxyUrl: options.proxyUrl,
            maxBytes: opts.ocspMaxBytes,
          });

    // If OCSP gives a definitive answer (good or revoked), use it
    if (ocspResult.status === "good" || ocspResult.status === "revoked") {
      return ocspResult;
    }

    // OCSP returned unknown or error - try CRL as fallback
  }

  // Try CRL
  if (opts.crlEnabled) {
    const hasCrlUrls = extractCRLUrls(x509Cert).length > 0;
    const issuer = hasCrlUrls ? await getIssuer() : null;
    crlResult =
      hasCrlUrls && !issuer
        ? issuerUnavailable("crl")
        : await checkCRL(x509Cert, {
            timeout: opts.crlTimeout,
            proxyUrl: options.proxyUrl,
            issuerCertificate: issuer,
            maxBytes: opts.crlMaxBytes,
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
