// src/core/revocation/types.ts

/**
 * Result of a certificate revocation check
 */
export interface RevocationResult {
  /** Whether the certificate passed revocation check (not revoked) */
  isValid: boolean;
  /** Revocation status */
  status: "good" | "revoked" | "unknown" | "error";
  /** Method used to check revocation */
  method?: "ocsp" | "crl" | "none";
  /** Human-readable reason for the status */
  reason?: string;
  /** Date when certificate was revoked (if revoked) */
  revokedAt?: Date;
  /** When this revocation check was performed */
  checkedAt: Date;
}

/**
 * Options for revocation checking
 */
export interface RevocationCheckOptions {
  /** Enable OCSP checking (default: true) */
  ocspEnabled?: boolean;
  /** Enable CRL checking as fallback (default: true) */
  crlEnabled?: boolean;
  /** Timeout for OCSP requests in ms (default: 5000) */
  ocspTimeout?: number;
  /** Timeout for CRL requests in ms (default: 10000) */
  crlTimeout?: number;
  /** Certificate chain for finding issuer (PEM strings) */
  certificateChain?: string[];
  /**
   * CORS proxy URL for browser environments.
   * When set, all OCSP/CRL fetch requests will be routed through this proxy.
   * The original URL will be URL-encoded and appended as a query parameter.
   * Example: "https://cors-proxy.example.com/?url="
   */
  proxyUrl?: string;
  /** Maximum CRL download size in bytes (default: 10 MB) */
  crlMaxBytes?: number;
  /** Maximum OCSP response size in bytes (default: 1 MB) */
  ocspMaxBytes?: number;
}

/**
 * Default options for revocation checking
 */
export const DEFAULT_REVOCATION_OPTIONS: Required<
  Omit<RevocationCheckOptions, "certificateChain" | "proxyUrl">
> = {
  ocspEnabled: true,
  crlEnabled: true,
  ocspTimeout: 5000,
  crlTimeout: 10000,
  crlMaxBytes: 10 * 1024 * 1024,
  ocspMaxBytes: 1024 * 1024,
};

/**
 * Maximum number of OCSP, CRL or CA Issuers URLs tried per certificate.
 * URLs come from the certificate itself, so the number of requests is bounded.
 */
export const MAX_URLS_PER_CERTIFICATE = 3;

/**
 * Allowed clock difference when checking OCSP/CRL validity times (ms)
 */
export const REVOCATION_CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * OID constants for certificate extensions
 */
export const OID = {
  /** Authority Information Access */
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  /** CRL Distribution Points */
  crlDistributionPoints: "2.5.29.31",
  /** OCSP access method */
  ocsp: "1.3.6.1.5.5.7.48.1",
  /** CA Issuers access method */
  caIssuers: "1.3.6.1.5.5.7.48.2",
} as const;
