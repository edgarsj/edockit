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
  /**
   * True when the result came from embedded XAdES LTV material (OCSP/CRL captured
   * at signing time) rather than a live OCSP/CRL fetch.
   */
  fromEmbedded?: boolean;
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
   * Embedded XAdES OCSP responses (base64-encoded DER) captured at signing time.
   * Tried before any live OCSP/CRL fetch so revocation can be evaluated offline.
   */
  embeddedOCSP?: string[];
  /**
   * Embedded XAdES CRLs (base64-encoded DER) captured at signing time.
   * Tried (after embedded OCSP) before any live fetch.
   */
  embeddedCRL?: string[];
  /**
   * Evaluation moment for revocation ("at signing time"), typically the trusted
   * timestamp time. Used when checking embedded material. Defaults to now.
   */
  atTime?: Date;
  /**
   * CORS proxy URL for browser environments.
   * When set, all OCSP/CRL fetch requests will be routed through this proxy.
   * The original URL will be URL-encoded and appended as a query parameter.
   * Example: "https://cors-proxy.example.com/?url="
   */
  proxyUrl?: string;
}

/**
 * Default options for revocation checking
 */
export const DEFAULT_REVOCATION_OPTIONS: Required<
  Omit<
    RevocationCheckOptions,
    "certificateChain" | "proxyUrl" | "embeddedOCSP" | "embeddedCRL" | "atTime"
  >
> = {
  ocspEnabled: true,
  crlEnabled: true,
  ocspTimeout: 5000,
  crlTimeout: 10000,
};

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
