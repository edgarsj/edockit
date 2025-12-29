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
}

/**
 * Default options for revocation checking
 */
export const DEFAULT_REVOCATION_OPTIONS: Required<
  Omit<RevocationCheckOptions, "certificateChain">
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
