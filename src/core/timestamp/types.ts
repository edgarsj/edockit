// src/core/timestamp/types.ts

import { RevocationResult, RevocationCheckOptions } from "../revocation/types";

/**
 * Parsed timestamp information from RFC 3161 TimeStampToken
 */
export interface TimestampInfo {
  /** The timestamp generation time (when TSA signed) */
  genTime: Date;
  /** TSA policy OID */
  policy: string;
  /** Serial number of the timestamp */
  serialNumber: string;
  /** Hash algorithm used for the message imprint */
  hashAlgorithm: string;
  /** The message imprint (hash of timestamped data) */
  messageImprint: string;
  /** TSA name (if provided) */
  tsaName?: string;
  /** TSA certificate (PEM format) */
  tsaCertificate?: string;
  /** Accuracy of the timestamp (in seconds) */
  accuracy?: number;
}

/**
 * Result of timestamp verification
 */
export interface TimestampVerificationResult {
  /** Whether the timestamp is valid */
  isValid: boolean;
  /** Parsed timestamp info (if parsing succeeded) */
  info?: TimestampInfo;
  /** Error or status message */
  reason?: string;
  /** Whether the timestamp covers the signature value correctly */
  coversSignature?: boolean;
  /** TSA certificate revocation check result (if checkTsaRevocation was enabled) */
  tsaRevocation?: RevocationResult;
}

/**
 * Options for timestamp verification
 */
export interface TimestampVerificationOptions {
  /** The signature value that the timestamp should cover (base64) */
  signatureValue?: string;
  /** Verify the TSA certificate chain */
  verifyTsaCertificate?: boolean;
  /** Check TSA certificate revocation */
  checkTsaRevocation?: boolean;
  /** Options for TSA certificate revocation checking (timeouts, proxy, etc.) */
  revocationOptions?: RevocationCheckOptions;
}
