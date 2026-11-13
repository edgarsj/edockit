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
  /**
   * TSA certificate (PEM format): the certificate identified by the token's
   * SignerInfo (issuerAndSerialNumber / subjectKeyIdentifier). Undefined when
   * no matching certificate was found.
   */
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
  /**
   * Whether the token's CMS signature and signed attributes (content-type,
   * message-digest, signing-certificate) verified against the TSA certificate
   */
  signatureValid?: boolean;
  /** TSA certificate revocation check result (if checkTsaRevocation was enabled) */
  tsaRevocation?: RevocationResult;
}

/**
 * Options for timestamp verification
 */
export interface TimestampVerificationOptions {
  /** The canonicalized ds:SignatureValue XML element (per XAdES spec) */
  canonicalSignatureValue?: string;
  /**
   * Additional candidate certificates (PEM or base64 DER) used to locate the TSA
   * certificate when the token does not embed it (e.g. XAdES CertificateValues)
   */
  certificates?: string[];
  /** Verify the TSA certificate chain */
  verifyTsaCertificate?: boolean;
  /** Check TSA certificate revocation */
  checkTsaRevocation?: boolean;
  /** Options for TSA certificate revocation checking (timeouts, proxy, etc.) */
  revocationOptions?: RevocationCheckOptions;
}
