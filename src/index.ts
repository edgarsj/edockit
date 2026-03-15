import { parseEdoc, SignatureInfo } from "./core/parser";
import {
  XMLCanonicalizer,
  CANONICALIZATION_METHODS,
} from "./core/canonicalization/XMLCanonicalizer";
import { parseCertificate, getSignerDisplayName, formatValidityPeriod } from "./core/certificate";
import {
  verifyChecksums,
  verifySignature,
  VerificationOptions,
  ChecksumVerificationResult,
  SignatureVerificationResult,
  CertificateVerificationResult,
  ValidationStatus,
  ValidationLimitation,
  ChecklistStatus,
  ChecklistCheck,
  ChecklistItem,
  VerificationResult,
} from "./core/verification";
import { checkCertificateRevocation } from "./core/revocation/check";
import { RevocationResult, RevocationCheckOptions } from "./core/revocation/types";
import { parseTimestamp, verifyTimestamp, getTimestampTime } from "./core/timestamp/verify";
import { TimestampInfo, TimestampVerificationResult } from "./core/timestamp/types";

export {
  // Core functionality
  parseEdoc,
  SignatureInfo,

  // Canonicalization
  XMLCanonicalizer,
  CANONICALIZATION_METHODS,

  // Certificate utilities
  parseCertificate,
  getSignerDisplayName,
  formatValidityPeriod,

  // Verification
  verifyChecksums,
  verifySignature,
  VerificationOptions,
  ChecksumVerificationResult,
  SignatureVerificationResult,
  CertificateVerificationResult,
  ValidationStatus,
  ValidationLimitation,
  ChecklistStatus,
  ChecklistCheck,
  ChecklistItem,
  VerificationResult,

  // Revocation checking
  checkCertificateRevocation,
  RevocationResult,
  RevocationCheckOptions,

  // Timestamp verification
  parseTimestamp,
  verifyTimestamp,
  getTimestampTime,
  TimestampInfo,
  TimestampVerificationResult,
};

export type { TrustedListFetchOptions } from "./core/trustedlist/types";
export type {
  TrustListProvider,
  TrustMatchConfidence,
  TrustListMatch,
  TrustListQuery,
  TrustListQueryPurpose,
} from "./core/trustedlist/contract";
