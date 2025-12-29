import { parseEdoc, SignatureInfo } from "./core/parser";
import {
  XMLCanonicalizer,
  CANONICALIZATION_METHODS,
} from "./core/canonicalization/XMLCanonicalizer";
import { parseCertificate, getSignerDisplayName, formatValidityPeriod } from "./core/certificate";
import { verifyChecksums, verifySignature } from "./core/verification";
import {
  checkCertificateRevocation,
  RevocationResult,
  RevocationCheckOptions,
} from "./core/revocation";

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

  // Revocation checking
  checkCertificateRevocation,
  RevocationResult,
  RevocationCheckOptions,
};
