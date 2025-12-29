// src/core/revocation/index.ts

// Main exports
export { checkCertificateRevocation, checkCertificatesRevocation } from "./check";

// Types
export { RevocationResult, RevocationCheckOptions, DEFAULT_REVOCATION_OPTIONS, OID } from "./types";

// OCSP utilities (for advanced usage)
export { extractOCSPUrls, extractCAIssuersUrls, findIssuerInChain, checkOCSP } from "./ocsp";

// CRL utilities (for advanced usage)
export { extractCRLUrls, checkCRL } from "./crl";
