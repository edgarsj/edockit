export type {
  TrustListMatch,
  TrustListProvider,
  TrustListQuery,
  TrustListQueryPurpose,
  TrustMatchConfidence,
} from "./core/trustedlist/contract";

export {
  base64UrlToHex,
  getTrustListPurposeMaskForQueryPurpose,
  getTrustListPurposeMaskForServiceType,
  hexToBase64Url,
  isTrustedServiceStatus,
  normalizeDistinguishedName,
  normalizeHex,
  normalizeKeyIdentifier,
  trustListPurposeMatchesMask,
} from "./core/trustedlist/normalize";

export {
  extractCertificateIdentityFromCertificate,
  extractIssuerIdentityFromCertificate,
} from "./core/trustedlist/identity";

export { buildTrustedListData, createEmptyTrustedListBundle } from "./core/trustedlist/loader";

export {
  matchCertificateIssuerToTrustedList,
  matchCertificateToTrustedList,
  matchIssuerIdentityToTrustedList,
  matchTrustListQuery,
} from "./core/trustedlist/matcher";

export type { MatchCertificateIssuerToTrustedListOptions } from "./core/trustedlist/matcher";

export { createTrustListProvider } from "./core/trustedlist/reference-provider";
export type {
  CreateTrustListProviderFromDataOptions,
  CreateTrustListProviderFromUrlOptions,
  CreateTrustListProviderOptions,
} from "./core/trustedlist/reference-provider";

export type {
  CertificateIdentity,
  CompactTrustedInterval,
  CompactTrustedListBundle,
  CompactTrustedListSource,
  CompactTrustedService,
  IssuerIdentity,
  MatchCertificateToTrustedListOptions,
  MatchIssuerOptions,
  TrustListPurposeMask,
  TrustedListData,
  TrustedListEntry,
  TrustedListIndexes,
  TrustedListSource,
  TrustedTrustInterval,
} from "./core/trustedlist/types";
