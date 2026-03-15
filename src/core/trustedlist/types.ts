import type { TrustListQueryPurpose } from "./contract";

export type {
  TrustListMatch,
  TrustListProvider,
  TrustListQuery,
  TrustListQueryPurpose,
  TrustMatchConfidence,
} from "./contract";

export interface TrustedListSource {
  id: string;
  label: string;
  lotlUrl: string;
}

export type TrustListPurposeMask = 1 | 2 | 3;

export interface TrustedListFetchOptions {
  timeout?: number;
  proxyUrl?: string;
}

export interface TrustedStatusPeriod {
  status: string;
  from: string;
  to: string | null;
}

export interface TrustedService {
  skiHex: string | null;
  spkiSha256Hex: string;
  subjectDn: string;
  country: string;
  tspName: string;
  serviceType: string;
  source: string;
  sourceLabel: string;
  history: TrustedStatusPeriod[];
}

export interface TrustedServiceSnapshot {
  skiHex: string | null;
  spkiSha256Hex: string;
  subjectDn: string;
  country: string;
  tspName: string;
  serviceType: string;
  source: string;
  sourceLabel: string;
  status: string;
  startTime: string;
}

export interface TrustedTrustInterval {
  fromUnix: number;
  toUnix: number | null;
}

export interface TrustedListEntry {
  skiHex: string | null;
  spkiSha256Hex: string | null;
  subjectDn: string;
  country: string;
  purposeMask: TrustListPurposeMask;
  trustIntervals: TrustedTrustInterval[];
}

export interface TslPointer {
  url: string;
  territory?: string;
  source: TrustedListSource;
}

export interface TrustedListIndexes {
  bySki: Map<string, TrustedListEntry[]>;
  bySpkiSha256: Map<string, TrustedListEntry[]>;
  bySubjectDn: Map<string, TrustedListEntry[]>;
}

export interface TrustedListData {
  version: number;
  generatedAt: string;
  sources: TrustedListSource[];
  services: TrustedListEntry[];
  indexes: TrustedListIndexes;
}

export interface IssuerIdentity {
  issuerSubjectDn: string;
  authorityKeyIdentifierHex?: string | null;
  issuerCertificate?: {
    subjectDn: string;
    spkiSha256Hex: string;
  } | null;
}

export interface CertificateIdentity {
  subjectDn: string;
  subjectKeyIdentifierHex?: string | null;
  spkiSha256Hex?: string | null;
}

export interface MatchIssuerOptions {
  time: Date;
}

export interface MatchCertificateToTrustedListOptions {
  purpose?: TrustListQueryPurpose;
  time: Date;
  trustedListData: TrustedListData;
}

export type CompactTrustedInterval = [fromUnix: number, toUnix: number | null];

export type CompactTrustedService = [
  spkiSha256Base64Url: string | null,
  skiBase64Url: string | null,
  subjectDnIdx: number,
  country: string,
  purposeMask: TrustListPurposeMask,
  trustIntervals: CompactTrustedInterval[],
];

export type CompactTrustedListSource = [id: string, label: string, lotlUrl: string];

export interface CompactTrustedListBundle {
  v: 2;
  generatedAt: string;
  sources: CompactTrustedListSource[];
  dns: string[];
  services: CompactTrustedService[];
}

export interface TrustedListBundleManifest {
  schemaVersion: number;
  bundleId: string;
  generatedAt: string;
  url: string;
  sha256: string;
}
