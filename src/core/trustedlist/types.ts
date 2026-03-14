export interface TrustedListSource {
  id: string;
  label: string;
  lotlUrl: string;
}

export type TrustMatchConfidence = "exact" | "aki_dn" | "dn_only";

export interface TrustListMatch {
  found: boolean;
  trustedAtSigningTime?: boolean;
  confidence?: TrustMatchConfidence;
  country?: string;
  tspName?: string;
  serviceType?: string;
  status?: string;
  source?: string;
  sourceLabel?: string;
  detail?: string;
}

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

export interface TslPointer {
  url: string;
  territory?: string;
  source: TrustedListSource;
}

export interface TrustedListIndexes {
  bySki: Map<string, TrustedService[]>;
  bySpkiSha256: Map<string, TrustedService[]>;
  bySubjectDn: Map<string, TrustedService[]>;
}

export interface TrustedListData {
  version: number;
  generatedAt: string;
  sources: TrustedListSource[];
  services: TrustedService[];
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

export interface MatchIssuerOptions {
  signingTime?: Date | null;
  allowWeakDnOnlyMatch?: boolean;
}

export type CompactTrustedHistory = [statusCode: number, fromIso: string, toIso: string | null];

export type CompactTrustedService = [
  skiHex: string | null,
  spkiSha256Hex: string,
  subjectDnIdx: number,
  country: string,
  tspNameIdx: number,
  serviceTypeCode: number,
  sourceCode: number,
  history: CompactTrustedHistory[],
];

export type CompactTrustedListSource = [id: string, label: string, lotlUrl: string];

export interface CompactTrustedListBundle {
  v: number;
  generatedAt: string;
  sources: CompactTrustedListSource[];
  codes: {
    serviceTypes: string[];
    statuses: string[];
  };
  strings: string[];
  services: CompactTrustedService[];
}

export interface TrustedListBundleManifest {
  schemaVersion: number;
  bundleId: string;
  generatedAt: string;
  url: string;
  sha256: string;
}
