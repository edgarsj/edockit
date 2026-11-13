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
  /**
   * Extra attempts for a LOTL/TSL endpoint that fails to fetch (network error,
   * timeout, non-2xx). Defaults to 1.
   */
  retries?: number;
  /**
   * Trusted lists are not signature-verified by the builder, so their integrity
   * relies on TLS. By default `http://` LOTL/TSL locations are upgraded to
   * `https://`; set this to `true` to fetch them over plain HTTP instead.
   */
  allowInsecureHttp?: boolean;
}

export interface TrustedStatusPeriod {
  status: string;
  from: string;
  to: string | null;
  /** AdditionalServiceInformation URIs of this history period */
  additionalServiceInfo?: string[];
  /** Qualifications extension elements of this history period */
  qualifications?: QualificationElement[];
}

/**
 * Criteria of a trusted-list QualificationElement (ETSI TS 119 612, 5.5.9.2).
 * A certificate matches when the criteria hold according to `assert`.
 */
export interface QualificationCriteriaList {
  assert: "all" | "atLeastOne" | "none";
  /** Each entry is one KeyUsage criterion: key usage bit name -> required value */
  keyUsage?: Array<Record<string, boolean>>;
  /** Each entry is one PolicySet: the certificate must contain all of these policy OIDs */
  policySets?: string[][];
  /** Each entry is one ExtendedKeyUsage criterion: all of these key purpose OIDs */
  extendedKeyUsage?: string[][];
  /** Each entry is one CertSubjectDNAttribute criterion: all of these attribute OIDs */
  subjectDnAttributes?: string[][];
  criteriaLists?: QualificationCriteriaList[];
  /** The list contains criteria this library does not evaluate */
  unsupported?: boolean;
}

export interface QualificationElement {
  /** Qualifier URI suffixes, e.g. "QCWithQSCD", "QCForESig", "NotQualified" */
  qualifiers: string[];
  criteria: QualificationCriteriaList;
}

/**
 * A period in which a CA/QC service was in a granted (or pre-eIDAS
 * equivalent) status, with the information needed to determine whether the
 * certificates it issued are qualified.
 */
export interface TrustedQualificationPeriod {
  fromUnix: number;
  toUnix: number | null;
  forESignatures: boolean;
  forESeals: boolean;
  forWebSiteAuthentication: boolean;
  qualifications: QualificationElement[];
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
  additionalServiceInfo?: string[];
  qualifications?: QualificationElement[];
}

export interface TrustedTrustInterval {
  fromUnix: number;
  toUnix: number | null;
}

export interface TrustedListEntry {
  /** Hex SKI; only available from version 2 bundles */
  skiHex: string | null;
  /**
   * Lookup key of the service certificate's public key: the first 24
   * base64url characters (144 bits) of SHA-256 over the SubjectPublicKeyInfo.
   * See `getSpkiKey`.
   */
  spkiKey: string | null;
  subjectDn: string;
  country: string;
  /** Id of the LOTL source the service was published through (e.g. "eu", "ades") */
  source?: string;
  sourceLabel?: string;
  purposeMask: TrustListPurposeMask;
  trustIntervals: TrustedTrustInterval[];
  /**
   * Granted CA/QC periods with qualification data. Undefined when the bundle
   * carries no qualification data (version 2 bundles).
   */
  qualificationPeriods?: TrustedQualificationPeriod[];
}

export interface TslPointer {
  url: string;
  territory?: string;
  source: TrustedListSource;
}

export interface TrustedListIndexes {
  bySki: Map<string, TrustedListEntry[]>;
  bySpkiKey: Map<string, TrustedListEntry[]>;
  bySubjectDn: Map<string, TrustedListEntry[]>;
}

export interface TrustedListData {
  version: number;
  /** Stable identifier for this snapshot, derived from generatedAt. */
  bundleId?: string;
  generatedAt: string;
  sources: TrustedListSource[];
  services: TrustedListEntry[];
  indexes: TrustedListIndexes;
}

export interface IssuerIdentity {
  issuerSubjectDn: string;
  authorityKeyIdentifierHex?: string | null;
  /**
   * True when the issuer certificate named by the certificate (matching subject
   * DN and authority key identifier) was available, but its key did not verify
   * the certificate's signature.
   */
  issuerSignatureMismatch?: boolean;
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

/**
 * Granted CA/QC period: [fromUnix, toUnix, additionalServiceInfoMask, qualIdxs].
 * The mask has bit 1 = ForeSignatures, 2 = ForeSeals, 4 = ForWebSiteAuthentication.
 * `qualIdxs` index into the bundle's `quals` codebook.
 */
export type CompactQualificationPeriod = [
  fromUnix: number,
  toUnix: number | null,
  additionalServiceInfoMask: number,
  qualIdxs?: number[],
];

/** Codebook entry: [qualifiers, criteria] */
export type CompactQualificationElement = [
  qualifiers: string[],
  criteria: QualificationCriteriaList,
];

export type CompactTrustedService = [
  /**
   * v3: first 24 base64url characters of SHA-256(SPKI) (see `getSpkiKey`).
   * v2: the full base64url SHA-256(SPKI).
   */
  spkiKey: string | null,
  /** v2 only (base64url SKI); always null in v3 */
  skiBase64Url: string | null,
  subjectDnIdx: number,
  country: string,
  purposeMask: TrustListPurposeMask,
  trustIntervals: CompactTrustedInterval[],
  /** Index into `sources` of the LOTL the service was published through (optional for older bundles) */
  sourceIdx?: number,
  /** v3: granted CA/QC periods with qualification data */
  qualificationPeriods?: CompactQualificationPeriod[],
];

export type CompactTrustedListSource = [id: string, label: string, lotlUrl: string];

export interface CompactTrustedListBundle {
  /**
   * 3: truncated SPKI keys, no SKI, normalized DNs and qualification data.
   * 2: full SPKI hashes and SKIs (still readable).
   */
  v: 2 | 3;
  /** Stable identifier for this snapshot, derived from generatedAt. */
  bundleId?: string;
  generatedAt: string;
  sources: CompactTrustedListSource[];
  dns: string[];
  /** v3: qualification element codebook referenced by `CompactQualificationPeriod` */
  quals?: CompactQualificationElement[];
  services: CompactTrustedService[];
}

export interface TrustedListBundleManifest {
  schemaVersion: number;
  bundleId: string;
  generatedAt: string;
  url: string;
  sha256: string;
}
