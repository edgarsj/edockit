import type { TrustedQualificationPeriod } from "./types";

export type TrustListQueryPurpose = "signature_issuer" | "timestamp_tsa";

export type TrustMatchConfidence = "exact" | "ski_dn" | "dn_only";

export interface TrustListQuery {
  purpose: TrustListQueryPurpose;
  time: Date;
  spkiSha256Hex?: string | null;
  skiHex?: string | null;
  subjectDn?: string | null;
}

export interface TrustListMatch {
  found: boolean;
  trustedAtTime?: boolean;
  confidence?: TrustMatchConfidence;
  country?: string;
  /**
   * Id of the trusted-list source of the matched service. With the default
   * sources this is "eu" (EU/EEA national trusted lists) or "ades" (third-country
   * lists notified to the EU for AdES validation, which are not equivalent to
   * EU qualified status).
   */
  source?: string;
  sourceLabel?: string;
  detail?: string;
  /**
   * Granted CA/QC periods of the matched service(s), used to determine whether
   * the certificates the issuer issued are qualified. Only set for exact
   * signature-issuer matches when the trusted-list data carries qualification
   * data (version 3 bundles); an empty array means the matched service was
   * never a granted CA/QC service.
   */
  qualificationPeriods?: TrustedQualificationPeriod[];
}

export interface TrustListProvider {
  match(query: TrustListQuery): Promise<TrustListMatch>;
}
