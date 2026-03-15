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
  detail?: string;
}

export interface TrustListProvider {
  match(query: TrustListQuery): Promise<TrustListMatch>;
}
