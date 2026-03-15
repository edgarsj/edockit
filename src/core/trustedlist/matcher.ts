import {
  trustListPurposeMatchesMask,
  normalizeDistinguishedName,
  normalizeHex,
  normalizeKeyIdentifier,
} from "./normalize";
import {
  extractCertificateIdentityFromCertificate,
  extractIssuerIdentityFromCertificate,
} from "./identity";
import type { TrustListMatch, TrustListQuery, TrustListQueryPurpose } from "./contract";
import type {
  IssuerIdentity,
  MatchCertificateToTrustedListOptions,
  MatchIssuerOptions,
  TrustedListData,
  TrustedListEntry,
  TrustedListFetchOptions,
} from "./types";

export interface MatchCertificateIssuerToTrustedListOptions extends MatchIssuerOptions {
  certificateChain?: string[];
  trustedListData: TrustedListData;
  fetchOptions?: TrustedListFetchOptions;
}

function getTrustIntervalAtTime(service: TrustedListEntry, time: Date) {
  const timeUnix = Math.floor(time.getTime() / 1000);

  return (
    service.trustIntervals.find((interval) => {
      const intervalEnd = interval.toUnix ?? Number.POSITIVE_INFINITY;
      return timeUnix >= interval.fromUnix && timeUnix < intervalEnd;
    }) || null
  );
}

function getMatchSubjectLabel(purpose: TrustListQueryPurpose): string {
  return purpose === "signature_issuer" ? "issuer" : "timestamp authority";
}

function buildPositiveDetail(
  purpose: TrustListQueryPurpose,
  confidence: "exact" | "ski_dn" | "dn_only",
): string {
  if (purpose === "signature_issuer") {
    if (confidence === "exact") {
      return "Trusted-list issuer match by SPKI, trusted at the requested time";
    }

    if (confidence === "ski_dn") {
      return "Trusted-list issuer match by SKI + DN, trusted at the requested time";
    }

    return "Trusted-list issuer match by DN, trusted at the requested time";
  }

  if (confidence === "exact") {
    return "Trusted-list timestamp authority match by certificate SPKI, trusted at the requested time";
  }

  if (confidence === "ski_dn") {
    return "Trusted-list timestamp authority match by SKI + DN, trusted at the requested time";
  }

  return "Trusted-list timestamp authority match by DN, trusted at the requested time";
}

function buildWeakDnOnlyDetail(purpose: TrustListQueryPurpose): string {
  return purpose === "signature_issuer"
    ? "Only issuer DN matched trusted-list data; no SKI or issuer certificate SPKI match available"
    : "Only timestamp authority DN matched trusted-list data; no SKI or certificate SPKI match available";
}

function buildTrustMatch(
  service: TrustedListEntry,
  query: TrustListQuery,
  confidence: "exact" | "ski_dn" | "dn_only",
): TrustListMatch {
  if (!query.time) {
    return {
      found: true,
      confidence,
      country: service.country,
      detail: `Matching ${getMatchSubjectLabel(query.purpose)} found, but no verification time was provided`,
    };
  }

  const activeInterval = getTrustIntervalAtTime(service, query.time);
  if (!activeInterval) {
    return {
      found: true,
      confidence,
      country: service.country,
      detail: `Matching ${getMatchSubjectLabel(query.purpose)} found, but service was not trusted at the requested time`,
      trustedAtTime: false,
    };
  }

  return {
    found: true,
    trustedAtTime: true,
    confidence,
    country: service.country,
    detail:
      confidence === "dn_only"
        ? buildWeakDnOnlyDetail(query.purpose)
        : buildPositiveDetail(query.purpose, confidence),
  };
}

function pickBestServiceMatch(
  services: TrustedListEntry[],
  query: TrustListQuery,
  confidence: "exact" | "ski_dn" | "dn_only",
): TrustListMatch {
  if (!query.time) {
    return buildTrustMatch(services[0], query, confidence);
  }

  const trustedService = services.find((service) => getTrustIntervalAtTime(service, query.time));
  if (trustedService) {
    return buildTrustMatch(trustedService, query, confidence);
  }

  return buildTrustMatch(services[0], query, confidence);
}

function filterServicesByPurpose(
  services: TrustedListEntry[] | undefined,
  purpose: TrustListQueryPurpose,
): TrustedListEntry[] {
  return (services || []).filter((service) =>
    trustListPurposeMatchesMask(purpose, service.purposeMask),
  );
}

function filterServicesBySubjectDn(
  services: TrustedListEntry[] | undefined,
  subjectDn?: string | null,
): TrustedListEntry[] {
  if (!subjectDn) {
    return services || [];
  }

  return (services || []).filter((service) => service.subjectDn === subjectDn);
}

export function matchTrustListQuery(
  query: TrustListQuery,
  trustedListData: TrustedListData,
): TrustListMatch {
  const normalizedSubjectDn = normalizeDistinguishedName(query.subjectDn);
  const normalizedSpkiSha256Hex = normalizeHex(query.spkiSha256Hex);
  const normalizedSkiHex = normalizeKeyIdentifier(query.skiHex);

  if (normalizedSpkiSha256Hex) {
    const exactMatches = filterServicesBySubjectDn(
      filterServicesByPurpose(
        trustedListData.indexes.bySpkiSha256.get(normalizedSpkiSha256Hex),
        query.purpose,
      ),
      normalizedSubjectDn,
    );

    if (exactMatches.length > 0) {
      return pickBestServiceMatch(
        exactMatches,
        {
          ...query,
          spkiSha256Hex: normalizedSpkiSha256Hex,
          subjectDn: normalizedSubjectDn,
        },
        "exact",
      );
    }
  }

  if (normalizedSkiHex && normalizedSubjectDn) {
    const skiMatches = filterServicesBySubjectDn(
      filterServicesByPurpose(trustedListData.indexes.bySki.get(normalizedSkiHex), query.purpose),
      normalizedSubjectDn,
    );

    if (skiMatches.length > 0) {
      return pickBestServiceMatch(
        skiMatches,
        {
          ...query,
          skiHex: normalizedSkiHex,
          subjectDn: normalizedSubjectDn,
        },
        "ski_dn",
      );
    }
  }

  if (normalizedSubjectDn) {
    const dnOnlyMatches = filterServicesByPurpose(
      trustedListData.indexes.bySubjectDn.get(normalizedSubjectDn),
      query.purpose,
    );

    if (dnOnlyMatches.length > 0) {
      return pickBestServiceMatch(
        dnOnlyMatches,
        {
          ...query,
          subjectDn: normalizedSubjectDn,
        },
        "dn_only",
      );
    }
  }

  return {
    found: false,
    detail: `No matching ${getMatchSubjectLabel(query.purpose)} found in trusted-list data`,
  };
}

export function matchIssuerIdentityToTrustedList(
  issuerIdentity: IssuerIdentity,
  trustedListData: TrustedListData,
  options: MatchIssuerOptions,
): TrustListMatch {
  const issuerCertificate = issuerIdentity.issuerCertificate
    ? {
        subjectDn: normalizeDistinguishedName(issuerIdentity.issuerCertificate.subjectDn),
        spkiSha256Hex: normalizeHex(issuerIdentity.issuerCertificate.spkiSha256Hex),
      }
    : null;

  return matchTrustListQuery(
    {
      purpose: "signature_issuer",
      subjectDn: issuerIdentity.issuerSubjectDn,
      skiHex: issuerIdentity.authorityKeyIdentifierHex,
      spkiSha256Hex: issuerCertificate?.spkiSha256Hex,
      time: options.time,
    },
    trustedListData,
  );
}

export async function matchCertificateIssuerToTrustedList(
  certificatePem: string,
  options: MatchCertificateIssuerToTrustedListOptions,
): Promise<TrustListMatch> {
  const issuerIdentity = await extractIssuerIdentityFromCertificate(certificatePem, options);

  return matchIssuerIdentityToTrustedList(issuerIdentity, options.trustedListData, {
    time: options.time,
  });
}

export async function matchCertificateToTrustedList(
  certificatePem: string,
  options: MatchCertificateToTrustedListOptions,
): Promise<TrustListMatch> {
  const certificateIdentity = await extractCertificateIdentityFromCertificate(certificatePem);

  return matchTrustListQuery(
    {
      purpose: options.purpose || "timestamp_tsa",
      subjectDn: certificateIdentity.subjectDn,
      skiHex: certificateIdentity.subjectKeyIdentifierHex,
      spkiSha256Hex: certificateIdentity.spkiSha256Hex,
      time: options.time,
    },
    options.trustedListData,
  );
}
