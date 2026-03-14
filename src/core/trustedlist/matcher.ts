import { AuthorityKeyIdentifierExtension, X509Certificate } from "@peculiar/x509";
import { findIssuerInChain, fetchIssuerFromAIA } from "../revocation/ocsp";
import { arrayBufferToHex } from "../../utils/encoding";
import { getBundledTrustedListData } from "./loader";
import {
  isTrustedServiceStatus,
  normalizeDistinguishedName,
  normalizeHex,
  normalizeKeyIdentifier,
} from "./normalize";
import type {
  IssuerIdentity,
  MatchIssuerOptions,
  TrustListMatch,
  TrustedListData,
  TrustedListFetchOptions,
  TrustedService,
} from "./types";

const AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";

export interface MatchCertificateIssuerToTrustedListOptions extends MatchIssuerOptions {
  certificateChain?: string[];
  trustedListData?: TrustedListData;
  fetchOptions?: TrustedListFetchOptions;
}

function getHistoryStatusAtTime(service: TrustedService, signingTime: Date) {
  const timestamp = signingTime.getTime();

  return (
    service.history.find((period) => {
      const from = new Date(period.from).getTime();
      const to = period.to ? new Date(period.to).getTime() : Number.POSITIVE_INFINITY;
      return timestamp >= from && timestamp < to;
    }) || null
  );
}

function buildPositiveDetail(service: TrustedService, confidence: "exact" | "aki_dn" | "dn_only") {
  if (confidence === "exact") {
    return `${service.tspName} - ${service.sourceLabel} (exact issuer SPKI match, trusted on signing date)`;
  }

  if (confidence === "aki_dn") {
    return `${service.tspName} - ${service.sourceLabel} (AKI/SKI + DN, trusted on signing date)`;
  }

  return `${service.tspName} - ${service.sourceLabel} (issuer DN match, trusted on signing date)`;
}

function buildTrustMatch(
  service: TrustedService,
  confidence: "exact" | "aki_dn" | "dn_only",
  signingTime?: Date | null,
  allowWeakDnOnlyMatch: boolean = false,
): TrustListMatch {
  if (!signingTime) {
    return {
      found: true,
      confidence,
      country: service.country,
      tspName: service.tspName,
      serviceType: service.serviceType,
      source: service.source,
      sourceLabel: service.sourceLabel,
      detail: "Matching issuer found, but signing time was not provided",
    };
  }

  if (confidence === "dn_only" && !allowWeakDnOnlyMatch) {
    // DN-only matches are intentionally left indeterminate: the name match is too weak to
    // make either a positive or negative trust assertion, even if the matched service history
    // happens to contain an active withdrawn/deprecated status at the signing time.
    return {
      found: true,
      confidence,
      country: service.country,
      tspName: service.tspName,
      serviceType: service.serviceType,
      source: service.source,
      sourceLabel: service.sourceLabel,
      detail:
        "Only issuer DN matched trusted-list data; no AKI/SKI or issuer certificate match available",
    };
  }

  const activeStatus = getHistoryStatusAtTime(service, signingTime);
  if (!activeStatus) {
    return {
      found: true,
      confidence,
      country: service.country,
      tspName: service.tspName,
      serviceType: service.serviceType,
      source: service.source,
      sourceLabel: service.sourceLabel,
      detail: "Matching issuer found, but service was not in trusted status on the signing date",
      trustedAtSigningTime: false,
    };
  }

  const trustedAtSigningTime = isTrustedServiceStatus(activeStatus.status);

  return {
    found: true,
    trustedAtSigningTime,
    confidence,
    country: service.country,
    tspName: service.tspName,
    serviceType: service.serviceType,
    status: activeStatus.status,
    source: service.source,
    sourceLabel: service.sourceLabel,
    detail: trustedAtSigningTime
      ? buildPositiveDetail(service, confidence)
      : "Matching issuer found, but service was not in trusted status on the signing date",
  };
}

function pickBestServiceMatch(
  services: TrustedService[],
  confidence: "exact" | "aki_dn" | "dn_only",
  options: MatchIssuerOptions,
): TrustListMatch {
  const { signingTime, allowWeakDnOnlyMatch = false } = options;

  if (!signingTime) {
    return buildTrustMatch(services[0], confidence, signingTime, allowWeakDnOnlyMatch);
  }

  const activeServices = services
    .map((service) => ({
      service,
      activeStatus: getHistoryStatusAtTime(service, signingTime),
    }))
    .filter((item) => item.activeStatus);

  const trustedActiveService = activeServices.find((item) =>
    isTrustedServiceStatus(item.activeStatus!.status),
  );
  if (trustedActiveService) {
    return buildTrustMatch(
      trustedActiveService.service,
      confidence,
      signingTime,
      allowWeakDnOnlyMatch,
    );
  }

  if (activeServices.length > 0) {
    return buildTrustMatch(
      activeServices[0].service,
      confidence,
      signingTime,
      allowWeakDnOnlyMatch,
    );
  }

  return buildTrustMatch(services[0], confidence, signingTime, allowWeakDnOnlyMatch);
}

async function computeSha256Hex(input: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", input);
  return arrayBufferToHex(digest);
}

function getAuthorityKeyIdentifierHex(certificate: X509Certificate): string | null {
  const authorityKeyIdentifier = certificate.getExtension(
    AUTHORITY_KEY_IDENTIFIER_OID,
  ) as AuthorityKeyIdentifierExtension | null;

  return normalizeKeyIdentifier(authorityKeyIdentifier?.keyId);
}

function filterServicesBySubjectDn(
  services: TrustedService[] | undefined,
  subjectDn: string,
): TrustedService[] {
  return (services || []).filter((service) => service.subjectDn === subjectDn);
}

export function matchIssuerIdentityToTrustedList(
  issuerIdentity: IssuerIdentity,
  trustedListData: TrustedListData = getBundledTrustedListData(),
  options: MatchIssuerOptions = {},
): TrustListMatch {
  const normalizedSubjectDn = normalizeDistinguishedName(issuerIdentity.issuerSubjectDn);
  const issuerCertificate = issuerIdentity.issuerCertificate
    ? {
        subjectDn: normalizeDistinguishedName(issuerIdentity.issuerCertificate.subjectDn),
        spkiSha256Hex: normalizeHex(issuerIdentity.issuerCertificate.spkiSha256Hex) || "",
      }
    : null;
  const authorityKeyIdentifierHex = normalizeKeyIdentifier(
    issuerIdentity.authorityKeyIdentifierHex,
  );

  if (issuerCertificate) {
    const exactMatches = filterServicesBySubjectDn(
      trustedListData.indexes.bySpkiSha256.get(issuerCertificate.spkiSha256Hex),
      issuerCertificate.subjectDn,
    );

    if (exactMatches.length > 0) {
      return pickBestServiceMatch(exactMatches, "exact", options);
    }
  }

  if (authorityKeyIdentifierHex) {
    const akiMatches = filterServicesBySubjectDn(
      trustedListData.indexes.bySki.get(authorityKeyIdentifierHex),
      normalizedSubjectDn,
    );

    if (akiMatches.length > 0) {
      return pickBestServiceMatch(akiMatches, "aki_dn", options);
    }
  }

  const dnOnlyMatches = trustedListData.indexes.bySubjectDn.get(normalizedSubjectDn) || [];
  if (dnOnlyMatches.length > 0) {
    return pickBestServiceMatch(dnOnlyMatches, "dn_only", options);
  }

  return {
    found: false,
    detail: "No matching issuer found in trusted-list data",
  };
}

export async function extractIssuerIdentityFromCertificate(
  certificatePem: string,
  options: Omit<MatchCertificateIssuerToTrustedListOptions, "trustedListData" | "signingTime"> = {},
): Promise<IssuerIdentity> {
  const signerCertificate = new X509Certificate(certificatePem);
  let issuerCertificate =
    options.certificateChain && options.certificateChain.length > 0
      ? findIssuerInChain(signerCertificate, options.certificateChain)
      : null;

  if (!issuerCertificate && options.fetchOptions) {
    issuerCertificate = await fetchIssuerFromAIA(
      signerCertificate,
      options.fetchOptions.timeout,
      options.fetchOptions.proxyUrl,
    );
  }

  return {
    issuerSubjectDn: normalizeDistinguishedName(signerCertificate.issuer),
    authorityKeyIdentifierHex: getAuthorityKeyIdentifierHex(signerCertificate),
    issuerCertificate: issuerCertificate
      ? {
          subjectDn: normalizeDistinguishedName(issuerCertificate.subject),
          spkiSha256Hex: await computeSha256Hex(issuerCertificate.publicKey.rawData),
        }
      : null,
  };
}

export async function matchCertificateIssuerToTrustedList(
  certificatePem: string,
  options: MatchCertificateIssuerToTrustedListOptions = {},
): Promise<TrustListMatch> {
  const issuerIdentity = await extractIssuerIdentityFromCertificate(certificatePem, options);

  return matchIssuerIdentityToTrustedList(
    issuerIdentity,
    options.trustedListData || getBundledTrustedListData(),
    {
      signingTime: options.signingTime,
      allowWeakDnOnlyMatch: options.allowWeakDnOnlyMatch,
    },
  );
}
