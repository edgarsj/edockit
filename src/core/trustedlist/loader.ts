import type {
  CompactQualificationElement,
  CompactQualificationPeriod,
  CompactTrustedInterval,
  CompactTrustedListBundle,
  CompactTrustedService,
  QualificationElement,
  TrustedQualificationPeriod,
  TrustedListData,
  TrustedListEntry,
  TrustedListIndexes,
  TrustedListSource,
  TrustedService,
  TrustedStatusPeriod,
  TrustedTrustInterval,
} from "./types";
import {
  base64UrlToHex,
  getSpkiKey,
  getTrustListPurposeMaskForServiceType,
  isQualifiedServiceStatus,
  isTrustedServiceStatus,
  normalizeDistinguishedName,
  normalizeHex,
  SPKI_KEY_LENGTH,
} from "./normalize";
import {
  ASI_FOR_ESEALS,
  ASI_FOR_ESIGNATURES,
  ASI_FOR_WEBSITE_AUTHENTICATION,
  getAdditionalServiceInfoMask,
} from "./qualifications";

function addToIndex(
  index: Map<string, TrustedListEntry[]>,
  key: string | null,
  service: TrustedListEntry,
) {
  if (!key) {
    return;
  }

  const normalizedKey = key.trim();
  if (!normalizedKey) {
    return;
  }

  const existing = index.get(normalizedKey);
  if (existing) {
    existing.push(service);
    return;
  }

  index.set(normalizedKey, [service]);
}

function buildIndexes(services: TrustedListEntry[]): TrustedListIndexes {
  const indexes: TrustedListIndexes = {
    bySki: new Map<string, TrustedListEntry[]>(),
    bySpkiKey: new Map<string, TrustedListEntry[]>(),
    bySubjectDn: new Map<string, TrustedListEntry[]>(),
  };

  for (const service of services) {
    addToIndex(indexes.bySki, normalizeHex(service.skiHex), service);
    addToIndex(indexes.bySpkiKey, service.spkiKey, service);
    addToIndex(indexes.bySubjectDn, service.subjectDn, service);
  }

  return indexes;
}

function dedupeHistory(history: TrustedStatusPeriod[]): TrustedStatusPeriod[] {
  const deduped: TrustedStatusPeriod[] = [];

  for (const item of history) {
    const previous = deduped[deduped.length - 1];
    if (
      previous &&
      previous.status === item.status &&
      previous.from === item.from &&
      previous.to === item.to
    ) {
      continue;
    }

    deduped.push(item);
  }

  return deduped;
}

function parseTimestampToUnixSeconds(input: string): number {
  const parsedDate = new Date(input);
  if (Number.isNaN(parsedDate.getTime())) {
    throw new Error(`Invalid trusted-list timestamp "${input}"`);
  }

  return Math.floor(parsedDate.getTime() / 1000);
}

function mergeCompactIntervals(intervals: CompactTrustedInterval[]): CompactTrustedInterval[] {
  const merged: CompactTrustedInterval[] = [];

  for (const [fromUnix, toUnix] of intervals) {
    const previous = merged[merged.length - 1];
    if (!previous) {
      merged.push([fromUnix, toUnix]);
      continue;
    }

    const previousToUnix = previous[1];
    if (previousToUnix === null || fromUnix <= previousToUnix) {
      previous[1] =
        previousToUnix === null || toUnix === null ? null : Math.max(previousToUnix, toUnix);
      continue;
    }

    merged.push([fromUnix, toUnix]);
  }

  return merged;
}

function collapseTrustedIntervals(history: TrustedStatusPeriod[]): CompactTrustedInterval[] {
  const trustedIntervals = history
    .filter((entry) => isTrustedServiceStatus(entry.status))
    .map<CompactTrustedInterval>((entry) => [
      parseTimestampToUnixSeconds(entry.from),
      entry.to ? parseTimestampToUnixSeconds(entry.to) : null,
    ]);

  return mergeCompactIntervals(trustedIntervals);
}

function hydrateTrustIntervals(trustIntervals: CompactTrustedInterval[]): TrustedTrustInterval[] {
  return trustIntervals.map(([fromUnix, toUnix]) => ({
    fromUnix,
    toUnix,
  }));
}

function sortCompactServices(left: CompactTrustedService, right: CompactTrustedService): number {
  const leftKey = JSON.stringify(left);
  const rightKey = JSON.stringify(right);
  return leftKey.localeCompare(rightKey);
}

/**
 * Derive a stable, filesystem/URL-safe bundle id from a generatedAt timestamp,
 * e.g. "2026-06-25T18:30:00.000Z" -> "2026-06-25T18-30-00Z".
 */
export function formatTrustedListBundleId(generatedAt: string): string {
  const parsedDate = new Date(generatedAt);

  if (Number.isNaN(parsedDate.getTime())) {
    throw new Error(`Invalid trusted-list generatedAt timestamp "${generatedAt}"`);
  }

  return parsedDate
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z")
    .replace(/:/g, "-");
}

export function createEmptyTrustedListBundle(): CompactTrustedListBundle {
  const generatedAt = new Date(0).toISOString();
  return {
    v: 3,
    bundleId: formatTrustedListBundleId(generatedAt),
    generatedAt,
    sources: [],
    dns: [],
    quals: [],
    services: [],
  };
}

function hydrateQualificationElement([
  qualifiers,
  criteria,
]: CompactQualificationElement): QualificationElement {
  return { qualifiers, criteria };
}

function hydrateQualificationPeriods(
  periods: CompactQualificationPeriod[],
  qualifications: QualificationElement[],
): TrustedQualificationPeriod[] {
  return periods.map(([fromUnix, toUnix, additionalServiceInfoMask, qualIdxs]) => ({
    fromUnix,
    toUnix,
    forESignatures: (additionalServiceInfoMask & ASI_FOR_ESIGNATURES) !== 0,
    forESeals: (additionalServiceInfoMask & ASI_FOR_ESEALS) !== 0,
    forWebSiteAuthentication: (additionalServiceInfoMask & ASI_FOR_WEBSITE_AUTHENTICATION) !== 0,
    qualifications: (qualIdxs ?? []).map((index) => {
      const element = qualifications[index];
      if (!element) {
        throw new Error(`Trusted list bundle contains unknown qualification code ${index}`);
      }
      return element;
    }),
  }));
}

/**
 * Hydrate a compact bundle (version 2 or 3) into indexed runtime data.
 *
 * Version 3 bundles are produced by `buildCompactTrustedListBundle`, which
 * stores DNs already normalized, so they are used as-is.
 */
export function buildTrustedListData(bundle: CompactTrustedListBundle): TrustedListData {
  const isV3 = bundle.v === 3;
  const dns = isV3 ? bundle.dns : bundle.dns.map((dn) => normalizeDistinguishedName(dn));
  const qualifications = (bundle.quals ?? []).map(hydrateQualificationElement);

  const services: TrustedListEntry[] = bundle.services.map((serviceRecord) => {
    const [
      spkiKey,
      skiBase64Url,
      subjectDnIdx,
      country,
      purposeMask,
      trustIntervals,
      sourceIdx,
      qualificationPeriods,
    ] = serviceRecord;
    const source = sourceIdx !== undefined ? bundle.sources[sourceIdx] : undefined;

    const subjectDn = dns[subjectDnIdx];
    if (subjectDn === undefined) {
      throw new Error(`Trusted list bundle contains unknown DN code ${subjectDnIdx}`);
    }

    return {
      skiHex: isV3 ? null : base64UrlToHex(skiBase64Url),
      spkiKey: spkiKey ? spkiKey.slice(0, SPKI_KEY_LENGTH) : null,
      subjectDn,
      country,
      ...(source ? { source: source[0], sourceLabel: source[1] } : {}),
      purposeMask,
      trustIntervals: hydrateTrustIntervals(trustIntervals),
      ...(isV3
        ? {
            qualificationPeriods: hydrateQualificationPeriods(
              qualificationPeriods ?? [],
              qualifications,
            ),
          }
        : {}),
    };
  });

  return {
    version: bundle.v,
    bundleId: bundle.bundleId ?? formatTrustedListBundleId(bundle.generatedAt),
    generatedAt: bundle.generatedAt,
    sources: bundle.sources.map(([id, label, lotlUrl]) => ({
      id,
      label,
      lotlUrl,
    })),
    services,
    indexes: buildIndexes(services),
  };
}

/**
 * Sort periods and merge adjacent or overlapping ones that carry the same
 * service information (consecutive history entries often differ only in their
 * status date).
 */
function sortAndMergeQualificationPeriods(
  periods: CompactQualificationPeriod[],
): CompactQualificationPeriod[] {
  const sorted = [...periods].sort(
    (left, right) =>
      left[0] - right[0] || JSON.stringify(left).localeCompare(JSON.stringify(right)),
  );
  const merged: CompactQualificationPeriod[] = [];

  for (const period of sorted) {
    const previous = merged[merged.length - 1];
    const sameInformation =
      previous &&
      previous[2] === period[2] &&
      JSON.stringify(previous[3] ?? []) === JSON.stringify(period[3] ?? []);
    if (sameInformation && (previous[1] === null || period[0] <= previous[1])) {
      previous[1] =
        previous[1] === null || period[1] === null ? null : Math.max(previous[1], period[1]);
      continue;
    }
    merged.push([...period] as CompactQualificationPeriod);
  }

  return merged;
}

class QualificationCodebook {
  readonly entries: CompactQualificationElement[] = [];
  private readonly indexByKey = new Map<string, number>();

  add(element: CompactQualificationElement): number {
    const key = JSON.stringify(element);
    let index = this.indexByKey.get(key);
    if (index === undefined) {
      index = this.entries.length;
      this.entries.push(element);
      this.indexByKey.set(key, index);
    }
    return index;
  }
}

function buildQualificationPeriods(
  service: TrustedService,
  codebook: QualificationCodebook,
): CompactQualificationPeriod[] {
  if (service.serviceType !== "CA/QC") {
    return [];
  }

  return service.history
    .filter((entry) => isQualifiedServiceStatus(entry.status))
    .map<CompactQualificationPeriod>((entry) => {
      const qualIdxs = [
        ...new Set(
          (entry.qualifications ?? []).map((element) =>
            codebook.add([element.qualifiers, element.criteria]),
          ),
        ),
      ].sort((left, right) => left - right);
      return [
        parseTimestampToUnixSeconds(entry.from),
        entry.to ? parseTimestampToUnixSeconds(entry.to) : null,
        getAdditionalServiceInfoMask(entry.additionalServiceInfo),
        ...(qualIdxs.length > 0 ? [qualIdxs] : []),
      ] as CompactQualificationPeriod;
    });
}

function compactServiceRecord(
  spkiKey: string | null,
  subjectDnIdx: number,
  country: string,
  purposeMask: CompactTrustedService[4],
  trustIntervals: CompactTrustedInterval[],
  sourceIdx: number | undefined,
  qualificationPeriods: CompactQualificationPeriod[],
): CompactTrustedService {
  const record: unknown[] = [spkiKey, null, subjectDnIdx, country, purposeMask, trustIntervals];
  if (sourceIdx !== undefined || qualificationPeriods.length > 0) {
    record.push(sourceIdx ?? -1);
  }
  if (qualificationPeriods.length > 0) {
    record.push(qualificationPeriods);
  }
  return record as CompactTrustedService;
}

/**
 * Build a version 3 compact bundle: SPKI lookup keys (see `getSpkiKey`), no
 * SKIs, normalized DNs, and qualification data for CA/QC services.
 */
export function buildCompactTrustedListBundle(
  services: TrustedService[],
  sources: TrustedListSource[],
  generatedAt: string = new Date().toISOString(),
): CompactTrustedListBundle {
  const dedupedServices = dedupeTrustedServices(services);
  const distinguishedNameCodebook = new Map<string, number>();
  const dns: string[] = [];
  const codebook = new QualificationCodebook();
  const compactServiceMap = new Map<
    string,
    {
      spkiKey: string | null;
      subjectDnIdx: number;
      country: string;
      purposeMask: CompactTrustedService[4];
      trustIntervals: CompactTrustedInterval[];
      sourceIdx: number | undefined;
      qualificationPeriods: CompactQualificationPeriod[];
    }
  >();
  const sourceIndexById = new Map(sources.map((source, index) => [source.id, index]));

  const getDistinguishedNameCode = (value: string) => {
    const existing = distinguishedNameCodebook.get(value);
    if (existing !== undefined) {
      return existing;
    }

    const nextIndex = dns.length;
    dns.push(value);
    distinguishedNameCodebook.set(value, nextIndex);
    return nextIndex;
  };

  for (const service of dedupedServices) {
    const purposeMask = getTrustListPurposeMaskForServiceType(service.serviceType);
    if (!purposeMask) {
      continue;
    }

    const subjectDn = normalizeDistinguishedName(service.subjectDn);
    if (!subjectDn) {
      continue;
    }

    const trustIntervals = collapseTrustedIntervals(service.history);
    if (trustIntervals.length === 0) {
      continue;
    }

    const spkiKey = getSpkiKey(service.spkiSha256Hex);
    const sourceIdx = sourceIndexById.get(service.source);
    const qualificationPeriods = buildQualificationPeriods(service, codebook);
    const compactServiceKey = JSON.stringify([
      spkiKey,
      subjectDn,
      service.country,
      trustIntervals,
      sourceIdx ?? null,
    ]);

    const existingService = compactServiceMap.get(compactServiceKey);
    if (existingService) {
      existingService.purposeMask = (existingService.purposeMask |
        purposeMask) as CompactTrustedService[4];
      existingService.qualificationPeriods.push(...qualificationPeriods);
      continue;
    }

    compactServiceMap.set(compactServiceKey, {
      spkiKey,
      subjectDnIdx: getDistinguishedNameCode(subjectDn),
      country: service.country,
      purposeMask,
      trustIntervals,
      sourceIdx,
      qualificationPeriods,
    });
  }

  return {
    v: 3,
    bundleId: formatTrustedListBundleId(generatedAt),
    generatedAt,
    sources: sources.map((source) => [source.id, source.label, source.lotlUrl]),
    dns,
    quals: codebook.entries,
    services: Array.from(compactServiceMap.values())
      .map((service) =>
        compactServiceRecord(
          service.spkiKey,
          service.subjectDnIdx,
          service.country,
          service.purposeMask,
          service.trustIntervals,
          service.sourceIdx,
          sortAndMergeQualificationPeriods(service.qualificationPeriods),
        ),
      )
      .sort(sortCompactServices),
  };
}

/**
 * Convert a compact bundle to version 3. Version 2 SPKI hashes are truncated
 * to lookup keys, SKIs are dropped and DNs are normalized; version 2 bundles
 * carry no qualification data.
 */
export function upgradeTrustedListBundle(
  bundle: CompactTrustedListBundle,
): CompactTrustedListBundle {
  if (bundle.v === 3) {
    return bundle;
  }

  return {
    ...bundle,
    v: 3,
    dns: bundle.dns.map((dn) => normalizeDistinguishedName(dn)),
    quals: [],
    services: bundle.services.map((service) =>
      compactServiceRecord(
        service[0] ? service[0].slice(0, SPKI_KEY_LENGTH) : null,
        service[2],
        service[3],
        service[4],
        service[5],
        service[6],
        [],
      ),
    ),
  };
}

/**
 * Carry forward last-known-good services only for territories whose advertised
 * TSL endpoints were explicitly observed as unreachable during this fetch.
 *
 * A territory merely being absent from the fresh bundle is not sufficient:
 * absence can represent a legitimate removal and must not resurrect stale trust.
 * A territory present in the fresh bundle always wins.
 *
 * The result is a version 3 bundle; a version 2 `previous` bundle is upgraded
 * first (its carried services then have no qualification data).
 */
export function mergeForwardUnreachableTerritories(
  freshBundle: CompactTrustedListBundle,
  previousBundle: CompactTrustedListBundle,
  unreachableTerritories: ReadonlySet<string>,
): CompactTrustedListBundle {
  const fresh = upgradeTrustedListBundle(freshBundle);
  const previous = upgradeTrustedListBundle(previousBundle);
  const freshTerritories = new Set(fresh.services.map((service) => service[3]));
  const carriedServices = previous.services.filter(
    (service) => unreachableTerritories.has(service[3]) && !freshTerritories.has(service[3]),
  );

  if (carriedServices.length === 0) {
    return fresh;
  }

  const dns = [...fresh.dns];
  const dnIndex = new Map(dns.map((dn, index) => [dn, index]));
  const codebook = new QualificationCodebook();
  for (const element of fresh.quals ?? []) {
    codebook.add(element);
  }
  const previousQuals = previous.quals ?? [];

  const remappedServices = carriedServices.map<CompactTrustedService>((service) => {
    const subjectDn = previous.dns[service[2]];
    let index = dnIndex.get(subjectDn);
    if (index === undefined) {
      index = dns.length;
      dns.push(subjectDn);
      dnIndex.set(subjectDn, index);
    }
    const previousSource =
      service[6] !== undefined && service[6] >= 0 ? previous.sources[service[6]] : undefined;
    const sourceIdx = previousSource
      ? fresh.sources.findIndex(([id]) => id === previousSource[0])
      : -1;
    const qualificationPeriods = (service[7] ?? []).map<CompactQualificationPeriod>(
      ([fromUnix, toUnix, mask, qualIdxs]) => {
        const remapped = (qualIdxs ?? []).map((qualIdx) => {
          const element = previousQuals[qualIdx];
          if (!element) {
            throw new Error(`Trusted list bundle contains unknown qualification code ${qualIdx}`);
          }
          return codebook.add(element);
        });
        return [
          fromUnix,
          toUnix,
          mask,
          ...(remapped.length > 0 ? [remapped] : []),
        ] as CompactQualificationPeriod;
      },
    );
    return compactServiceRecord(
      service[0],
      index,
      service[3],
      service[4],
      service[5],
      sourceIdx >= 0 ? sourceIdx : undefined,
      qualificationPeriods,
    );
  });

  return {
    ...fresh,
    dns,
    quals: codebook.entries,
    services: [...fresh.services, ...remappedServices].sort(sortCompactServices),
  };
}

export function dedupeTrustedServices(services: TrustedService[]): TrustedService[] {
  const serviceMap = new Map<string, TrustedService>();

  for (const service of services) {
    const normalizedService: TrustedService = {
      ...service,
      skiHex: normalizeHex(service.skiHex),
      spkiSha256Hex: normalizeHex(service.spkiSha256Hex) || "",
      subjectDn: normalizeDistinguishedName(service.subjectDn),
      history: dedupeHistory(
        [...service.history].sort((left, right) => left.from.localeCompare(right.from)),
      ),
    };

    const key = JSON.stringify([
      normalizedService.skiHex,
      normalizedService.spkiSha256Hex,
      normalizedService.subjectDn,
      normalizedService.country,
      normalizedService.tspName,
      normalizedService.serviceType,
      normalizedService.source,
      normalizedService.sourceLabel,
      normalizedService.history,
    ]);

    if (!serviceMap.has(key)) {
      serviceMap.set(key, normalizedService);
    }
  }

  return Array.from(serviceMap.values());
}
