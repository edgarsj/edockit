import type {
  CompactTrustedInterval,
  CompactTrustedListBundle,
  CompactTrustedService,
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
  getTrustListPurposeMaskForServiceType,
  hexToBase64Url,
  isTrustedServiceStatus,
  normalizeDistinguishedName,
  normalizeHex,
} from "./normalize";

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
    bySpkiSha256: new Map<string, TrustedListEntry[]>(),
    bySubjectDn: new Map<string, TrustedListEntry[]>(),
  };

  for (const service of services) {
    addToIndex(indexes.bySki, normalizeHex(service.skiHex), service);
    addToIndex(indexes.bySpkiSha256, normalizeHex(service.spkiSha256Hex), service);
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

export function createEmptyTrustedListBundle(): CompactTrustedListBundle {
  return {
    v: 2,
    generatedAt: new Date(0).toISOString(),
    sources: [],
    dns: [],
    services: [],
  };
}

export function buildTrustedListData(bundle: CompactTrustedListBundle): TrustedListData {
  const services: TrustedListEntry[] = bundle.services.map((serviceRecord) => {
    const [spkiSha256Base64Url, skiBase64Url, subjectDnIdx, country, purposeMask, trustIntervals] =
      serviceRecord;

    const subjectDn = bundle.dns[subjectDnIdx];
    if (subjectDn === undefined) {
      throw new Error(`Trusted list bundle contains unknown DN code ${subjectDnIdx}`);
    }

    return {
      skiHex: base64UrlToHex(skiBase64Url),
      spkiSha256Hex: base64UrlToHex(spkiSha256Base64Url),
      subjectDn: normalizeDistinguishedName(subjectDn),
      country,
      purposeMask,
      trustIntervals: hydrateTrustIntervals(trustIntervals),
    };
  });

  return {
    version: bundle.v,
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

export function buildCompactTrustedListBundle(
  services: TrustedService[],
  sources: TrustedListSource[],
  generatedAt: string = new Date().toISOString(),
): CompactTrustedListBundle {
  const dedupedServices = dedupeTrustedServices(services);
  const distinguishedNameCodebook = new Map<string, number>();
  const dns: string[] = [];
  const compactServiceMap = new Map<string, CompactTrustedService>();

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

    const compactServiceKey = JSON.stringify([
      hexToBase64Url(service.spkiSha256Hex),
      hexToBase64Url(service.skiHex),
      subjectDn,
      service.country,
      trustIntervals,
    ]);

    const existingService = compactServiceMap.get(compactServiceKey);
    if (existingService) {
      existingService[4] = (existingService[4] | purposeMask) as (typeof existingService)[4];
      continue;
    }

    compactServiceMap.set(compactServiceKey, [
      hexToBase64Url(service.spkiSha256Hex),
      hexToBase64Url(service.skiHex),
      getDistinguishedNameCode(subjectDn),
      service.country,
      purposeMask,
      trustIntervals,
    ]);
  }

  return {
    v: 2,
    generatedAt,
    sources: sources.map((source) => [source.id, source.label, source.lotlUrl]),
    dns,
    services: Array.from(compactServiceMap.values()).sort(sortCompactServices),
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
