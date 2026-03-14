import bundledTrustedListBundle from "../../data/trusted-list.js";
import type {
  CompactTrustedListBundle,
  TrustedListData,
  TrustedListIndexes,
  TrustedListSource,
  TrustedService,
  TrustedStatusPeriod,
} from "./types";
import { normalizeDistinguishedName, normalizeHex } from "./normalize";

let bundledTrustedListCache: TrustedListData | null = null;

function addToIndex(
  index: Map<string, TrustedService[]>,
  key: string | null,
  service: TrustedService,
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

function buildIndexes(services: TrustedService[]): TrustedListIndexes {
  const indexes: TrustedListIndexes = {
    bySki: new Map<string, TrustedService[]>(),
    bySpkiSha256: new Map<string, TrustedService[]>(),
    bySubjectDn: new Map<string, TrustedService[]>(),
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

export function createEmptyTrustedListBundle(): CompactTrustedListBundle {
  return {
    v: 1,
    generatedAt: new Date(0).toISOString(),
    sources: [],
    codes: {
      serviceTypes: [],
      statuses: [],
    },
    strings: [],
    services: [],
  };
}

export function buildTrustedListData(bundle: CompactTrustedListBundle): TrustedListData {
  const services: TrustedService[] = bundle.services.map((serviceRecord) => {
    const [
      skiHex,
      spkiSha256Hex,
      subjectDnIdx,
      country,
      tspNameIdx,
      serviceTypeCode,
      sourceCode,
      historyRecords,
    ] = serviceRecord;

    const sourceTuple = bundle.sources[sourceCode];
    if (!sourceTuple) {
      throw new Error(`Trusted list bundle contains unknown source code ${sourceCode}`);
    }

    const [sourceId, sourceLabel] = sourceTuple;

    const subjectDn = bundle.strings[subjectDnIdx];
    const tspName = bundle.strings[tspNameIdx];
    const serviceType = bundle.codes.serviceTypes[serviceTypeCode];

    if (subjectDn === undefined) {
      throw new Error(`Trusted list bundle contains unknown string code ${subjectDnIdx}`);
    }

    if (tspName === undefined) {
      throw new Error(`Trusted list bundle contains unknown string code ${tspNameIdx}`);
    }

    if (serviceType === undefined) {
      throw new Error(`Trusted list bundle contains unknown service type code ${serviceTypeCode}`);
    }

    const history = historyRecords.map((historyRecord) => {
      const [statusCode, from, to] = historyRecord;
      const status = bundle.codes.statuses[statusCode];

      if (status === undefined) {
        throw new Error(`Trusted list bundle contains unknown status code ${statusCode}`);
      }

      return {
        status,
        from,
        to,
      };
    });

    return {
      skiHex: normalizeHex(skiHex),
      spkiSha256Hex: normalizeHex(spkiSha256Hex) || "",
      subjectDn: normalizeDistinguishedName(subjectDn),
      country,
      tspName,
      serviceType,
      source: sourceId,
      sourceLabel,
      history: dedupeHistory(history),
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
  const stringCodebook = new Map<string, number>();
  const strings: string[] = [];
  const serviceTypeCodebook = new Map<string, number>();
  const statusCodebook = new Map<string, number>();
  const serviceTypes: string[] = [];
  const statuses: string[] = [];
  const sourceCodebook = new Map<string, number>();

  const getStringCode = (value: string) => {
    const existing = stringCodebook.get(value);
    if (existing !== undefined) {
      return existing;
    }

    const nextIndex = strings.length;
    strings.push(value);
    stringCodebook.set(value, nextIndex);
    return nextIndex;
  };

  const getServiceTypeCode = (value: string) => {
    const existing = serviceTypeCodebook.get(value);
    if (existing !== undefined) {
      return existing;
    }

    const nextIndex = serviceTypes.length;
    serviceTypes.push(value);
    serviceTypeCodebook.set(value, nextIndex);
    return nextIndex;
  };

  const getStatusCode = (value: string) => {
    const existing = statusCodebook.get(value);
    if (existing !== undefined) {
      return existing;
    }

    const nextIndex = statuses.length;
    statuses.push(value);
    statusCodebook.set(value, nextIndex);
    return nextIndex;
  };

  sources.forEach((source, index) => {
    sourceCodebook.set(source.id, index);
  });

  return {
    v: 1,
    generatedAt,
    sources: sources.map((source) => [source.id, source.label, source.lotlUrl]),
    codes: {
      serviceTypes,
      statuses,
    },
    strings,
    services: dedupedServices.map((service) => {
      const sourceCode = sourceCodebook.get(service.source);
      if (sourceCode === undefined) {
        throw new Error(`Trusted service references unknown source "${service.source}"`);
      }

      return [
        normalizeHex(service.skiHex),
        normalizeHex(service.spkiSha256Hex) || "",
        getStringCode(normalizeDistinguishedName(service.subjectDn)),
        service.country,
        getStringCode(service.tspName),
        getServiceTypeCode(service.serviceType),
        sourceCode,
        dedupeHistory(service.history).map((historyRecord) => [
          getStatusCode(historyRecord.status),
          historyRecord.from,
          historyRecord.to,
        ]),
      ];
    }),
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

export function getBundledTrustedListData(): TrustedListData {
  if (!bundledTrustedListCache) {
    bundledTrustedListCache = buildTrustedListData(
      bundledTrustedListBundle || createEmptyTrustedListBundle(),
    );
  }

  return bundledTrustedListCache;
}
