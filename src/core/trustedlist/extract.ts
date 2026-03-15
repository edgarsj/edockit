import { SubjectKeyIdentifierExtension, X509Certificate } from "@peculiar/x509";
import { formatPEM } from "../certificate";
import { arrayBufferToHex } from "../../utils/encoding";
import {
  getChildElement,
  getChildElements,
  getChildText,
  getDescendantText,
  getDocumentElement,
  getLanguageAttribute,
  parseXmlDocument,
} from "./dom";
import {
  getRelevantServiceType,
  getServiceStatusSuffix,
  isLikelyXmlTslUrl,
  normalizeDistinguishedName,
  normalizeKeyIdentifier,
} from "./normalize";
import type {
  TslPointer,
  TrustedListSource,
  TrustedService,
  TrustedServiceSnapshot,
} from "./types";

const SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";

interface SnapshotIdentityGroup {
  country: string;
  tspName: string;
  serviceType: string;
  source: string;
  sourceLabel: string;
  subjectDn: string;
  skiHex: string | null;
  spkiSha256Hex: string;
  snapshots: TrustedServiceSnapshot[];
}

interface ParsedDigitalIdentity {
  subjectDn: string;
  skiHex: string | null;
  spkiSha256Hex: string;
}

function getPreferredName(parent: Element | null): string | undefined {
  if (!parent) {
    return undefined;
  }

  const names = getChildElements(parent, "Name");
  if (names.length === 0) {
    return parent.textContent?.trim() || undefined;
  }

  const englishName = names.find((name) =>
    getLanguageAttribute(name)?.toLowerCase().startsWith("en"),
  );

  return (
    englishName?.textContent?.trim() ||
    names.find((name) => name.textContent?.trim())?.textContent?.trim() ||
    undefined
  );
}

async function computeSha256Hex(input: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", input);
  return arrayBufferToHex(digest);
}

async function parseDigitalIdentity(
  digitalIdentityElement: Element,
  context: {
    country: string;
    source: TrustedListSource;
    serviceType: string;
    tspName: string;
    status: string;
    startTime: string;
  },
): Promise<ParsedDigitalIdentity | null> {
  const certificateValue = getDescendantText(digitalIdentityElement, "X509Certificate");
  const subjectDnFromTsl = normalizeDistinguishedName(
    getDescendantText(digitalIdentityElement, "X509SubjectName") || null,
  );
  const skiFromTsl = normalizeKeyIdentifier(
    getDescendantText(digitalIdentityElement, "X509SKI") || null,
  );

  let subjectDnFromCertificate = "";
  let skiFromCertificate: string | null = null;
  let spkiSha256Hex = "";

  if (certificateValue) {
    try {
      const certificate = new X509Certificate(formatPEM(certificateValue.replace(/\s+/g, "")));
      const skiExtension = certificate.getExtension(
        SUBJECT_KEY_IDENTIFIER_OID,
      ) as SubjectKeyIdentifierExtension | null;

      subjectDnFromCertificate = normalizeDistinguishedName(certificate.subject);
      skiFromCertificate = normalizeKeyIdentifier(skiExtension?.keyId);
      spkiSha256Hex = await computeSha256Hex(certificate.publicKey.rawData);
    } catch {
      // Some live TSL history entries only expose subject name/SKI and may carry invalid or absent certs.
    }
  }

  const subjectDn = subjectDnFromCertificate || subjectDnFromTsl;
  const skiHex = skiFromCertificate || skiFromTsl;

  if (!subjectDn && !skiHex && !spkiSha256Hex) {
    return null;
  }

  return {
    subjectDn,
    skiHex,
    spkiSha256Hex,
  };
}

function buildSnapshotsFromDigitalIdentities(
  identities: ParsedDigitalIdentity[],
  context: {
    country: string;
    source: TrustedListSource;
    serviceType: string;
    tspName: string;
    status: string;
    startTime: string;
  },
): TrustedServiceSnapshot[] {
  const identitiesWithSubject = identities.filter((identity) => identity.subjectDn);
  if (identitiesWithSubject.length === 0) {
    return [];
  }

  const identitiesWithoutSubject = identities.filter(
    (identity) => !identity.subjectDn && (identity.skiHex || identity.spkiSha256Hex),
  );
  const attachAnonymousIdentityEvidence =
    identitiesWithSubject.length === 1 && identitiesWithoutSubject.length > 0;

  return identitiesWithSubject.map((identity, index) => {
    const mergedIdentity =
      attachAnonymousIdentityEvidence && index === 0
        ? identitiesWithoutSubject.reduce(
            (current, anonymousIdentity) => ({
              ...current,
              skiHex: current.skiHex || anonymousIdentity.skiHex,
              spkiSha256Hex: current.spkiSha256Hex || anonymousIdentity.spkiSha256Hex,
            }),
            identity,
          )
        : identity;

    return {
      skiHex: mergedIdentity.skiHex,
      spkiSha256Hex: mergedIdentity.spkiSha256Hex,
      subjectDn: mergedIdentity.subjectDn,
      country: context.country,
      tspName: context.tspName,
      serviceType: context.serviceType,
      source: context.source.id,
      sourceLabel: context.source.label,
      status: context.status,
      startTime: context.startTime,
    };
  });
}

function mergeSnapshotIntoGroup(
  group: SnapshotIdentityGroup,
  snapshot: TrustedServiceSnapshot,
): SnapshotIdentityGroup {
  return {
    ...group,
    skiHex: group.skiHex || snapshot.skiHex,
    spkiSha256Hex: group.spkiSha256Hex || snapshot.spkiSha256Hex,
    snapshots: [...group.snapshots, snapshot],
  };
}

function mergeSnapshotGroups(
  targetGroup: SnapshotIdentityGroup,
  sourceGroup: SnapshotIdentityGroup,
): SnapshotIdentityGroup {
  return {
    ...targetGroup,
    skiHex: targetGroup.skiHex || sourceGroup.skiHex,
    spkiSha256Hex: targetGroup.spkiSha256Hex || sourceGroup.spkiSha256Hex,
    snapshots: [...targetGroup.snapshots, ...sourceGroup.snapshots],
  };
}

function buildTrustedServicesFromSnapshots(snapshots: TrustedServiceSnapshot[]): TrustedService[] {
  const snapshotsByContext = new Map<string, TrustedServiceSnapshot[]>();

  for (const snapshot of snapshots) {
    const key = JSON.stringify([
      snapshot.country,
      snapshot.tspName,
      snapshot.serviceType,
      snapshot.source,
      snapshot.sourceLabel,
      snapshot.subjectDn,
    ]);

    const existingSnapshots = snapshotsByContext.get(key);
    if (existingSnapshots) {
      existingSnapshots.push(snapshot);
      continue;
    }

    snapshotsByContext.set(key, [snapshot]);
  }

  const services: TrustedService[] = [];

  for (const contextSnapshots of snapshotsByContext.values()) {
    const groups: SnapshotIdentityGroup[] = [];

    for (const snapshot of contextSnapshots) {
      const matchingGroupIndexes = groups
        .map((group, index) => ({ group, index }))
        .filter(({ group }) => {
          if (snapshot.skiHex && group.skiHex === snapshot.skiHex) {
            return true;
          }

          if (snapshot.spkiSha256Hex && group.spkiSha256Hex === snapshot.spkiSha256Hex) {
            return true;
          }

          return false;
        })
        .map(({ index }) => index);

      if (matchingGroupIndexes.length === 0) {
        const shouldAttachBySubjectOnly =
          !snapshot.skiHex && !snapshot.spkiSha256Hex && groups.length === 1;

        if (shouldAttachBySubjectOnly) {
          groups[0] = mergeSnapshotIntoGroup(groups[0], snapshot);
          continue;
        }

        groups.push({
          country: snapshot.country,
          tspName: snapshot.tspName,
          serviceType: snapshot.serviceType,
          source: snapshot.source,
          sourceLabel: snapshot.sourceLabel,
          subjectDn: snapshot.subjectDn,
          skiHex: snapshot.skiHex,
          spkiSha256Hex: snapshot.spkiSha256Hex,
          snapshots: [snapshot],
        });
        continue;
      }

      const [firstGroupIndex, ...otherGroupIndexes] = matchingGroupIndexes;
      const primaryGroup = groups[firstGroupIndex];
      let mergedGroup = mergeSnapshotIntoGroup(primaryGroup, snapshot);

      for (const otherGroupIndex of otherGroupIndexes.sort((left, right) => right - left)) {
        mergedGroup = mergeSnapshotGroups(mergedGroup, groups[otherGroupIndex]);
        groups.splice(otherGroupIndex, 1);
      }

      const normalizedFirstIndex = groups.findIndex((group) => group === primaryGroup);
      groups[normalizedFirstIndex >= 0 ? normalizedFirstIndex : 0] = mergedGroup;
    }

    services.push(
      ...groups.map((group) => {
        const sortedSnapshots = [...group.snapshots].sort((left, right) =>
          left.startTime.localeCompare(right.startTime),
        );

        return {
          skiHex: group.skiHex,
          spkiSha256Hex: group.spkiSha256Hex,
          subjectDn: group.subjectDn,
          country: group.country,
          tspName: group.tspName,
          serviceType: group.serviceType,
          source: group.source,
          sourceLabel: group.sourceLabel,
          history: sortedSnapshots.map((snapshot, index) => ({
            status: snapshot.status,
            from: snapshot.startTime,
            to: sortedSnapshots[index + 1]?.startTime || null,
          })),
        };
      }),
    );
  }

  return services;
}

async function extractServiceSnapshots(
  serviceElement: Element,
  context: {
    country: string;
    source: TrustedListSource;
    tspName: string;
  },
): Promise<TrustedServiceSnapshot[]> {
  const snapshotContainers: Element[] = [];
  const currentServiceInfo = getChildElement(serviceElement, "ServiceInformation");
  if (currentServiceInfo) {
    snapshotContainers.push(currentServiceInfo);
  }

  const serviceHistory = getChildElement(serviceElement, "ServiceHistory");
  snapshotContainers.push(...getChildElements(serviceHistory, "ServiceHistoryInstance"));

  const snapshots: TrustedServiceSnapshot[] = [];

  for (const container of snapshotContainers) {
    const serviceType = getRelevantServiceType(getChildText(container, "ServiceTypeIdentifier"));
    if (!serviceType) {
      continue;
    }

    const status = getServiceStatusSuffix(getChildText(container, "ServiceStatus"));
    const startTime = getChildText(container, "StatusStartingTime");
    if (!status || !startTime) {
      continue;
    }

    const serviceDigitalIdentity = getChildElement(container, "ServiceDigitalIdentity");
    const digitalIdentities = getChildElements(serviceDigitalIdentity, "DigitalId");

    const digitalIdentitySnapshots = (
      await Promise.all(
        digitalIdentities.map((digitalIdentity) =>
          parseDigitalIdentity(digitalIdentity, {
            country: context.country,
            source: context.source,
            serviceType,
            tspName: context.tspName,
            status,
            startTime,
          }),
        ),
      )
    ).filter((snapshot): snapshot is ParsedDigitalIdentity => Boolean(snapshot));

    snapshots.push(
      ...buildSnapshotsFromDigitalIdentities(digitalIdentitySnapshots, {
        country: context.country,
        source: context.source,
        serviceType,
        tspName: context.tspName,
        status,
        startTime,
      }),
    );
  }

  return snapshots;
}

export function parseLotlPointers(xml: string, source: TrustedListSource): TslPointer[] {
  const document = parseXmlDocument(xml);
  const rootElement = getDocumentElement(document);
  const schemeInformation = getChildElement(rootElement, "SchemeInformation");
  const pointersToOtherTsl = getChildElement(
    schemeInformation || rootElement,
    "PointersToOtherTSL",
  );
  const pointers = getChildElements(pointersToOtherTsl, "OtherTSLPointer");
  const dedupedPointers = new Map<string, TslPointer>();

  for (const pointer of pointers) {
    const url = getChildText(pointer, "TSLLocation");
    if (!url || !isLikelyXmlTslUrl(url)) {
      continue;
    }

    const territory = getDescendantText(pointer, "SchemeTerritory");
    const dedupeKey = `${source.id}|${url}`;

    if (!dedupedPointers.has(dedupeKey)) {
      dedupedPointers.set(dedupeKey, {
        url,
        territory,
        source,
      });
    }
  }

  return Array.from(dedupedPointers.values());
}

export async function parseTrustedList(
  xml: string,
  context: {
    source: TrustedListSource;
    territoryHint?: string;
  },
): Promise<TrustedService[]> {
  const document = parseXmlDocument(xml);
  const rootElement = getDocumentElement(document);
  const schemeInformation = getChildElement(rootElement, "SchemeInformation");
  const country = getChildText(schemeInformation, "SchemeTerritory") || context.territoryHint || "";
  const providerList = getChildElement(rootElement, "TrustServiceProviderList");
  const providers = getChildElements(providerList, "TrustServiceProvider");
  const services: TrustedService[] = [];

  for (const provider of providers) {
    const tspInformation = getChildElement(provider, "TSPInformation");
    const tspName =
      getPreferredName(getChildElement(tspInformation, "TSPName")) ||
      getPreferredName(getChildElement(tspInformation, "TSPTradeName")) ||
      country ||
      "Unknown TSP";

    const tspServices = getChildElements(getChildElement(provider, "TSPServices"), "TSPService");
    for (const serviceElement of tspServices) {
      const snapshots = await extractServiceSnapshots(serviceElement, {
        country,
        source: context.source,
        tspName,
      });

      if (snapshots.length === 0) {
        continue;
      }

      services.push(...buildTrustedServicesFromSnapshots(snapshots));
    }
  }

  return services;
}
