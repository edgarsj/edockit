import { fetchBinary } from "../revocation/fetch";
import { parseLotlPointers, parseTrustedList } from "./extract";
import {
  buildCompactTrustedListBundle,
  buildTrustedListData,
  createEmptyTrustedListBundle,
  dedupeTrustedServices,
  getBundledTrustedListData,
} from "./loader";
import type {
  CompactTrustedListBundle,
  TrustedListData,
  TrustedListFetchOptions,
  TrustedListSource,
  TrustedService,
} from "./types";

export * from "./types";
export * from "./normalize";
export * from "./loader";
export * from "./extract";
export * from "./matcher";

export const DEFAULT_TRUSTED_LIST_SOURCES: TrustedListSource[] = [
  {
    id: "eu",
    label: "EU LOTL",
    lotlUrl: "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
  },
  {
    id: "ades",
    label: "AdES LOTL",
    lotlUrl: "https://ec.europa.eu/tools/lotl/mra/ades-lotl.xml",
  },
];

async function fetchXml(url: string, options: TrustedListFetchOptions = {}): Promise<string> {
  const result = await fetchBinary(url, {
    timeout: options.timeout ?? 10000,
    accept: "application/xml, text/xml;q=0.9, */*;q=0.8",
    proxyUrl: options.proxyUrl,
  });

  if (!result.ok || !result.data) {
    throw new Error(`Failed to fetch "${url}": ${result.error || `HTTP ${result.status}`}`);
  }

  return new TextDecoder().decode(result.data);
}

async function fetchXmlWithWarnings(
  url: string,
  options: TrustedListFetchOptions = {},
): Promise<string | null> {
  try {
    return await fetchXml(url, options);
  } catch (error) {
    // The Node-only builder intentionally skips broken endpoints, including
    // TLS-chain failures such as UNABLE_TO_VERIFY_LEAF_SIGNATURE, rather than
    // attempting local intermediate repair in the generic fetch path.
    console.warn(
      `Trusted-list fetch warning for "${url}": ${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
}

function isProbablyXmlDocument(xml: string): boolean {
  const trimmed = xml.trimStart();
  return trimmed.startsWith("<");
}

async function parseTrustedListWithWarnings(
  xml: string,
  context: { source: TrustedListSource; territoryHint?: string; url: string },
): Promise<TrustedService[]> {
  if (!isProbablyXmlDocument(xml)) {
    console.warn(
      `Trusted-list parse warning for "${context.url}": response does not look like XML`,
    );
    return [];
  }

  try {
    return await parseTrustedList(xml, {
      source: context.source,
      territoryHint: context.territoryHint,
    });
  } catch (error) {
    console.warn(
      `Trusted-list parse warning for "${context.url}": ${error instanceof Error ? error.message : String(error)}`,
    );
    return [];
  }
}

/**
 * Low-level live fetch helper for LOTL/TSL processing.
 *
 * Primarily intended for Node.js build/update tooling. Browser callers generally
 * need a proxy and should prefer the higher-level trusted-list update flow.
 */
export async function fetchTrustedListBundle(
  sources: TrustedListSource[] = DEFAULT_TRUSTED_LIST_SOURCES,
  fetchOptions: TrustedListFetchOptions = {},
): Promise<CompactTrustedListBundle> {
  if (sources.length === 0) {
    return createEmptyTrustedListBundle();
  }

  const lotlDocuments = await Promise.all(
    sources.map(async (source) => ({
      source,
      xml: await fetchXmlWithWarnings(source.lotlUrl, fetchOptions),
    })),
  );
  const availableLotlDocuments = lotlDocuments.filter(
    (document): document is { source: TrustedListSource; xml: string } => Boolean(document.xml),
  );

  if (availableLotlDocuments.length === 0) {
    throw new Error("Failed to fetch any configured LOTL source");
  }

  const pointers = availableLotlDocuments.flatMap(({ source, xml }) =>
    parseLotlPointers(xml, source),
  );
  const tslDocuments = await Promise.all(
    pointers.map(async (pointer) => ({
      pointer,
      xml: await fetchXmlWithWarnings(pointer.url, fetchOptions),
    })),
  );
  const availableTslDocuments = tslDocuments.filter(
    (document): document is { pointer: (typeof pointers)[number]; xml: string } =>
      Boolean(document.xml),
  );

  const extractedServices = (
    await Promise.all(
      availableTslDocuments.map(({ pointer, xml }) =>
        parseTrustedListWithWarnings(xml, {
          source: pointer.source,
          territoryHint: pointer.territory,
          url: pointer.url,
        }),
      ),
    )
  ).flat();

  if (extractedServices.length === 0) {
    throw new Error("Trusted-list update fetched LOTL data but extracted no trusted services");
  }

  return buildCompactTrustedListBundle(
    dedupeTrustedServices(extractedServices),
    sources,
    new Date().toISOString(),
  );
}

export async function updateTrustedList(
  sources: TrustedListSource[] = DEFAULT_TRUSTED_LIST_SOURCES,
  fetchOptions: TrustedListFetchOptions = {},
): Promise<TrustedListData> {
  const bundle = await fetchTrustedListBundle(sources, fetchOptions);
  return buildTrustedListData(bundle);
}

export function getBundledTrustedList(): TrustedListData {
  return getBundledTrustedListData();
}
