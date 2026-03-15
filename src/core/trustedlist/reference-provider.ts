import type { TrustListProvider } from "./contract";
import { buildTrustedListData } from "./loader";
import { matchTrustListQuery } from "./matcher";
import type { CompactTrustedListBundle, TrustedListData } from "./types";

export interface CreateTrustListProviderFromDataOptions {
  data: CompactTrustedListBundle | TrustedListData;
}

export interface CreateTrustListProviderFromUrlOptions {
  url: string;
  fetch?: typeof fetch;
  headers?: HeadersInit;
}

export type CreateTrustListProviderOptions =
  | CreateTrustListProviderFromDataOptions
  | CreateTrustListProviderFromUrlOptions;

function isTrustedListData(
  value: CompactTrustedListBundle | TrustedListData,
): value is TrustedListData {
  return "indexes" in value;
}

function createInMemoryTrustListProvider(trustedListData: TrustedListData): TrustListProvider {
  return {
    async match(query) {
      return matchTrustListQuery(query, trustedListData);
    },
  };
}

async function loadTrustedListDataFromUrl(
  options: CreateTrustListProviderFromUrlOptions,
): Promise<TrustedListData> {
  const fetchImpl = options.fetch ?? globalThis.fetch;

  if (!fetchImpl) {
    throw new Error("No fetch implementation available to load trusted-list data");
  }

  const response = await fetchImpl(options.url, {
    method: "GET",
    headers: options.headers,
  });

  if (!response.ok) {
    throw new Error(
      `Failed to fetch trusted-list data from "${options.url}": HTTP ${response.status}`,
    );
  }

  const bundle = (await response.json()) as CompactTrustedListBundle;
  return buildTrustedListData(bundle);
}

export function createTrustListProvider(
  options: CreateTrustListProviderOptions,
): TrustListProvider {
  if (!options) {
    throw new Error(
      "createTrustListProvider requires either { data } or { url }. For bundled fallback use createBundledTrustListProvider from edockit/trusted-list/bundled.",
    );
  }

  if ("data" in options) {
    const trustedListData = isTrustedListData(options.data)
      ? options.data
      : buildTrustedListData(options.data);
    return createInMemoryTrustListProvider(trustedListData);
  }

  let trustedListDataPromise: Promise<TrustedListData> | null = null;

  return {
    async match(query) {
      if (!trustedListDataPromise) {
        trustedListDataPromise = loadTrustedListDataFromUrl(options);
      }

      const trustedListData = await trustedListDataPromise;
      return matchTrustListQuery(query, trustedListData);
    },
  };
}
