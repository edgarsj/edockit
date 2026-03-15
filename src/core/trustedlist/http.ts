import type { TrustListMatch, TrustListProvider, TrustListQuery } from "./contract";

export interface CreateRemoteTrustListProviderOptions {
  url: string;
  fetch?: typeof fetch;
  headers?: HeadersInit;
}

export function createRemoteTrustListProvider(
  options: CreateRemoteTrustListProviderOptions,
): TrustListProvider {
  const fetchImpl = options.fetch ?? globalThis.fetch;

  if (!fetchImpl) {
    throw new Error("No fetch implementation available to create remote trust-list provider");
  }

  return {
    async match(query: TrustListQuery): Promise<TrustListMatch> {
      const response = await fetchImpl(options.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...options.headers,
        },
        body: JSON.stringify(query),
      });

      if (!response.ok) {
        throw new Error(`Trust-list API failed: HTTP ${response.status}`);
      }

      return response.json() as Promise<TrustListMatch>;
    },
  };
}
