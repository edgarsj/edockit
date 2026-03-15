import type { TrustListMatch, TrustListProvider, TrustListQuery } from "./contract";

export interface CreateRemoteTrustListProviderOptions {
  url: string;
  fetch?: typeof fetch;
  headers?: HeadersInit;
  timeout?: number;
}

function normalizeRequestHeaders(headersInit?: HeadersInit): Record<string, string> {
  const headers: Record<string, string> = {};

  if (!headersInit) {
    return headers;
  }

  if (Array.isArray(headersInit)) {
    for (const [key, value] of headersInit) {
      headers[key.toLowerCase()] = value;
    }
    return headers;
  }

  if (typeof Headers !== "undefined" && headersInit instanceof Headers) {
    headersInit.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    return headers;
  }

  if (typeof (headersInit as { forEach?: unknown }).forEach === "function") {
    (headersInit as { forEach: (callback: (value: string, key: string) => void) => void }).forEach(
      (value, key) => {
        headers[key.toLowerCase()] = value;
      },
    );
    return headers;
  }

  for (const [key, value] of Object.entries(headersInit)) {
    headers[key.toLowerCase()] = value;
  }

  return headers;
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
      const timeoutMs =
        typeof options.timeout === "number" && options.timeout > 0 ? options.timeout : undefined;
      const controller = timeoutMs ? new AbortController() : null;
      const timeoutId = controller
        ? setTimeout(() => {
            controller.abort();
          }, timeoutMs)
        : null;

      try {
        const response = await fetchImpl(options.url, {
          method: "POST",
          headers: {
            ...normalizeRequestHeaders(options.headers),
            "content-type": "application/json",
          },
          body: JSON.stringify(query),
          signal: controller?.signal,
        });

        if (!response.ok) {
          throw new Error(`Trust-list API failed: HTTP ${response.status}`);
        }

        return response.json() as Promise<TrustListMatch>;
      } catch (error) {
        if (
          timeoutMs &&
          controller?.signal.aborted &&
          error instanceof Error &&
          error.name === "AbortError"
        ) {
          throw new Error(`Trust-list API timed out after ${timeoutMs} ms`);
        }

        throw error;
      } finally {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
      }
    },
  };
}
