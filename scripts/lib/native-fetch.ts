import http from "node:http";
import https from "node:https";

type FetchInit = Parameters<typeof fetch>[1];

function resolveUrl(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return (input as Request).url;
}

function nativeGet(url: string, init: FetchInit, timeoutMs: number): Promise<Response> {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("http://") ? http : https;
    const headers: Record<string, string> = {};
    const initHeaders = init?.headers as Record<string, string> | undefined;
    if (initHeaders) {
      for (const [key, value] of Object.entries(initHeaders)) {
        headers[key] = value;
      }
    }

    const request = client.get(url, { headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        resolve(
          new Response(Buffer.concat(chunks), {
            status: response.statusCode ?? 0,
            statusText: response.statusMessage ?? "",
          }),
        );
      });
    });

    request.on("error", reject);
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`native request timeout after ${timeoutMs}ms`));
    });
  });
}

/**
 * Install a global `fetch` wrapper that falls back to Node's native http(s)
 * client when undici returns HTTP 403 or throws.
 *
 * Some national trusted-list endpoints (e.g. Estonia's sr.riik.ee) block
 * undici's TLS/HTTP2 client fingerprint (and reject browser-style User-Agents),
 * while accepting Node's native client. The fallback only applies to GET
 * requests; everything else is passed straight through to the original fetch.
 *
 * Returns a function that restores the original global fetch.
 */
export function installNativeFetchFallback(timeoutMs = 20000): () => void {
  const originalFetch = globalThis.fetch;

  const wrapped = (async (input, init) => {
    const method = (init?.method ?? "GET").toUpperCase();

    try {
      const response = await originalFetch(input as Parameters<typeof fetch>[0], init);
      if (response.status !== 403 || method !== "GET") {
        return response;
      }
    } catch (error) {
      if (method !== "GET") {
        throw error;
      }
      // GET failed outright (e.g. fingerprint reset) — try the native client.
    }

    return nativeGet(resolveUrl(input), init, timeoutMs);
  }) as typeof fetch;

  globalThis.fetch = wrapped;
  return () => {
    globalThis.fetch = originalFetch;
  };
}
