// src/core/revocation/fetch.ts

/**
 * Cross-platform HTTP fetch for OCSP and CRL requests
 * Works in both browser and Node.js environments
 */

/** Default response size cap for generic fetches (e.g. trusted lists) */
export const DEFAULT_MAX_RESPONSE_BYTES = 50 * 1024 * 1024;
/** Default response size cap for CRL downloads */
// National CRLs can be large (the Estonian ID card CRL is ~18 MB)
export const DEFAULT_MAX_CRL_BYTES = 50 * 1024 * 1024;
/** Default response size cap for OCSP responses and certificates */
export const DEFAULT_MAX_OCSP_BYTES = 1024 * 1024;
/** Default maximum number of HTTP redirects followed */
export const DEFAULT_MAX_REDIRECTS = 5;

export interface FetchOptions {
  /** Overall request timeout in milliseconds (covers connect, redirects and body read) */
  timeout?: number;
  /** HTTP method (default: GET) */
  method?: "GET" | "POST";
  /** Request body for POST requests */
  body?: ArrayBuffer | Uint8Array;
  /** Content-Type header */
  contentType?: string;
  /** Accept header */
  accept?: string;
  /**
   * CORS proxy URL for browser environments.
   * When set, the original URL will be URL-encoded and appended to this proxy URL.
   * Example: "https://cors-proxy.example.com/?url="
   */
  proxyUrl?: string;
  /** Maximum response body size in bytes (default: DEFAULT_MAX_RESPONSE_BYTES) */
  maxBytes?: number;
  /**
   * Maximum number of redirects to follow (default: DEFAULT_MAX_REDIRECTS).
   * Redirects are followed manually in Node.js so they can be counted and their
   * scheme checked. Browsers do not expose redirect responses, so there the
   * platform limit applies and only the final URL's scheme is checked.
   */
  maxRedirects?: number;
}

export interface FetchResult {
  ok: boolean;
  status: number;
  data?: ArrayBuffer;
  error?: string;
}

class FetchLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FetchLimitError";
  }
}

/**
 * Returns an error message if the URL is not an absolute http(s) URL.
 */
export function checkUrlScheme(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `Invalid URL: ${url}`;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return `Unsupported URL scheme "${parsed.protocol}" (only http and https are allowed)`;
  }
  return null;
}

/**
 * Whether manual redirect handling is usable. Node's fetch exposes 3xx
 * responses with `redirect: "manual"`; browsers return opaque responses.
 */
function canFollowRedirectsManually(): boolean {
  return (
    typeof window === "undefined" &&
    typeof process !== "undefined" &&
    !!(process as { versions?: { node?: string } }).versions?.node
  );
}

function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function getHeader(response: Response, name: string): string | null {
  try {
    return response.headers?.get?.(name) ?? null;
  } catch {
    return null;
  }
}

function discardBody(response: Response): void {
  try {
    void response.body?.cancel?.().catch(() => undefined);
  } catch {
    // ignore
  }
}

/**
 * Read a response body, enforcing a byte limit.
 */
async function readBodyWithLimit(response: Response, maxBytes: number): Promise<ArrayBuffer> {
  const contentLength = getHeader(response, "content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (Number.isFinite(declared) && declared > maxBytes) {
      discardBody(response);
      throw new FetchLimitError(`Response exceeds maximum size of ${maxBytes} bytes`);
    }
  }

  const stream = response.body as ReadableStream<Uint8Array> | null | undefined;
  if (stream && typeof stream.getReader === "function") {
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // ignore
        }
        throw new FetchLimitError(`Response exceeds maximum size of ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return out.buffer;
  }

  const data = await response.arrayBuffer();
  if (data.byteLength > maxBytes) {
    throw new FetchLimitError(`Response exceeds maximum size of ${maxBytes} bytes`);
  }
  return data;
}

/**
 * Fetch binary data from a URL with timeout, redirect and size limits
 * @param url URL to fetch (must be http or https)
 * @param options Fetch options
 * @returns FetchResult with binary data or error
 */
export async function fetchBinary(url: string, options: FetchOptions = {}): Promise<FetchResult> {
  const {
    timeout = 10000,
    method = "GET",
    body,
    contentType,
    accept,
    proxyUrl,
    maxBytes = DEFAULT_MAX_RESPONSE_BYTES,
    maxRedirects = DEFAULT_MAX_REDIRECTS,
  } = options;

  const schemeError = checkUrlScheme(url);
  if (schemeError) {
    return { ok: false, status: 0, error: schemeError };
  }

  // Apply proxy URL if provided
  const fetchUrl = proxyUrl ? `${proxyUrl}${encodeURIComponent(url)}` : url;

  const controller = new AbortController();
  let timedOut = false;
  // The timer stays active until the body has been read, so a slow body cannot
  // keep the request open past the timeout.
  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeout);
  const timeoutPromise = new Promise<never>((_, reject) => {
    controller.signal.addEventListener("abort", () =>
      reject(new FetchLimitError(`Request timeout after ${timeout}ms`)),
    );
  });
  timeoutPromise.catch(() => undefined);

  try {
    const headers: Record<string, string> = {};
    if (contentType) {
      headers["Content-Type"] = contentType;
    }
    if (accept) {
      headers["Accept"] = accept;
    }

    const manualRedirects = canFollowRedirectsManually();
    let currentUrl = fetchUrl;
    let currentMethod: "GET" | "POST" = method;
    let currentBody: Uint8Array<ArrayBuffer> | undefined = body ? new Uint8Array(body) : undefined;
    let response: Response;

    for (let redirects = 0; ; redirects++) {
      response = await Promise.race([
        fetch(currentUrl, {
          method: currentMethod,
          headers,
          body: currentBody,
          signal: controller.signal,
          redirect: manualRedirects ? "manual" : "follow",
        }),
        timeoutPromise,
      ]);

      if (manualRedirects && isRedirectStatus(response.status)) {
        discardBody(response);
        if (redirects >= maxRedirects) {
          return { ok: false, status: response.status, error: "Too many redirects" };
        }
        const location = getHeader(response, "location");
        if (!location) {
          return {
            ok: false,
            status: response.status,
            error: `HTTP ${response.status} redirect without Location header`,
          };
        }
        let nextUrl: string;
        try {
          nextUrl = new URL(location, currentUrl).toString();
        } catch {
          return { ok: false, status: response.status, error: `Invalid redirect URL: ${location}` };
        }
        const redirectSchemeError = checkUrlScheme(nextUrl);
        if (redirectSchemeError) {
          return { ok: false, status: response.status, error: redirectSchemeError };
        }
        if (
          response.status === 303 ||
          ((response.status === 301 || response.status === 302) && currentMethod === "POST")
        ) {
          currentMethod = "GET";
          currentBody = undefined;
        }
        currentUrl = nextUrl;
        continue;
      }
      break;
    }

    if (response.redirected && response.url) {
      const finalSchemeError = checkUrlScheme(response.url);
      if (finalSchemeError) {
        discardBody(response);
        return { ok: false, status: response.status, error: finalSchemeError };
      }
    }

    if (!response.ok) {
      discardBody(response);
      return {
        ok: false,
        status: response.status,
        error: `HTTP ${response.status}: ${response.statusText}`,
      };
    }

    const data = await Promise.race([readBodyWithLimit(response, maxBytes), timeoutPromise]);
    return {
      ok: true,
      status: response.status,
      data,
    };
  } catch (error) {
    if (timedOut) {
      return {
        ok: false,
        status: 0,
        error: `Request timeout after ${timeout}ms`,
      };
    }

    if (error instanceof Error) {
      if (error.name === "AbortError") {
        return {
          ok: false,
          status: 0,
          error: `Request timeout after ${timeout}ms`,
        };
      }
      return {
        ok: false,
        status: 0,
        error: error.message,
      };
    }

    return {
      ok: false,
      status: 0,
      error: String(error),
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Fetch OCSP response
 * @param url OCSP responder URL
 * @param request DER-encoded OCSP request
 * @param timeout Timeout in milliseconds
 * @param proxyUrl Optional CORS proxy URL
 * @param maxBytes Maximum response size in bytes
 * @returns FetchResult with OCSP response data
 */
export async function fetchOCSP(
  url: string,
  request: ArrayBuffer,
  timeout: number = 5000,
  proxyUrl?: string,
  maxBytes: number = DEFAULT_MAX_OCSP_BYTES,
): Promise<FetchResult> {
  return fetchBinary(url, {
    method: "POST",
    body: request,
    contentType: "application/ocsp-request",
    accept: "application/ocsp-response",
    timeout,
    proxyUrl,
    maxBytes,
  });
}

/**
 * Fetch CRL from distribution point
 * @param url CRL distribution point URL
 * @param timeout Timeout in milliseconds
 * @param proxyUrl Optional CORS proxy URL
 * @param maxBytes Maximum response size in bytes
 * @returns FetchResult with CRL data
 */
export async function fetchCRL(
  url: string,
  timeout: number = 10000,
  proxyUrl?: string,
  maxBytes: number = DEFAULT_MAX_CRL_BYTES,
): Promise<FetchResult> {
  return fetchBinary(url, {
    method: "GET",
    accept: "application/pkix-crl, application/x-pkcs7-crl;q=0.9, */*;q=0.8",
    timeout,
    proxyUrl,
    maxBytes,
  });
}

/**
 * Fetch issuer certificate from AIA extension
 * @param url CA Issuers URL
 * @param timeout Timeout in milliseconds
 * @param proxyUrl Optional CORS proxy URL
 * @returns FetchResult with certificate data
 */
export async function fetchIssuerCertificate(
  url: string,
  timeout: number = 5000,
  proxyUrl?: string,
): Promise<FetchResult> {
  return fetchBinary(url, {
    method: "GET",
    // Some CA servers answer 406 to a bare application/pkix-cert Accept header.
    accept: "application/pkix-cert, application/x-x509-ca-cert;q=0.9, */*;q=0.8",
    timeout,
    proxyUrl,
    maxBytes: DEFAULT_MAX_OCSP_BYTES,
  });
}
