// src/core/revocation/fetch.ts

/**
 * Cross-platform HTTP fetch for OCSP and CRL requests
 * Works in both browser and Node.js environments
 */

export interface FetchOptions {
  /** Request timeout in milliseconds */
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
}

export interface FetchResult {
  ok: boolean;
  status: number;
  data?: ArrayBuffer;
  error?: string;
}

/**
 * Fetch binary data from a URL with timeout support
 * @param url URL to fetch
 * @param options Fetch options
 * @returns FetchResult with binary data or error
 */
export async function fetchBinary(url: string, options: FetchOptions = {}): Promise<FetchResult> {
  const { timeout = 10000, method = "GET", body, contentType, accept, proxyUrl } = options;

  // Apply proxy URL if provided
  const fetchUrl = proxyUrl ? `${proxyUrl}${encodeURIComponent(url)}` : url;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const headers: Record<string, string> = {};
    if (contentType) {
      headers["Content-Type"] = contentType;
    }
    if (accept) {
      headers["Accept"] = accept;
    }

    const response = await fetch(fetchUrl, {
      method,
      headers,
      body: body ? new Uint8Array(body) : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        error: `HTTP ${response.status}: ${response.statusText}`,
      };
    }

    const data = await response.arrayBuffer();
    return {
      ok: true,
      status: response.status,
      data,
    };
  } catch (error) {
    clearTimeout(timeoutId);

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
  }
}

/**
 * Fetch OCSP response
 * @param url OCSP responder URL
 * @param request DER-encoded OCSP request
 * @param timeout Timeout in milliseconds
 * @param proxyUrl Optional CORS proxy URL
 * @returns FetchResult with OCSP response data
 */
export async function fetchOCSP(
  url: string,
  request: ArrayBuffer,
  timeout: number = 5000,
  proxyUrl?: string,
): Promise<FetchResult> {
  return fetchBinary(url, {
    method: "POST",
    body: request,
    contentType: "application/ocsp-request",
    accept: "application/ocsp-response",
    timeout,
    proxyUrl,
  });
}

/**
 * Fetch CRL from distribution point
 * @param url CRL distribution point URL
 * @param timeout Timeout in milliseconds
 * @param proxyUrl Optional CORS proxy URL
 * @returns FetchResult with CRL data
 */
export async function fetchCRL(
  url: string,
  timeout: number = 10000,
  proxyUrl?: string,
): Promise<FetchResult> {
  return fetchBinary(url, {
    method: "GET",
    accept: "application/pkix-crl",
    timeout,
    proxyUrl,
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
    accept: "application/pkix-cert",
    timeout,
    proxyUrl,
  });
}
