import {
  fetchBinary,
  fetchOCSP,
  fetchCRL,
  fetchIssuerCertificate,
} from "../../../../src/core/revocation/fetch";

// Mock global fetch
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe("revocation/fetch", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe("fetchBinary", () => {
    it("should fetch directly when no proxyUrl is provided", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await fetchBinary("http://example.com/file.crl");

      expect(mockFetch).toHaveBeenCalledWith("http://example.com/file.crl", expect.any(Object));
    });

    it("should route through proxy when proxyUrl is provided", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await fetchBinary("http://example.com/file.crl", {
        proxyUrl: "https://proxy.example.com/?url=",
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://proxy.example.com/?url=http%3A%2F%2Fexample.com%2Ffile.crl",
        expect.any(Object),
      );
    });

    it("should URL-encode the original URL when using proxy", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const originalUrl = "http://example.com/path?param=value&other=123";
      await fetchBinary(originalUrl, {
        proxyUrl: "https://cors-proxy.workers.dev/?url=",
      });

      const expectedProxiedUrl =
        "https://cors-proxy.workers.dev/?url=" + encodeURIComponent(originalUrl);
      expect(mockFetch).toHaveBeenCalledWith(expectedProxiedUrl, expect.any(Object));
    });

    it("should return error on network failure", async () => {
      mockFetch.mockRejectedValue(new Error("Network error"));

      const result = await fetchBinary("http://example.com/file.crl");

      expect(result.ok).toBe(false);
      expect(result.error).toBe("Network error");
    });

    it("should return error on HTTP error status", async () => {
      const mockResponse = {
        ok: false,
        status: 404,
        statusText: "Not Found",
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await fetchBinary("http://example.com/file.crl");

      expect(result.ok).toBe(false);
      expect(result.status).toBe(404);
      expect(result.error).toBe("HTTP 404: Not Found");
    });
  });

  describe("fetchOCSP", () => {
    it("should pass proxyUrl to fetchBinary", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const request = new ArrayBuffer(100);
      await fetchOCSP("http://ocsp.example.com", request, 5000, "https://proxy.example.com/?url=");

      expect(mockFetch).toHaveBeenCalledWith(
        "https://proxy.example.com/?url=http%3A%2F%2Focsp.example.com",
        expect.objectContaining({
          method: "POST",
        }),
      );
    });

    it("should fetch directly when proxyUrl is undefined", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const request = new ArrayBuffer(100);
      await fetchOCSP("http://ocsp.example.com", request, 5000);

      expect(mockFetch).toHaveBeenCalledWith(
        "http://ocsp.example.com",
        expect.objectContaining({
          method: "POST",
        }),
      );
    });
  });

  describe("fetchCRL", () => {
    it("should pass proxyUrl to fetchBinary", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await fetchCRL("http://crl.example.com/ca.crl", 10000, "https://proxy.example.com/?url=");

      expect(mockFetch).toHaveBeenCalledWith(
        "https://proxy.example.com/?url=http%3A%2F%2Fcrl.example.com%2Fca.crl",
        expect.objectContaining({
          method: "GET",
        }),
      );
    });

    it("should fetch directly when proxyUrl is undefined", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await fetchCRL("http://crl.example.com/ca.crl", 10000);

      expect(mockFetch).toHaveBeenCalledWith(
        "http://crl.example.com/ca.crl",
        expect.objectContaining({
          method: "GET",
        }),
      );
    });
  });

  describe("fetchIssuerCertificate", () => {
    it("should pass proxyUrl to fetchBinary", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await fetchIssuerCertificate(
        "http://ca.example.com/issuer.crt",
        5000,
        "https://proxy.example.com/?url=",
      );

      expect(mockFetch).toHaveBeenCalledWith(
        "https://proxy.example.com/?url=http%3A%2F%2Fca.example.com%2Fissuer.crt",
        expect.objectContaining({
          method: "GET",
        }),
      );
    });

    it("should fetch directly when proxyUrl is undefined", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        arrayBuffer: jest.fn().mockResolvedValue(new ArrayBuffer(10)),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await fetchIssuerCertificate("http://ca.example.com/issuer.crt", 5000);

      expect(mockFetch).toHaveBeenCalledWith(
        "http://ca.example.com/issuer.crt",
        expect.objectContaining({
          method: "GET",
        }),
      );
    });
  });

  describe("URL scheme limits", () => {
    it.each(["file:///etc/passwd", "ftp://example.com/ca.crl", "ldap://example.com/ca", "nope"])(
      "does not fetch %s",
      async (url) => {
        const result = await fetchBinary(url);

        expect(result.ok).toBe(false);
        expect(mockFetch).not.toHaveBeenCalled();
      },
    );

    it("accepts upper-case http schemes", async () => {
      mockFetch.mockResolvedValue(new Response(new Uint8Array([1]), { status: 200 }));

      const result = await fetchBinary("HTTP://example.com/file.crl");

      expect(result.ok).toBe(true);
    });
  });

  describe("response size limits", () => {
    it("rejects a response whose Content-Length exceeds the limit", async () => {
      mockFetch.mockResolvedValue(
        new Response(new Uint8Array(10), {
          status: 200,
          headers: { "Content-Length": String(5 * 1024 * 1024) },
        }),
      );

      const result = await fetchBinary("http://example.com/file.crl", { maxBytes: 1024 });

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/maximum size/);
    });

    it("rejects a streamed body that exceeds the limit", async () => {
      const chunk = new Uint8Array(600);
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(chunk);
          controller.enqueue(chunk);
          controller.close();
        },
      });
      mockFetch.mockResolvedValue(new Response(stream, { status: 200 }));

      const result = await fetchBinary("http://example.com/file.crl", { maxBytes: 1000 });

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/maximum size/);
    });

    it("returns bodies within the limit", async () => {
      mockFetch.mockResolvedValue(new Response(new Uint8Array(1000), { status: 200 }));

      const result = await fetchBinary("http://example.com/file.crl", { maxBytes: 1000 });

      expect(result.ok).toBe(true);
      expect(result.data?.byteLength).toBe(1000);
    });

    it("applies a 1 MB default limit to OCSP responses", async () => {
      mockFetch.mockResolvedValue(new Response(new Uint8Array(1024 * 1024 + 1), { status: 200 }));

      const result = await fetchOCSP("http://ocsp.example.com", new ArrayBuffer(10));

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/maximum size/);
    });

    it("allows CRLs larger than 1 MB by default", async () => {
      mockFetch.mockResolvedValue(new Response(new Uint8Array(2 * 1024 * 1024), { status: 200 }));

      const result = await fetchCRL("http://crl.example.com/ca.crl");

      expect(result.ok).toBe(true);
    });
  });

  describe("timeouts", () => {
    it("keeps the timeout active while the body is read", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        arrayBuffer: () => new Promise<ArrayBuffer>(() => undefined),
      });

      const result = await fetchBinary("http://example.com/file.crl", { timeout: 50 });

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/timeout/i);
    });
  });

  describe("redirects", () => {
    const redirect = (location: string, status = 302) =>
      new Response(null, { status, headers: { Location: location } });

    it("follows a redirect to another http(s) URL", async () => {
      mockFetch
        .mockResolvedValueOnce(redirect("https://example.com/moved.crl"))
        .mockResolvedValueOnce(new Response(new Uint8Array([1, 2, 3]), { status: 200 }));

      const result = await fetchBinary("http://example.com/file.crl");

      expect(result.ok).toBe(true);
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        "https://example.com/moved.crl",
        expect.objectContaining({ redirect: "manual" }),
      );
    });

    it("does not follow a redirect to a non-http scheme", async () => {
      mockFetch.mockResolvedValueOnce(redirect("file:///etc/passwd"));

      const result = await fetchBinary("http://example.com/file.crl");

      expect(result.ok).toBe(false);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("stops after the maximum number of redirects", async () => {
      mockFetch.mockImplementation(async () => redirect("http://example.com/again"));

      const result = await fetchBinary("http://example.com/file.crl", { maxRedirects: 2 });

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/Too many redirects/);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it("switches a POST to GET on a 303 redirect", async () => {
      mockFetch
        .mockResolvedValueOnce(redirect("http://example.com/result", 303))
        .mockResolvedValueOnce(new Response(new Uint8Array([1]), { status: 200 }));

      await fetchOCSP("http://ocsp.example.com", new ArrayBuffer(10));

      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        "http://example.com/result",
        expect.objectContaining({ method: "GET", body: undefined }),
      );
    });
  });
});
