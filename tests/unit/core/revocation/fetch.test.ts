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
});
