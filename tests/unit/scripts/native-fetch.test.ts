import http from "node:http";
import type { AddressInfo } from "node:net";
import { installNativeFetchFallback } from "../../../scripts/lib/native-fetch";

describe("installNativeFetchFallback", () => {
  let server: http.Server;
  let baseUrl: string;
  const originalFetch = globalThis.fetch;

  beforeAll((done) => {
    server = http.createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/xml" });
      res.end("<TrustServiceStatusList/>");
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${port}/tsl.xml`;
      done();
    });
  });

  afterAll((done) => {
    globalThis.fetch = originalFetch;
    server.close(() => done());
  });

  it("falls back to the native client when the wrapped fetch returns 403", async () => {
    globalThis.fetch = jest.fn().mockResolvedValue(new Response("blocked", { status: 403 }));
    const restore = installNativeFetchFallback(5000);

    const response = await globalThis.fetch(baseUrl);

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("TrustServiceStatusList");
    restore();
  });

  it("falls back to the native client when the wrapped fetch throws on GET", async () => {
    globalThis.fetch = jest.fn().mockRejectedValue(new Error("fingerprint reset"));
    const restore = installNativeFetchFallback(5000);

    const response = await globalThis.fetch(baseUrl);

    expect(response.status).toBe(200);
    restore();
  });

  it("passes non-403 responses straight through without hitting the network", async () => {
    const inner = jest.fn().mockResolvedValue(new Response("ok", { status: 200 }));
    globalThis.fetch = inner;
    const restore = installNativeFetchFallback(5000);

    const response = await globalThis.fetch("http://example.invalid/never-reached");

    expect(response.status).toBe(200);
    expect(inner).toHaveBeenCalledTimes(1);
    restore();
  });

  it("restores the original fetch", () => {
    const sentinel = jest.fn();
    globalThis.fetch = sentinel as unknown as typeof fetch;
    const restore = installNativeFetchFallback();
    expect(globalThis.fetch).not.toBe(sentinel);
    restore();
    expect(globalThis.fetch).toBe(sentinel);
  });
});
