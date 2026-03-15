import { buildCompactTrustedListBundle } from "../../../../src/core/trustedlist/loader";
import { createTrustListProvider } from "../../../../src/trusted-list";
import { createBundledTrustListProvider } from "../../../../src/trusted-list-bundled";
import { createRemoteTrustListProvider } from "../../../../src/trusted-list-http";
import type {
  TrustListMatch,
  TrustListProvider,
  TrustListQuery,
} from "../../../../src/core/trustedlist/contract";
import type { TrustedListSource, TrustedService } from "../../../../src/core/trustedlist/types";

const SOURCES: TrustedListSource[] = [
  {
    id: "eu",
    label: "EU LOTL",
    lotlUrl: "https://example.test/eu-lotl.xml",
  },
];

function createBundle(services: TrustedService[]) {
  return buildCompactTrustedListBundle(services, SOURCES, "2026-03-14T00:00:00Z");
}

describe("trusted-list providers", () => {
  it("requires explicit data or url for the local provider", () => {
    expect(() => createTrustListProvider(undefined as never)).toThrow(
      "createTrustListProvider requires either { data } or { url }",
    );
  });

  it("creates a local provider from compact bundle data", async () => {
    const provider = createTrustListProvider({
      data: createBundle([
        {
          skiHex: "deadbeef",
          spkiSha256Hex: "aa11",
          subjectDn: "CN=Issuer,O=Example,C=LV",
          country: "LV",
          tspName: "LVRTC",
          serviceType: "CA/QC",
          source: "eu",
          sourceLabel: "EU LOTL",
          history: [
            {
              status: "granted",
              from: "2024-01-01T00:00:00Z",
              to: null,
            },
          ],
        },
      ]),
    });

    const match = await provider.match({
      purpose: "signature_issuer",
      subjectDn: "CN=Issuer,O=Example,C=LV",
      skiHex: "deadbeef",
      spkiSha256Hex: "aa11",
      time: new Date("2024-06-01T00:00:00Z"),
    });

    expect(match).toMatchObject({
      found: true,
      trustedAtTime: true,
      confidence: "exact",
      country: "LV",
    });
  });

  it("loads a provider bundle from URL only once", async () => {
    const fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () =>
        createBundle([
          {
            skiHex: "deadbeef",
            spkiSha256Hex: "aa11",
            subjectDn: "CN=Issuer,O=Example,C=LV",
            country: "LV",
            tspName: "LVRTC",
            serviceType: "CA/QC",
            source: "eu",
            sourceLabel: "EU LOTL",
            history: [
              {
                status: "granted",
                from: "2024-01-01T00:00:00Z",
                to: null,
              },
            ],
          },
        ]),
    });

    const provider = createTrustListProvider({
      url: "https://example.test/trusted-list.json",
      fetch,
    });

    const query: TrustListQuery = {
      purpose: "signature_issuer",
      subjectDn: "CN=Issuer,O=Example,C=LV",
      skiHex: "deadbeef",
      spkiSha256Hex: "aa11",
      time: new Date("2024-06-01T00:00:00Z"),
    };

    const firstMatch = await provider.match(query);
    const secondMatch = await provider.match(query);

    expect(firstMatch.found).toBe(true);
    expect(secondMatch.found).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("retries URL bundle loading after a transient fetch failure", async () => {
    const fetch = jest
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () =>
          createBundle([
            {
              skiHex: "deadbeef",
              spkiSha256Hex: "aa11",
              subjectDn: "CN=Issuer,O=Example,C=LV",
              country: "LV",
              tspName: "LVRTC",
              serviceType: "CA/QC",
              source: "eu",
              sourceLabel: "EU LOTL",
              history: [
                {
                  status: "granted",
                  from: "2024-01-01T00:00:00Z",
                  to: null,
                },
              ],
            },
          ]),
      });

    const provider = createTrustListProvider({
      url: "https://example.test/trusted-list.json",
      fetch,
    });

    const query: TrustListQuery = {
      purpose: "signature_issuer",
      subjectDn: "CN=Issuer,O=Example,C=LV",
      skiHex: "deadbeef",
      spkiSha256Hex: "aa11",
      time: new Date("2024-06-01T00:00:00Z"),
    };

    await expect(provider.match(query)).rejects.toThrow(
      'Failed to fetch trusted-list data from "https://example.test/trusted-list.json": HTTP 503',
    );

    await expect(provider.match(query)).resolves.toMatchObject({
      found: true,
      trustedAtTime: true,
      confidence: "exact",
      country: "LV",
    });

    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("warns once when the bundled snapshot is older than 14 days", async () => {
    const dateNowSpy = jest
      .spyOn(Date, "now")
      .mockReturnValue(new Date("2100-01-01T00:00:00Z").getTime());
    const consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const provider = createBundledTrustListProvider();

    await provider.match({
      purpose: "signature_issuer",
      subjectDn: "CN=Issuer,O=Example,C=LV",
      time: new Date("2024-06-01T00:00:00Z"),
    });
    await provider.match({
      purpose: "signature_issuer",
      subjectDn: "CN=Issuer,O=Example,C=LV",
      time: new Date("2024-06-01T00:00:00Z"),
    });

    expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
    expect(consoleWarnSpy.mock.calls[0][0]).toContain("Using bundled trusted-list snapshot");

    dateNowSpy.mockRestore();
    consoleWarnSpy.mockRestore();
  });

  it("creates a remote HTTP provider", async () => {
    const match: TrustListMatch = {
      found: true,
      trustedAtTime: true,
      confidence: "exact",
      country: "LV",
      detail: "Trusted-list issuer match by SPKI, trusted at the requested time",
    };
    const fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => match,
    });

    const provider: TrustListProvider = createRemoteTrustListProvider({
      url: "https://example.test/api/trust-list/match",
      fetch,
      headers: {
        "x-test-header": "1",
      },
    });

    const query: TrustListQuery = {
      purpose: "signature_issuer",
      subjectDn: "CN=Issuer,O=Example,C=LV",
      skiHex: "deadbeef",
      spkiSha256Hex: "aa11",
      time: new Date("2024-06-01T00:00:00Z"),
    };

    await expect(provider.match(query)).resolves.toEqual(match);
    expect(fetch).toHaveBeenCalledWith("https://example.test/api/trust-list/match", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-test-header": "1",
      },
      body: JSON.stringify(query),
    });
  });
});
