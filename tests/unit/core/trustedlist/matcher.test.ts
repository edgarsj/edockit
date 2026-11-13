import {
  matchIssuerIdentityToTrustedList,
  matchTrustListQuery,
} from "../../../../src/core/trustedlist/matcher";
import {
  buildCompactTrustedListBundle,
  buildTrustedListData,
} from "../../../../src/core/trustedlist/loader";
import { hexToBase64Url } from "../../../../src/core/trustedlist/normalize";
import {
  CompactTrustedService,
  IssuerIdentity,
  TrustedListSource,
  TrustedService,
} from "../../../../src/core/trustedlist/types";

const SOURCES: TrustedListSource[] = [
  {
    id: "eu",
    label: "EU LOTL",
    lotlUrl: "https://example.test/eu-lotl.xml",
  },
];

function createTrustedListData(services: TrustedService[]) {
  return buildTrustedListData(
    buildCompactTrustedListBundle(services, SOURCES, "2026-03-14T00:00:00Z"),
  );
}

/** Version 2 bundle (full SPKI hash and SKI) for a single service */
function createV2TrustedListData(service: TrustedService) {
  const bundle = buildCompactTrustedListBundle([service], SOURCES, "2026-03-14T00:00:00Z");
  return buildTrustedListData({
    ...bundle,
    v: 2,
    quals: undefined,
    services: bundle.services.map(
      (record) =>
        [record[0], hexToBase64Url(service.skiHex), ...record.slice(2, 7)] as CompactTrustedService,
    ),
  });
}

describe("trusted-list matcher", () => {
  it("filters matches by lookup purpose", () => {
    const trustedListData = createTrustedListData([
      {
        skiHex: "deadbeef",
        spkiSha256Hex: "aa11",
        subjectDn: "CN=Service,O=Example,C=LV",
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
    ]);

    const tsaMatch = matchTrustListQuery(
      {
        purpose: "timestamp_tsa",
        subjectDn: "CN=Service,O=Example,C=LV",
        skiHex: "deadbeef",
        spkiSha256Hex: "aa11",
        time: new Date("2024-06-01T00:00:00Z"),
      },
      trustedListData,
    );

    expect(tsaMatch.found).toBe(false);
  });

  it("prefers exact issuer SPKI matches over weaker evidence", () => {
    const trustedListData = createTrustedListData([
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
    ]);

    const identity: IssuerIdentity = {
      issuerSubjectDn: "CN=Issuer, O=Example, C=lv",
      authorityKeyIdentifierHex: "deadbeef",
      issuerCertificate: {
        subjectDn: "CN=Issuer,O=Example,C=LV",
        spkiSha256Hex: "aa11",
      },
    };

    const match = matchIssuerIdentityToTrustedList(identity, trustedListData, {
      time: new Date("2024-06-01T00:00:00Z"),
    });

    expect(match.found).toBe(true);
    expect(match.confidence).toBe("exact");
    expect(match.trustedAtTime).toBe(true);
    expect(match.detail).toContain("issuer match by SPKI");
  });

  it("uses AKI plus issuer DN from version 2 bundles when the issuer certificate is not available", () => {
    const trustedListData = createV2TrustedListData({
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
    });

    const match = matchIssuerIdentityToTrustedList(
      {
        issuerSubjectDn: "CN=Issuer,O=Example,C=LV",
        authorityKeyIdentifierHex: "deadbeef",
      },
      trustedListData,
      {
        time: new Date("2024-06-01T00:00:00Z"),
      },
    );

    expect(match.found).toBe(true);
    expect(match.confidence).toBe("ski_dn");
    expect(match.trustedAtTime).toBe(true);
    expect(match.detail).toContain("SKI + DN");
  });

  it("returns raw trusted-at-time evidence for DN-only matches", () => {
    const trustedListData = createTrustedListData([
      {
        skiHex: null,
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
    ]);

    const match = matchIssuerIdentityToTrustedList(
      {
        issuerSubjectDn: "CN=Issuer,O=Example,C=LV",
      },
      trustedListData,
      {
        time: new Date("2024-06-01T00:00:00Z"),
      },
    );

    expect(match.found).toBe(true);
    expect(match.confidence).toBe("dn_only");
    expect(match.trustedAtTime).toBe(true);
    expect(match.detail).toContain("Only issuer DN matched");
  });

  it("returns a failed trust result when the issuer is matched but not trusted at signing time", () => {
    const trustedListData = createV2TrustedListData({
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
          from: "2023-01-01T00:00:00Z",
          to: "2024-01-01T00:00:00Z",
        },
        {
          status: "withdrawn",
          from: "2024-01-01T00:00:00Z",
          to: null,
        },
      ],
    });

    const match = matchIssuerIdentityToTrustedList(
      {
        issuerSubjectDn: "CN=Issuer,O=Example,C=LV",
        authorityKeyIdentifierHex: "deadbeef",
      },
      trustedListData,
      {
        time: new Date("2024-06-01T00:00:00Z"),
      },
    );

    expect(match.found).toBe(true);
    expect(match.confidence).toBe("ski_dn");
    expect(match.trustedAtTime).toBe(false);
    expect(match.detail).toContain("not trusted at the requested time");
  });
});

describe("trusted-list match source", () => {
  const sources: TrustedListSource[] = [
    { id: "eu", label: "EU LOTL", lotlUrl: "https://example.test/eu-lotl.xml" },
    { id: "ades", label: "AdES LOTL", lotlUrl: "https://example.test/ades-lotl.xml" },
  ];
  const service = (source: string, country: string, spki: string): TrustedService => ({
    skiHex: null,
    spkiSha256Hex: spki,
    subjectDn: `CN=CA ${country},C=${country}`,
    country,
    tspName: "TSP",
    serviceType: "CA/QC",
    source,
    sourceLabel: source === "eu" ? "EU LOTL" : "AdES LOTL",
    history: [{ status: "granted", from: "2024-01-01T00:00:00Z", to: null }],
  });

  it("reports which trusted-list source a match came from", () => {
    const bundle = buildCompactTrustedListBundle(
      [service("eu", "LV", "aa11"), service("ades", "EG", "bb22")],
      sources,
      "2026-03-14T00:00:00Z",
    );
    const data = buildTrustedListData(JSON.parse(JSON.stringify(bundle)));
    const query = (spkiSha256Hex: string, country: string) =>
      matchTrustListQuery(
        {
          purpose: "signature_issuer",
          subjectDn: `CN=CA ${country},C=${country}`,
          spkiSha256Hex,
          time: new Date("2025-01-01T00:00:00Z"),
        },
        data,
      );

    expect(query("aa11", "LV")).toMatchObject({ found: true, source: "eu", country: "LV" });
    expect(query("bb22", "EG")).toMatchObject({
      found: true,
      source: "ades",
      sourceLabel: "AdES LOTL",
      country: "EG",
    });
  });

  it("omits the source for bundles without source indexes", () => {
    const bundle = buildCompactTrustedListBundle(
      [service("eu", "LV", "aa11")],
      sources,
      "2026-03-14T00:00:00Z",
    );
    bundle.services = bundle.services.map(
      (record) => record.slice(0, 6) as unknown as (typeof bundle.services)[number],
    );
    const match = matchTrustListQuery(
      {
        purpose: "signature_issuer",
        subjectDn: "CN=CA LV,C=LV",
        spkiSha256Hex: "aa11",
        time: new Date("2025-01-01T00:00:00Z"),
      },
      buildTrustedListData(bundle),
    );
    expect(match.found).toBe(true);
    expect(match.source).toBeUndefined();
  });
});
