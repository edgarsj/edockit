import {
  matchIssuerIdentityToTrustedList,
  matchTrustListQuery,
} from "../../../../src/core/trustedlist/matcher";
import {
  buildCompactTrustedListBundle,
  buildTrustedListData,
} from "../../../../src/core/trustedlist/loader";
import {
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

  it("uses AKI plus issuer DN when the issuer certificate is not available", () => {
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
            from: "2023-01-01T00:00:00Z",
            to: "2024-01-01T00:00:00Z",
          },
          {
            status: "withdrawn",
            from: "2024-01-01T00:00:00Z",
            to: null,
          },
        ],
      },
    ]);

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
