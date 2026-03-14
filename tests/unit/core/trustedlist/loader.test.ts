import {
  buildCompactTrustedListBundle,
  buildTrustedListData,
} from "../../../../src/core/trustedlist/loader";
import { TrustedListSource, TrustedService } from "../../../../src/core/trustedlist/types";

const SOURCES: TrustedListSource[] = [
  {
    id: "eu",
    label: "EU LOTL",
    lotlUrl: "https://example.test/eu-lotl.xml",
  },
];

describe("trusted-list loader", () => {
  it("round-trips compact bundles and builds runtime indexes", () => {
    const services: TrustedService[] = [
      {
        skiHex: "aa11",
        spkiSha256Hex: "bb22",
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
      {
        skiHex: "cc33",
        spkiSha256Hex: "dd44",
        subjectDn: "CN=Issuer,O=Example,C=LV",
        country: "LV",
        tspName: "LVRTC",
        serviceType: "CA/QC",
        source: "eu",
        sourceLabel: "EU LOTL",
        history: [
          {
            status: "withdrawn",
            from: "2020-01-01T00:00:00Z",
            to: "2021-01-01T00:00:00Z",
          },
        ],
      },
    ];

    const bundle = buildCompactTrustedListBundle(services, SOURCES, "2026-03-14T00:00:00Z");
    const trustedListData = buildTrustedListData(bundle);

    expect(bundle.sources).toEqual([["eu", "EU LOTL", "https://example.test/eu-lotl.xml"]]);
    expect(bundle.strings).toEqual(["C=LV,CN=Issuer,O=Example", "LVRTC"]);
    expect(trustedListData.generatedAt).toBe("2026-03-14T00:00:00Z");
    expect(trustedListData.services).toHaveLength(2);
    expect(trustedListData.indexes.bySubjectDn.get("C=LV,CN=Issuer,O=Example")).toHaveLength(2);
    expect(trustedListData.indexes.bySki.get("aa11")).toHaveLength(1);
    expect(trustedListData.indexes.bySpkiSha256.get("bb22")).toHaveLength(1);
  });
});
