import {
  buildCompactTrustedListBundle,
  createEmptyTrustedListBundle,
  formatTrustedListBundleId,
} from "../../../../src/core/trustedlist/loader";
import { TrustedListSource, TrustedService } from "../../../../src/core/trustedlist/types";

const SOURCES: TrustedListSource[] = [
  { id: "eu", label: "EU LOTL", lotlUrl: "https://example.test/eu-lotl.xml" },
];

const SERVICES: TrustedService[] = [
  {
    skiHex: "aa11",
    spkiSha256Hex: "bb22",
    subjectDn: "CN=Issuer,O=Example,C=LV",
    country: "LV",
    tspName: "LVRTC",
    serviceType: "CA/QC",
    source: "eu",
    sourceLabel: "EU LOTL",
    history: [{ status: "granted", from: "2024-01-01T00:00:00Z", to: null }],
  },
];

describe("compact bundle bundleId", () => {
  it("stamps a non-null bundleId derived from generatedAt", () => {
    const bundle = buildCompactTrustedListBundle(SERVICES, SOURCES, "2026-06-25T18:30:00.000Z");

    expect(bundle.bundleId).toBe("2026-06-25T18-30-00Z");
    expect(bundle.bundleId).toBe(formatTrustedListBundleId(bundle.generatedAt));
  });

  it("stamps a bundleId on the empty bundle as well", () => {
    expect(createEmptyTrustedListBundle().bundleId).toBeTruthy();
  });
});
