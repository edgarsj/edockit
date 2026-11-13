import { mergeForwardUnreachableTerritories } from "../../../../src/core/trustedlist/loader";
import type { CompactTrustedListBundle } from "../../../../src/core/trustedlist/types";

const fresh: CompactTrustedListBundle = {
  v: 3,
  bundleId: "2026-06-25T00-00-00Z",
  generatedAt: "2026-06-25T00:00:00.000Z",
  sources: [["eu", "EU LOTL", "https://example.test/eu-lotl.xml"]],
  dns: ["C=LV,CN=Fresh LV"],
  quals: [],
  services: [["lvspki", null, 0, "LV", 1, [[1700000000, null]]]],
};

const previous: CompactTrustedListBundle = {
  v: 3,
  bundleId: "2026-03-14T00-00-00Z",
  generatedAt: "2026-03-14T00:00:00.000Z",
  sources: [["eu", "EU LOTL", "https://example.test/eu-lotl.xml"]],
  dns: ["C=LV,CN=Old LV", "C=EE,CN=Old EE", "C=LT,CN=Old LT"],
  quals: [],
  services: [
    ["lvspki-old", null, 0, "LV", 1, [[1600000000, null]]],
    ["eespki", null, 1, "EE", 2, [[1600000000, null]]],
    ["ltspki", null, 2, "LT", 1, [[1600000000, null]]],
  ],
};

describe("mergeForwardUnreachableTerritories", () => {
  it("carries forward services only for explicitly unreachable territories", () => {
    const merged = mergeForwardUnreachableTerritories(fresh, previous, new Set(["EE"]));

    const countries = new Set(merged.services.map((s) => s[3]));
    expect(countries.has("LV")).toBe(true);
    expect(countries.has("EE")).toBe(true);
    expect(countries.has("LT")).toBe(false);
  });

  it("preserves the carried-forward service's subject DN via remapped index", () => {
    const merged = mergeForwardUnreachableTerritories(fresh, previous, new Set(["EE"]));
    const eeService = merged.services.find((s) => s[3] === "EE")!;
    expect(merged.dns[eeService[2]]).toBe("C=EE,CN=Old EE");
  });

  it("does not carry forward territories already present in the fresh bundle (fresh wins)", () => {
    const merged = mergeForwardUnreachableTerritories(fresh, previous, new Set(["LV", "EE"]));
    const lvServices = merged.services.filter((s) => s[3] === "LV");
    // Only the fresh LV service, not the stale one.
    expect(lvServices).toHaveLength(1);
    expect(lvServices[0][0]).toBe("lvspki");
  });

  it("does not resurrect a missing territory without an explicit fetch failure", () => {
    const merged = mergeForwardUnreachableTerritories(fresh, previous, new Set());

    expect(merged.services.map((service) => service[3])).toEqual(["LV"]);
  });

  it("keeps the fresh snapshot's generatedAt and bundleId", () => {
    const merged = mergeForwardUnreachableTerritories(fresh, previous, new Set(["EE"]));
    expect(merged.generatedAt).toBe(fresh.generatedAt);
    expect(merged.bundleId).toBe(fresh.bundleId);
  });

  it("rejects version 2 bundles", () => {
    const v2: CompactTrustedListBundle = { ...previous, v: 2, quals: undefined };
    expect(() => mergeForwardUnreachableTerritories(fresh, v2, new Set(["EE"]))).toThrow(
      "requires version 3 bundles",
    );
  });

  it("returns the fresh bundle unchanged when nothing is missing", () => {
    const merged = mergeForwardUnreachableTerritories(fresh, fresh, new Set(["EE"]));
    expect(merged.services).toHaveLength(fresh.services.length);
  });
});
