import { mergeForwardUnreachableTerritories } from "../../../../src/core/trustedlist/loader";
import type { CompactTrustedListBundle } from "../../../../src/core/trustedlist/types";

const fresh: CompactTrustedListBundle = {
  v: 2,
  bundleId: "2026-06-25T00-00-00Z",
  generatedAt: "2026-06-25T00:00:00.000Z",
  sources: [["eu", "EU LOTL", "https://example.test/eu-lotl.xml"]],
  dns: ["CN=Fresh LV,C=LV"],
  services: [["lvspki", "lvski", 0, "LV", 1, [[1700000000, null]]]],
};

const previous: CompactTrustedListBundle = {
  v: 2,
  bundleId: "2026-03-14T00-00-00Z",
  generatedAt: "2026-03-14T00:00:00.000Z",
  sources: [["eu", "EU LOTL", "https://example.test/eu-lotl.xml"]],
  dns: ["CN=Old LV,C=LV", "CN=Old EE,C=EE", "CN=Old LT,C=LT"],
  services: [
    ["lvspki-old", "lvski-old", 0, "LV", 1, [[1600000000, null]]],
    ["eespki", "eeski", 1, "EE", 2, [[1600000000, null]]],
    ["ltspki", "ltski", 2, "LT", 1, [[1600000000, null]]],
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
    expect(merged.dns[eeService[2]]).toBe("CN=Old EE,C=EE");
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

  it("returns the fresh bundle unchanged when nothing is missing", () => {
    const merged = mergeForwardUnreachableTerritories(fresh, fresh, new Set(["EE"]));
    expect(merged.services).toHaveLength(fresh.services.length);
  });
});
