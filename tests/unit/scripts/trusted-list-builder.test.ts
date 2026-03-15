import {
  buildTrustedListManifest,
  formatTrustedListBundleId,
} from "../../../src/trusted-list-build";
import type { CompactTrustedListBundle } from "../../../src/core/trustedlist/types";

const BUNDLE: CompactTrustedListBundle = {
  v: 2,
  generatedAt: "2026-03-14T12:34:56.789Z",
  sources: [["eu", "EU LOTL", "https://example.test/eu-lotl.xml"]],
  dns: ["C=LV,CN=Issuer,O=Example"],
  services: [["qxE", "uiI", 0, "LV", 1, [[1704067200, null]]]],
};

describe("trusted-list builder", () => {
  it("formats versioned bundle ids from generated timestamps", () => {
    expect(formatTrustedListBundleId("2026-03-14T12:34:56.789Z")).toBe("2026-03-14T12-34-56Z");
  });

  it("builds a manifest that points at a versioned bundle path", () => {
    const artifact = buildTrustedListManifest(BUNDLE, {
      baseUrl: "trusted-list/",
    });

    expect(artifact.bundleId).toBe("2026-03-14T12-34-56Z");
    expect(artifact.bundleRelativePath).toBe("bundles/2026-03-14T12-34-56Z.json");
    expect(artifact.manifest).toEqual({
      schemaVersion: 1,
      bundleId: "2026-03-14T12-34-56Z",
      generatedAt: "2026-03-14T12:34:56.789Z",
      url: "/trusted-list/bundles/2026-03-14T12-34-56Z.json",
      sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect(JSON.parse(artifact.manifestJson)).toEqual(artifact.manifest);
  });

  it("preserves absolute trusted-list base URLs", () => {
    const artifact = buildTrustedListManifest(BUNDLE, {
      baseUrl: "https://cdn.example.com/trusted-list/",
    });

    expect(artifact.manifest.url).toBe(
      "https://cdn.example.com/trusted-list/bundles/2026-03-14T12-34-56Z.json",
    );
  });
});
