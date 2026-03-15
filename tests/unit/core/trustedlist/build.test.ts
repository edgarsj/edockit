import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildTrustedListManifest,
  formatTrustedListBundleId,
  renderTrustedListJson,
  writeTrustedListBundle,
} from "../../../../src/trusted-list-build";
import type { CompactTrustedListBundle } from "../../../../src/core/trustedlist/types";

const TEST_BUNDLE: CompactTrustedListBundle = {
  v: 2,
  generatedAt: "2026-03-15T00:00:00Z",
  sources: [["eu", "EU LOTL", "https://example.test/eu-lotl.xml"]],
  dns: ["CN=Issuer,O=Example,C=LV"],
  services: [["qhE", "3q2-7w", 0, "LV", 1, [[1704067200, null]]]],
};

describe("trusted-list build helpers", () => {
  it("formats bundle ids from generatedAt timestamps", () => {
    expect(formatTrustedListBundleId(TEST_BUNDLE.generatedAt)).toBe("2026-03-15T00-00-00Z");
  });

  it("builds a manifest with a normalized base URL", () => {
    const result = buildTrustedListManifest(TEST_BUNDLE, {
      baseUrl: "assets/trusted-list/",
    });

    expect(result.bundleId).toBe("2026-03-15T00-00-00Z");
    expect(result.bundleRelativePath).toBe("bundles/2026-03-15T00-00-00Z.json");
    expect(result.manifest.url).toBe("/assets/trusted-list/bundles/2026-03-15T00-00-00Z.json");
    expect(result.manifest.sha256).toHaveLength(64);
  });

  it("writes bundle JSON and optional manifest files", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "edockit-trusted-list-"));
    const outputPath = join(tempDir, "assets", "trusted-list.json");
    const manifestOutputPath = join(tempDir, "assets", "manifest.json");

    try {
      const result = await writeTrustedListBundle({
        bundle: TEST_BUNDLE,
        outputPath,
        manifestOutputPath,
        baseUrl: "/assets",
      });

      expect(result.bundleId).toBe("2026-03-15T00-00-00Z");
      expect(result.outputPath).toBe(outputPath);
      expect(result.bytesWritten).toBe(
        Buffer.byteLength(renderTrustedListJson(TEST_BUNDLE), "utf8"),
      );
      expect(result.manifest?.url).toBe("/assets/bundles/2026-03-15T00-00-00Z.json");
      expect(result.manifestOutputPath).toBe(manifestOutputPath);

      await expect(readFile(outputPath, "utf8")).resolves.toBe(renderTrustedListJson(TEST_BUNDLE));
      await expect(readFile(manifestOutputPath, "utf8")).resolves.toContain(
        '"url": "/assets/bundles/2026-03-15T00-00-00Z.json"',
      );
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
