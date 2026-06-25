import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_TRUSTED_LIST_SOURCES,
  fetchTrustedListBundleWithDiagnostics,
  mergeForwardUnreachableTerritories,
} from "../src/core/trustedlist/index.ts";
import { buildTrustedListManifest, renderTrustedListJson } from "../src/core/trustedlist/build.ts";
import { renderTrustedListTypeScriptModule } from "./lib/trusted-list-builder.ts";
import { installNativeFetchFallback } from "./lib/native-fetch.ts";
import type { CompactTrustedListBundle } from "../src/core/trustedlist/types.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, "..");
const jsonOutputPath = resolve(projectRoot, "src/data/trusted-list.json");
const tsOutputPath = resolve(projectRoot, "src/data/trusted-list.ts");
const deployOutputRoot = resolve(
  projectRoot,
  process.env.TRUSTED_LIST_OUTPUT_DIR || "trusted-list",
);
const deployBaseUrl = process.env.TRUSTED_LIST_BASE_URL || "/trusted-list";

async function loadPreviousBundle(path: string): Promise<CompactTrustedListBundle | null> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as CompactTrustedListBundle;
  } catch {
    return null;
  }
}

async function main() {
  // Some national TSL endpoints block undici's fingerprint (returning 403) but
  // accept Node's native http(s) client; fall back to it so coverage stays fresh.
  const restoreFetch = installNativeFetchFallback();
  let fetchResult;
  try {
    fetchResult = await fetchTrustedListBundleWithDiagnostics(DEFAULT_TRUSTED_LIST_SOURCES);
  } finally {
    restoreFetch();
  }
  const { bundle: freshBundle, diagnostics } = fetchResult;
  const unreachableTerritories = new Set(diagnostics.unreachableTerritories);

  // Don't regress coverage when every advertised endpoint for a territory was
  // unreachable. Successfully fetched removals remain removed.
  const previousBundle = await loadPreviousBundle(jsonOutputPath);
  const bundle = previousBundle
    ? mergeForwardUnreachableTerritories(freshBundle, previousBundle, unreachableTerritories)
    : freshBundle;

  if (previousBundle) {
    const freshTerritories = new Set(freshBundle.services.map((service) => service[3]));
    const previousTerritories = new Set(previousBundle.services.map((service) => service[3]));
    const carriedTerritories = diagnostics.unreachableTerritories.filter(
      (territory) => previousTerritories.has(territory) && !freshTerritories.has(territory),
    );
    if (carriedTerritories.length > 0) {
      console.warn(
        `Carried forward last-known-good services for unreachable territories: ${carriedTerritories.join(", ")}`,
      );
    }
  }

  const { bundleId, bundleJson, bundleRelativePath, manifest, manifestJson } =
    buildTrustedListManifest(bundle, { baseUrl: deployBaseUrl });
  const tsPayload = renderTrustedListTypeScriptModule(bundle);
  const deployBundlePath = resolve(deployOutputRoot, bundleRelativePath);
  const manifestOutputPath = resolve(deployOutputRoot, "manifest.json");

  await mkdir(dirname(jsonOutputPath), { recursive: true });
  await mkdir(dirname(deployBundlePath), { recursive: true });
  await writeFile(jsonOutputPath, renderTrustedListJson(bundle), "utf8");
  await writeFile(tsOutputPath, tsPayload, "utf8");
  await writeFile(deployBundlePath, bundleJson, "utf8");
  await writeFile(manifestOutputPath, manifestJson, "utf8");

  console.log(
    `Wrote ${bundle.services.length} trusted services from ${bundle.sources.length} LOTL sources.`,
  );
  console.log(`Bundled fallback JSON: ${jsonOutputPath}`);
  console.log(`Bundled fallback TS:   ${tsOutputPath}`);
  console.log(`Builder bundle:        ${deployBundlePath}`);
  console.log(`Builder manifest:      ${manifestOutputPath}`);
  console.log(`Bundle id:             ${bundleId}`);
  console.log(`Bundle URL:            ${manifest.url}`);
}

main().catch((error) => {
  console.error(
    `Trusted-list update failed: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exit(1);
});
