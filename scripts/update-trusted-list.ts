import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_TRUSTED_LIST_SOURCES,
  fetchTrustedListBundle,
} from "../src/core/trustedlist/index.ts";
import {
  buildTrustedListManifest,
  renderTrustedListTypeScriptModule,
} from "./lib/trusted-list-builder.ts";

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

async function main() {
  const bundle = await fetchTrustedListBundle(DEFAULT_TRUSTED_LIST_SOURCES);
  const { bundleId, bundleJson, bundleRelativePath, manifest, manifestJson } =
    buildTrustedListManifest(bundle, { baseUrl: deployBaseUrl });
  const tsPayload = renderTrustedListTypeScriptModule(bundle);
  const deployBundlePath = resolve(deployOutputRoot, bundleRelativePath);
  const manifestOutputPath = resolve(deployOutputRoot, "manifest.json");

  await mkdir(dirname(jsonOutputPath), { recursive: true });
  await mkdir(dirname(deployBundlePath), { recursive: true });
  await writeFile(jsonOutputPath, bundleJson, "utf8");
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
