import { createHash } from "node:crypto";
import type {
  CompactTrustedListBundle,
  TrustedListBundleManifest,
} from "../../src/core/trustedlist/types.ts";

const DEFAULT_TRUSTED_LIST_BASE_URL = "/trusted-list";

function normalizeBaseUrl(baseUrl: string): string {
  const trimmedBaseUrl = baseUrl.trim() || DEFAULT_TRUSTED_LIST_BASE_URL;
  const withLeadingSlash = trimmedBaseUrl.startsWith("/") ? trimmedBaseUrl : `/${trimmedBaseUrl}`;
  return withLeadingSlash.replace(/\/+$/g, "");
}

export function formatTrustedListBundleId(generatedAt: string): string {
  const parsedDate = new Date(generatedAt);

  if (Number.isNaN(parsedDate.getTime())) {
    throw new Error(`Invalid trusted-list generatedAt timestamp "${generatedAt}"`);
  }

  return parsedDate
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z")
    .replace(/:/g, "-");
}

export function renderTrustedListJson(bundle: CompactTrustedListBundle): string {
  return `${JSON.stringify(bundle, null, 2)}\n`;
}

export function renderTrustedListTypeScriptModule(bundle: CompactTrustedListBundle): string {
  return `import type { CompactTrustedListBundle } from "../core/trustedlist/types";

const trustedListBundle: CompactTrustedListBundle = ${JSON.stringify(bundle, null, 2)};

export default trustedListBundle;
`;
}

export function buildTrustedListManifest(
  bundle: CompactTrustedListBundle,
  options: {
    baseUrl?: string;
  } = {},
): {
  bundleId: string;
  bundleJson: string;
  bundleRelativePath: string;
  manifest: TrustedListBundleManifest;
  manifestJson: string;
} {
  const bundleId = formatTrustedListBundleId(bundle.generatedAt);
  const bundleJson = renderTrustedListJson(bundle);
  const bundleRelativePath = `bundles/${bundleId}.json`;
  const baseUrl = normalizeBaseUrl(options.baseUrl || DEFAULT_TRUSTED_LIST_BASE_URL);
  const manifest: TrustedListBundleManifest = {
    schemaVersion: 1,
    bundleId,
    generatedAt: bundle.generatedAt,
    url: `${baseUrl}/${bundleRelativePath}`,
    sha256: createHash("sha256").update(bundleJson).digest("hex"),
  };

  return {
    bundleId,
    bundleJson,
    bundleRelativePath,
    manifest,
    manifestJson: `${JSON.stringify(manifest, null, 2)}\n`,
  };
}
