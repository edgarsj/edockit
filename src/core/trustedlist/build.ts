import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { DEFAULT_TRUSTED_LIST_SOURCES, fetchTrustedListBundle } from "./index";
import type {
  CompactTrustedListBundle,
  TrustedListBundleManifest,
  TrustedListFetchOptions,
  TrustedListSource,
} from "./types";

const DEFAULT_TRUSTED_LIST_BASE_URL = "/trusted-list";

export interface RenderTrustedListJsonOptions {
  pretty?: boolean;
}

export interface BuildTrustedListManifestOptions {
  baseUrl?: string;
  pretty?: boolean;
}

export interface WriteTrustedListBundleOptions {
  bundle: CompactTrustedListBundle;
  outputPath: string;
  pretty?: boolean;
  manifestOutputPath?: string;
  baseUrl?: string;
}

export interface WriteTrustedListBundleResult {
  bundle: CompactTrustedListBundle;
  bundleId: string;
  outputPath: string;
  bytesWritten: number;
  manifest?: TrustedListBundleManifest;
  manifestOutputPath?: string;
}

export interface GenerateTrustedListBundleOptions extends TrustedListFetchOptions {
  outputPath: string;
  sources?: TrustedListSource[];
  pretty?: boolean;
  manifestOutputPath?: string;
  baseUrl?: string;
}

function normalizeBaseUrl(baseUrl: string): string {
  const trimmedBaseUrl = baseUrl.trim() || DEFAULT_TRUSTED_LIST_BASE_URL;
  const isAbsoluteUrl = /^(?:[a-z][a-z\d+\-.]*:)?\/\//i.test(trimmedBaseUrl);
  const withLeadingSlash =
    trimmedBaseUrl.startsWith("/") || isAbsoluteUrl ? trimmedBaseUrl : `/${trimmedBaseUrl}`;
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

export function renderTrustedListJson(
  bundle: CompactTrustedListBundle,
  options: RenderTrustedListJsonOptions = {},
): string {
  return `${JSON.stringify(bundle, null, options.pretty ? 2 : undefined)}\n`;
}

export function buildTrustedListManifest(
  bundle: CompactTrustedListBundle,
  options: BuildTrustedListManifestOptions = {},
): {
  bundleId: string;
  bundleJson: string;
  bundleRelativePath: string;
  manifest: TrustedListBundleManifest;
  manifestJson: string;
} {
  const bundleId = formatTrustedListBundleId(bundle.generatedAt);
  const bundleJson = renderTrustedListJson(bundle, {
    pretty: options.pretty,
  });
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

export async function writeTrustedListBundle(
  options: WriteTrustedListBundleOptions,
): Promise<WriteTrustedListBundleResult> {
  const bundleJson = renderTrustedListJson(options.bundle, {
    pretty: options.pretty,
  });
  const bundleId = formatTrustedListBundleId(options.bundle.generatedAt);

  await mkdir(dirname(options.outputPath), { recursive: true });
  await writeFile(options.outputPath, bundleJson, "utf8");

  let manifest: TrustedListBundleManifest | undefined;
  if (options.manifestOutputPath) {
    const builtManifest = buildTrustedListManifest(options.bundle, {
      baseUrl: options.baseUrl,
      pretty: options.pretty,
    });
    manifest = builtManifest.manifest;

    await mkdir(dirname(options.manifestOutputPath), { recursive: true });
    await writeFile(options.manifestOutputPath, builtManifest.manifestJson, "utf8");
  }

  return {
    bundle: options.bundle,
    bundleId,
    outputPath: options.outputPath,
    bytesWritten: Buffer.byteLength(bundleJson, "utf8"),
    ...(manifest
      ? {
          manifest,
          manifestOutputPath: options.manifestOutputPath,
        }
      : {}),
  };
}

export async function generateTrustedListBundle(
  options: GenerateTrustedListBundleOptions,
): Promise<WriteTrustedListBundleResult> {
  const { sources, timeout, proxyUrl, ...writeOptions } = options;
  const bundle = await fetchTrustedListBundle(sources || DEFAULT_TRUSTED_LIST_SOURCES, {
    timeout,
    proxyUrl,
  });

  return writeTrustedListBundle({
    ...writeOptions,
    bundle,
  });
}
