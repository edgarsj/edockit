import bundledTrustedListBundle from "../../data/trusted-list.js";
import type { TrustListProvider } from "./contract";
import { buildTrustedListData, createEmptyTrustedListBundle } from "./loader";
import { createTrustListProvider } from "./reference-provider";
import type { TrustedListData } from "./types";

const BUNDLED_SNAPSHOT_MAX_AGE_DAYS = 14;
const BUNDLED_SNAPSHOT_MAX_AGE_MS = BUNDLED_SNAPSHOT_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;

let bundledTrustedListCache: TrustedListData | null = null;
let hasWarnedAboutStaleBundledSnapshot = false;

function getBundledTrustedListData(): TrustedListData {
  if (!bundledTrustedListCache) {
    bundledTrustedListCache = buildTrustedListData(
      bundledTrustedListBundle || createEmptyTrustedListBundle(),
    );
  }

  return bundledTrustedListCache;
}

function warnIfBundledSnapshotIsStale(generatedAt: string) {
  if (hasWarnedAboutStaleBundledSnapshot) {
    return;
  }

  const generatedTimeMs = Date.parse(generatedAt);
  if (Number.isNaN(generatedTimeMs)) {
    return;
  }

  if (Date.now() - generatedTimeMs <= BUNDLED_SNAPSHOT_MAX_AGE_MS) {
    return;
  }

  hasWarnedAboutStaleBundledSnapshot = true;
  console.warn(
    `[edockit] Using bundled trusted-list snapshot generated at ${generatedAt}. It is older than ${BUNDLED_SNAPSHOT_MAX_AGE_DAYS} days and may be stale. Prefer a hosted or freshly generated trusted-list JSON.`,
  );
}

export function createBundledTrustListProvider(): TrustListProvider {
  const trustedListData = getBundledTrustedListData();
  warnIfBundledSnapshotIsStale(trustedListData.generatedAt);
  return createTrustListProvider({ data: trustedListData });
}
