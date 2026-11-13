export {
  DEFAULT_TRUSTED_LIST_SOURCES,
  fetchTrustedListBundle,
  fetchTrustedListBundleWithDiagnostics,
  updateTrustedList,
} from "./core/trustedlist/index";
export type { TrustedListFetchDiagnostics, TrustedListFetchResult } from "./core/trustedlist/index";

export { mergeForwardUnreachableTerritories } from "./core/trustedlist/loader";

export {
  buildTrustedListManifest,
  formatTrustedListBundleId,
  generateTrustedListBundle,
  renderTrustedListJson,
  writeTrustedListBundle,
} from "./core/trustedlist/build";

export type {
  BuildTrustedListManifestOptions,
  GenerateTrustedListBundleOptions,
  RenderTrustedListJsonOptions,
  WriteTrustedListBundleOptions,
  WriteTrustedListBundleResult,
} from "./core/trustedlist/build";

export type {
  CompactTrustedListBundle,
  TrustedListBundleManifest,
  TrustedListFetchOptions,
  TrustedListSource,
} from "./core/trustedlist/types";
