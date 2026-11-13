import type { CompactTrustedListBundle } from "../../src/core/trustedlist/types.ts";

/**
 * Render the bundled snapshot module. The data is embedded as a JSON string
 * parsed at load time: JavaScript engines parse JSON considerably faster than
 * an equivalent object literal.
 */
export function renderTrustedListTypeScriptModule(bundle: CompactTrustedListBundle): string {
  const literal = JSON.stringify(bundle)
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  return `import type { CompactTrustedListBundle } from "../core/trustedlist/types";

const trustedListBundle: CompactTrustedListBundle = JSON.parse('${literal}');

export default trustedListBundle;
`;
}
