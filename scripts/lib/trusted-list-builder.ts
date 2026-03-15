import type { CompactTrustedListBundle } from "../../src/core/trustedlist/types.ts";

export function renderTrustedListTypeScriptModule(bundle: CompactTrustedListBundle): string {
  return `import type { CompactTrustedListBundle } from "../core/trustedlist/types";

const trustedListBundle: CompactTrustedListBundle = ${JSON.stringify(bundle)};

export default trustedListBundle;
`;
}
