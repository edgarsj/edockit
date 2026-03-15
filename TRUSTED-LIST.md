# Trusted List Usage

This document describes the intended trusted-list integration model for `edockit`.

## Package Surfaces

`edockit` exposes the verification API and the trusted-list contract types:

- `verifySignature`
- `TrustListProvider`
- `TrustListQuery`
- `TrustListMatch`

Trusted-list runtime is opt-in and split into subpaths:

- `edockit/trusted-list`
  - local compact-JSON provider
  - use this for app-hosted JSON data
- `edockit/trusted-list/build`
  - Node.js-only trusted-list bundle generation helpers
  - use this in CI or app build scripts to generate your own JSON
- `edockit/trusted-list/http`
  - tiny remote API wrapper
  - use this if trust matching happens on your server
- `edockit/trusted-list/bundled`
  - convenience bundled fallback snapshot
  - use only if you explicitly want the library-shipped snapshot

## Recommended Production Setup

For a first production version, use:

- `edockit`
- `edockit/trusted-list`
- your own hosted compact trusted-list JSON

Do not use the bundled fallback as the main production path.

This avoids:

- duplicating trusted-list data in your app and in the package
- tying freshness to npm package releases
- shipping extra trusted-list bytes you do not control

## Browser: Local JSON

```typescript
import { parseEdoc, verifySignature } from "edockit";
import { createTrustListProvider } from "edockit/trusted-list";

const trustListProvider = createTrustListProvider({
  url: "/assets/trusted-list.json",
});

const container = parseEdoc(fileBuffer);

const result = await verifySignature(container.signatures[0], container.files, {
  includeChecklist: true,
  trustListProvider,
});
```

This is the preferred default for normal web apps.

## Node.js: Local JSON

```typescript
import { readFileSync } from "node:fs";
import { parseEdoc, verifySignature } from "edockit";
import { createTrustListProvider } from "edockit/trusted-list";

const trustedListBundle = JSON.parse(readFileSync("./trusted-list.json", "utf8"));
const trustListProvider = createTrustListProvider({
  data: trustedListBundle,
});

const container = parseEdoc(fileBuffer);

const result = await verifySignature(container.signatures[0], container.files, {
  trustListProvider,
});
```

## Provider Contract

The provider answers one narrow question:

> Was this service trusted at time `T` for this purpose?

The verifier combines that with timestamp, certificate, and revocation checks into the final signature result.

```typescript
type TrustListQueryPurpose = "signature_issuer" | "timestamp_tsa";

interface TrustListQuery {
  purpose: TrustListQueryPurpose;
  time: Date;
  spkiSha256Hex?: string | null;
  skiHex?: string | null;
  subjectDn?: string | null;
}

interface TrustListMatch {
  found: boolean;
  trustedAtTime?: boolean;
  confidence?: "exact" | "ski_dn" | "dn_only";
  country?: string;
  detail?: string;
}

interface TrustListProvider {
  match(query: TrustListQuery): Promise<TrustListMatch>;
}
```

Notes:

- `purpose` distinguishes signer-issuer matching from timestamp-authority matching.
- `time` is required because trust-list answers are historical.
- `subjectDn` should be the normalized X.500 DN used by the matcher.
- `dn_only` matches are weak evidence. `verifySignature()` keeps them `indeterminate` unless `allowWeakDnOnlyTrustMatch` is enabled.

## Remote API Example

If you want a server-side trust-match API, you can either use the tiny helper or write the provider inline.

```typescript
import { verifySignature, type TrustListProvider } from "edockit";

const trustListProvider: TrustListProvider = {
  async match(query) {
    const response = await fetch("/api/trust-list/match", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(query),
    });

    if (!response.ok) {
      throw new Error(`Trust-list lookup failed: HTTP ${response.status}`);
    }

    return response.json();
  },
};

const result = await verifySignature(signature, files, {
  trustListProvider,
});
```

The packaged helper is equivalent in spirit:

```typescript
import { createRemoteTrustListProvider } from "edockit/trusted-list/http";
```

## Hybrid Model

You can combine local hot data with remote fallback:

```typescript
import { createTrustListProvider } from "edockit/trusted-list";
import { createRemoteTrustListProvider } from "edockit/trusted-list/http";

const local = createTrustListProvider({
  url: "/assets/trusted-list-baltics.json",
});

const remote = createRemoteTrustListProvider({
  url: "/api/trust-list/match",
});

const trustListProvider = {
  async match(query) {
    const localMatch = await local.match(query);
    if (localMatch.found) {
      return localMatch;
    }

    return remote.match(query);
  },
};
```

That is a later optimization, not the recommended first step.

## Bundled Fallback

If you explicitly want the library-shipped fallback snapshot:

```typescript
import { createBundledTrustListProvider } from "edockit/trusted-list/bundled";

const trustListProvider = createBundledTrustListProvider();
```

Behavior:

- this is opt-in only
- the bundled snapshot carries `generatedAt`
- if it is older than 14 days, the provider emits a one-time warning

Use this for demos, tests, or temporary convenience. Prefer app-hosted JSON in production.

## Generating and Hosting JSON

Apps can generate compact trusted-list JSON themselves with the public Node-only build helper:

```typescript
import { generateTrustedListBundle } from "edockit/trusted-list/build";

await generateTrustedListBundle({
  outputPath: "public/assets/trusted-list.json",
});
```

That is the recommended production setup for a web app that wants local matching from app-hosted JSON.

If you also want a manifest for later sharding or rollout logic:

```typescript
await generateTrustedListBundle({
  outputPath: "public/assets/trusted-list.json",
  manifestOutputPath: "public/assets/trusted-list-manifest.json",
  baseUrl: "/assets",
});
```

If you want to do the same thing in this repository itself, the repo script still exists:

```bash
npm run update-trusted-list
```

That repo script writes:

- `trusted-list/manifest.json`
- `trusted-list/bundles/<bundleId>.json`

In production, the usual pattern is:

1. generate the JSON in CI
2. deploy it as a static asset from your own origin
3. load it with `createTrustListProvider({ url })`

If your app later moves issuer/TSA matching to a server API, keep generating the same JSON and load it on the server:

```typescript
import { readFileSync } from "node:fs";
import { buildTrustedListData, matchTrustListQuery } from "edockit/trusted-list";

const bundle = JSON.parse(readFileSync("./public/assets/trusted-list.json", "utf8"));
const trustedListData = buildTrustedListData(bundle);

export async function postTrustMatch(request: Request): Promise<Response> {
  const body = await request.json();
  const match = matchTrustListQuery(
    {
      ...body,
      time: new Date(body.time),
    },
    trustedListData,
  );

  return Response.json(match);
}
```

Browser code can then use:

```typescript
import { createRemoteTrustListProvider } from "edockit/trusted-list/http";

const trustListProvider = createRemoteTrustListProvider({
  url: "/api/trust-list/match",
});
```

## Practical Rollout

Recommended order:

1. Start with one compact JSON file.
2. Verify locally with `edockit/trusted-list`.
3. If needed later, split hot shards such as `lv`, `lt`, `ee`, or `baltics`.
4. Only after that, add remote fallback for the long tail.

That keeps the first production version simple and avoids unnecessary moving parts.
