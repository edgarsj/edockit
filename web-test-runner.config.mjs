import { esbuildPlugin } from "@web/dev-server-esbuild";
import { defaultReporter } from "@web/test-runner";
import { chromeLauncher } from "@web/test-runner-chrome";
import { playwrightLauncher } from "@web/test-runner-playwright";

// Use ALL_BROWSERS=true to test in Chrome, Safari/WebKit, and Firefox
// Requires: npx playwright install webkit firefox
const allBrowsers = process.env.ALL_BROWSERS === "true";

const browsers = [
  chromeLauncher({
    launchOptions: {
      headless: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-web-security",
        "--disable-features=IsolateOrigins,site-per-process",
      ],
    },
  }),
];

if (allBrowsers) {
  browsers.push(
    playwrightLauncher({ product: "webkit" }),
    playwrightLauncher({ product: "firefox" }),
  );
}

const config = {
  nodeResolve: true,
  files: ["tests-browser/**/*.spec.ts"],
  browsers,

  plugins: [
    // Stub out Node-only deps before esbuild tries to resolve them
    {
      name: "stub-node-deps",
      resolveImport({ source }) {
        if (source === "@xmldom/xmldom" || source === "xpath") {
          return `/__node-stub__/${source}`;
        }
      },
      serve(context) {
        if (context.path.startsWith("/__node-stub__/")) {
          return {
            body: "export default {}; export const DOMParser = undefined; export const XMLSerializer = undefined; export const select = undefined;",
            type: "js",
          };
        }
      },
    },
    esbuildPlugin({
      ts: true,
      tsconfig: "./tsconfig.json",
      target: "es2020",
    }),
  ],

  reporters: [
    defaultReporter({
      reportTestResults: true,
      reportTestProgress: true,
    }),
  ],

  testFramework: {
    config: {
      ui: "bdd",
      timeout: 30000,
    },
  },
};

export default config;
