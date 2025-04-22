import { esbuildPlugin } from "@web/dev-server-esbuild";
import { defaultReporter } from "@web/test-runner";
import { chromeLauncher } from "@web/test-runner-chrome";

const config = {
  nodeResolve: true,
  files: ["tests-browser/**/*.spec.ts"],

  // Explicit browser launcher configuration
  browsers: [
    chromeLauncher({
      launchOptions: {
        headless: true,
        args: ["--no-sandbox", "--disable-setuid-sandbox"],
      },
    }),
  ],

  plugins: [
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
      timeout: 3000,
    },
  },
};

export default config;
