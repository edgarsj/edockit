import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import esbuild from "rollup-plugin-esbuild";

const packageJson = require("./package.json");

const banner = `/*!
 * MIT License
 * Copyright (c) 2025 Edgars Jēkabsons, ZenomyTech SIA
 */`;

function createTypescriptPlugin() {
  return typescript({
    tsconfig: "./tsconfig.rollup.json",
  });
}

function isExternalModule(id) {
  return id === "fflate" || id === "@peculiar/x509" || id === "crypto" || id.startsWith("node:");
}

const moduleInputs = {
  index: "src/index.ts",
  "trusted-list": "src/trusted-list.ts",
  "trusted-list-build": "src/trusted-list-build.ts",
  "trusted-list-bundled": "src/trusted-list-bundled.ts",
  "trusted-list-http": "src/trusted-list-http.ts",
};

const moduleBuild = {
  input: moduleInputs,
  plugins: [resolve(), commonjs(), createTypescriptPlugin()],
  external: isExternalModule,
  output: [
    {
      dir: "dist",
      entryFileNames: "[name].esm.js",
      format: "esm",
      sourcemap: true,
      banner,
    },
    {
      dir: "dist",
      entryFileNames: "[name].cjs.js",
      format: "cjs",
      sourcemap: true,
      banner,
    },
  ],
};

const rootUmdBuild = {
  input: "src/index.ts",
  output: {
    file: packageJson.browser,
    format: "umd",
    name: "edockit",
    sourcemap: true,
    globals: {
      fflate: "fflate",
      "@peculiar/x509": "peculiarX509",
      crypto: "crypto",
    },
    banner,
  },
  plugins: [
    resolve(),
    commonjs(),
    createTypescriptPlugin(),
    esbuild({
      minify: true,
      target: "es2015",
    }),
  ],
  external: isExternalModule,
};

export default [moduleBuild, rootUmdBuild];
