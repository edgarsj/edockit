import { readFile } from "node:fs/promises";
import { rollup } from "rollup";
import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import esbuild from "rollup-plugin-esbuild";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

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
  return (
    id === "fflate" ||
    id === "@peculiar/x509" ||
    id === "@xmldom/xmldom" ||
    id === "xpath" ||
    id === "crypto" ||
    id.startsWith("node:") ||
    id.startsWith("@peculiar/asn1-")
  );
}

function isExternalModuleUmd(id) {
  return id === "fflate" || id === "@peculiar/x509" || id === "crypto" || id.startsWith("node:");
}

/**
 * Leave the trusted-list snapshot's text out of source maps; it is data and
 * would otherwise roughly double the size of the published package.
 */
function stripTrustedListDataFromSourceMaps() {
  return {
    name: "strip-trusted-list-data-from-source-maps",
    generateBundle(_options, bundle) {
      for (const file of Object.values(bundle)) {
        if (file.type !== "chunk" || !file.map?.sourcesContent) {
          continue;
        }
        file.map.sourcesContent = file.map.sourcesContent.map((content, index) =>
          /src[\\/]data[\\/]trusted-list\.ts$/.test(file.map.sources[index]) ? null : content,
        );
      }
    },
  };
}

function createModuleBuildConfig() {
  return {
    input: {
      index: "src/index.ts",
      "trusted-list": "src/trusted-list.ts",
      "trusted-list-build": "src/trusted-list-build.ts",
      "trusted-list-bundled": "src/trusted-list-bundled.ts",
      "trusted-list-http": "src/trusted-list-http.ts",
    },
    plugins: [
      resolve(),
      commonjs(),
      createTypescriptPlugin(),
      stripTrustedListDataFromSourceMaps(),
    ],
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
}

function createRootUmdBuildConfig() {
  return {
    input: "src/index.ts",
    plugins: [
      resolve(),
      commonjs(),
      createTypescriptPlugin(),
      esbuild({
        minify: true,
        target: "es2015",
      }),
    ],
    external: isExternalModuleUmd,
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
  };
}

async function build(config) {
  const bundle = await rollup({
    input: config.input,
    plugins: config.plugins,
    external: config.external,
  });

  try {
    const outputs = Array.isArray(config.output) ? config.output : [config.output];
    for (const output of outputs) {
      await bundle.write(output);
    }
  } finally {
    await bundle.close();
  }
}

await build(createModuleBuildConfig());
await build(createRootUmdBuildConfig());
process.exit(0);
