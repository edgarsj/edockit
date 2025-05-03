import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import esbuild from "rollup-plugin-esbuild";

const packageJson = require("./package.json");

// Simple banner with just the essentials
const banner = `/*!
 * MIT License
 * Copyright (c) 2025 Edgars Jēkabsons, ZenomyTech SIA
 */`;

export default [
  // ESM build
  {
    input: "src/index.ts",
    output: {
      file: packageJson.module,
      format: "esm",
      sourcemap: true,
      banner,
    },
    plugins: [resolve(), commonjs(), typescript({ tsconfig: "./tsconfig.json" })],
    external: ["fflate", "@peculiar/x509", "crypto"],
  },
  // CommonJS build
  {
    input: "src/index.ts",
    output: {
      file: packageJson.main,
      format: "cjs",
      sourcemap: true,
      banner,
    },
    plugins: [resolve(), commonjs(), typescript({ tsconfig: "./tsconfig.json" })],
    external: ["fflate", "@peculiar/x509"],
  },
  // UMD build
  {
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
      typescript({ tsconfig: "./tsconfig.json" }),
      esbuild({
        minify: true,
        target: "es2015",
      }),
    ],
    external: ["fflate", "@peculiar/x509"],
  },
];
