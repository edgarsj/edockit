import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import esbuild from "rollup-plugin-esbuild";

const packageJson = require("./package.json");

export default [
  // ESM build (for modern environments and bundlers)
  {
    input: "src/index.ts",
    output: {
      file: packageJson.module,
      format: "esm",
      sourcemap: true,
    },
    plugins: [resolve(), commonjs(), typescript({ tsconfig: "./tsconfig.json" })],
    external: ["fflate", "@peculiar/x509", "crypto"],
  },
  // CommonJS build (for Node.js)
  {
    input: "src/index.ts",
    output: {
      file: packageJson.main,
      format: "cjs",
      sourcemap: true,
    },
    plugins: [resolve(), commonjs(), typescript({ tsconfig: "./tsconfig.json" })],
    external: ["fflate", "@peculiar/x509"],
  },
  // UMD build (for browsers, including minification)
  {
    input: "src/index.ts",
    output: {
      file: packageJson.browser,
      format: "umd",
      name: "edockit", // Changed from 'LatvianEdoc' to 'edockit'
      sourcemap: true,
      globals: {
        fflate: "fflate",
        "@peculiar/x509": "peculiarX509",
        crypto: "crypto",
      },
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
