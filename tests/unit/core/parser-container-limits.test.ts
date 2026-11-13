import { randomBytes } from "crypto";
import { unzipSync, zipSync, Zippable } from "fflate";
import { parseEdoc, DEFAULT_PARSE_EDOC_LIMITS } from "../../../src/core/parser";

const CENTRAL_DIR_SIGNATURE = 0x02014b50;

function textBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function baseFiles(): Zippable {
  return {
    mimetype: [textBytes("application/vnd.etsi.asic-e+zip"), { level: 0 }],
  };
}

/**
 * Overwrite the declared uncompressed size of an entry in the central directory
 * (the size fflate uses to allocate the output buffer).
 */
function setDeclaredSize(zip: Uint8Array, entryName: string, declaredSize: number): Uint8Array {
  const out = new Uint8Array(zip);
  const view = new DataView(out.buffer);
  const decoder = new TextDecoder();
  for (let i = out.length - 46; i >= 0; i--) {
    if (view.getUint32(i, true) !== CENTRAL_DIR_SIGNATURE) continue;
    const nameLength = view.getUint16(i + 28, true);
    const name = decoder.decode(out.subarray(i + 46, i + 46 + nameLength));
    if (name === entryName) {
      view.setUint32(i + 24, declaredSize, true);
      return out;
    }
  }
  throw new Error(`Central directory entry ${entryName} not found`);
}

describe("parseEdoc container limits", () => {
  it("parses a small container with default limits", () => {
    const zip = zipSync({ ...baseFiles(), "doc.txt": textBytes("hello") });
    const container = parseEdoc(zip);
    expect(container.documentFileList).toEqual(["doc.txt"]);
    expect(container.metadataFileList).toEqual(["mimetype"]);
  });

  it("exposes the default limits", () => {
    expect(DEFAULT_PARSE_EDOC_LIMITS).toEqual({
      maxEntries: 1000,
      maxEntrySize: 100 * 1024 * 1024,
      maxTotalSize: 500 * 1024 * 1024,
    });
  });

  it("rejects containers with more entries than allowed", () => {
    const zip = zipSync({ ...baseFiles(), "a.txt": textBytes("a"), "b.txt": textBytes("b") });
    expect(() => parseEdoc(zip, { maxEntries: 2 })).toThrow(/more than 2 entries/);
    expect(() => parseEdoc(zip, { maxEntries: 3 })).not.toThrow();
  });

  it("applies the default entry count limit", () => {
    const files: Zippable = baseFiles();
    for (let i = 0; i < DEFAULT_PARSE_EDOC_LIMITS.maxEntries; i++) {
      files[`f${i}.txt`] = textBytes("x");
    }
    expect(() => parseEdoc(zipSync(files))).toThrow(/more than 1000 entries/);
  });

  it("rejects a deflated entry larger than maxEntrySize", () => {
    const zip = zipSync({ ...baseFiles(), "big.txt": textBytes("a".repeat(2000)) });
    expect(() => parseEdoc(zip, { maxEntrySize: 1000 })).toThrow(/"big.txt" is too large/);
    expect(() => parseEdoc(zip, { maxEntrySize: 2000 })).not.toThrow();
  });

  it("rejects a stored entry larger than maxEntrySize", () => {
    const zip = zipSync({ ...baseFiles(), "big.bin": [randomBytes(2000), { level: 0 }] });
    expect(() => parseEdoc(zip, { maxEntrySize: 1000 })).toThrow(/"big.bin" is too large/);
  });

  it("rejects containers whose total size exceeds maxTotalSize", () => {
    const zip = zipSync({
      ...baseFiles(),
      "a.txt": textBytes("a".repeat(600)),
      "b.txt": textBytes("b".repeat(600)),
    });
    expect(() => parseEdoc(zip, { maxTotalSize: 1000 })).toThrow(/Container content is too large/);
    expect(() => parseEdoc(zip, { maxTotalSize: 2000 })).not.toThrow();
  });

  it("rejects an entry whose declared size cannot follow from its compressed size", () => {
    const zip = setDeclaredSize(
      zipSync({ ...baseFiles(), "doc.txt": textBytes("hello world") }),
      "doc.txt",
      0x7fffffff,
    );
    expect(() => parseEdoc(zip)).toThrow(/inconsistent with its compressed size/);
  });

  it("applies the default per-entry limit to the declared size before decompressing", () => {
    // ~120 KB of incompressible data can plausibly declare up to ~120 MB
    const zip = setDeclaredSize(
      zipSync({ ...baseFiles(), "doc.bin": randomBytes(120 * 1024) }),
      "doc.bin",
      110 * 1024 * 1024,
    );
    expect(() => parseEdoc(zip)).toThrow(/"doc.bin" is too large/);
  });

  it("never returns more data than the declared size", () => {
    const content = textBytes("0123456789".repeat(100));
    const zip = setDeclaredSize(zipSync({ "doc.txt": content }), "doc.txt", 10);
    const result = unzipSync(zip);
    expect(result["doc.txt"].length).toBeLessThanOrEqual(10);
  });

  it("rejects invalid option values", () => {
    const zip = zipSync({ ...baseFiles(), "doc.txt": textBytes("hello") });
    expect(() => parseEdoc(zip, { maxEntries: -1 })).toThrow(/Invalid maxEntries option/);
    expect(() => parseEdoc(zip, { maxTotalSize: NaN })).toThrow(/Invalid maxTotalSize option/);
  });

  it("allows limits to be raised", () => {
    const zip = zipSync({ ...baseFiles(), "doc.txt": textBytes("hello") });
    expect(() =>
      parseEdoc(zip, { maxEntries: Infinity, maxEntrySize: Infinity, maxTotalSize: Infinity }),
    ).not.toThrow();
  });
});
