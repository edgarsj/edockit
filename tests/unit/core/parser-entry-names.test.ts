import { zipSync, Zippable } from "fflate";
import { parseEdoc } from "../../../src/core/parser";

const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_DIR_SIGNATURE = 0x02014b50;

function textBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function makeZip(names: string[]): Uint8Array {
  const files: Zippable = {
    mimetype: [textBytes("application/vnd.etsi.asic-e+zip"), { level: 0 }],
  };
  for (const name of names) {
    files[name] = textBytes(`content of ${name}`);
  }
  return zipSync(files);
}

/**
 * Rename an entry in both its local header and central directory record.
 * The new name must have the same byte length as the old one.
 */
function renameEntry(zip: Uint8Array, from: string, to: string): Uint8Array {
  const fromBytes = textBytes(from);
  const toBytes = textBytes(to);
  if (fromBytes.length !== toBytes.length) {
    throw new Error("renameEntry requires names of equal length");
  }
  const out = new Uint8Array(zip);
  const view = new DataView(out.buffer);
  let renamed = 0;
  for (let i = 0; i + 4 <= out.length; i++) {
    const sig = view.getUint32(i, true);
    let lengthOffset: number;
    let nameOffset: number;
    if (sig === LOCAL_HEADER_SIGNATURE) {
      lengthOffset = 26;
      nameOffset = 30;
    } else if (sig === CENTRAL_DIR_SIGNATURE) {
      lengthOffset = 28;
      nameOffset = 46;
    } else {
      continue;
    }
    const nameLength = view.getUint16(i + lengthOffset, true);
    const nameBytes = out.subarray(i + nameOffset, i + nameOffset + nameLength);
    if (nameLength === fromBytes.length && nameBytes.every((b, j) => b === fromBytes[j])) {
      out.set(toBytes, i + nameOffset);
      renamed++;
    }
  }
  if (renamed !== 2) {
    throw new Error(`Expected to rename 2 headers for ${from}, renamed ${renamed}`);
  }
  return out;
}

describe("parseEdoc entry names", () => {
  it("accepts ordinary nested names", () => {
    const container = parseEdoc(
      makeZip(["doc.pdf", "folder/sub/file.txt", "META-INF/manifest.xml", "a..b.txt"]),
    );
    expect(container.documentFileList).toEqual(["doc.pdf", "folder/sub/file.txt", "a..b.txt"]);
    expect(container.metadataFileList).toEqual(["mimetype", "META-INF/manifest.xml"]);
  });

  it("keeps entries in container order", () => {
    // Object keys that look like integers would be enumerated first; build the zip
    // with placeholder names and rename them so the container order is known
    let zip = makeZip(["b.txt", "xx", "a.txt", "y"]);
    zip = renameEntry(renameEntry(zip, "xx", "10"), "y", "2");
    const container = parseEdoc(zip);
    expect(Array.from(container.files.keys())).toEqual(["mimetype", "b.txt", "10", "a.txt", "2"]);
  });

  it.each([
    ["../outside.txt"],
    ["folder/../../outside.txt"],
    ["META-INF/../doc.txt"],
    ["folder/.."],
    ["..\\outside.txt"],
    ["folder\\..\\..\\outside.txt"],
  ])("rejects a name with a parent-directory segment: %s", (name) => {
    expect(() => parseEdoc(makeZip([name]))).toThrow(/must not contain "\.\." segments/);
  });

  it.each([["/etc/file.txt"], ["\\server\\share\\file.txt"]])(
    "rejects an absolute name: %s",
    (name) => {
      expect(() => parseEdoc(makeZip([name]))).toThrow(/must be a relative path/);
    },
  );

  it.each([["C:/file.txt"], ["c:file.txt"], ["D:\\dir\\file.txt"]])(
    "rejects a name starting with a drive letter: %s",
    (name) => {
      expect(() => parseEdoc(makeZip([name]))).toThrow(/drive letter/);
    },
  );

  it("rejects duplicate entry names", () => {
    const zip = renameEntry(makeZip(["first.txt", "other.txt"]), "other.txt", "first.txt");
    expect(() => parseEdoc(zip)).toThrow(/more than one entry named "first.txt"/);
  });

  it("rejects an entry named __proto__", () => {
    const zip = renameEntry(makeZip(["doc.txt", "xxxxxxxxx"]), "xxxxxxxxx", "__proto__");
    expect(() => parseEdoc(zip)).toThrow(/Unsupported entry name/);
  });

  it("keeps other Object.prototype names as regular entries", () => {
    const container = parseEdoc(makeZip(["constructor", "toString", "hasOwnProperty"]));
    expect(container.documentFileList).toEqual(["constructor", "toString", "hasOwnProperty"]);
    expect(new TextDecoder().decode(container.files.get("constructor"))).toBe(
      "content of constructor",
    );
  });

  it("classifies META-INF only by the first path segment", () => {
    const container = parseEdoc(
      makeZip(["META-INF/manifest.xml", "META-INF", "META-INFX/file.txt", "dir/META-INF/x.xml"]),
    );
    expect(container.metadataFileList).toEqual(["mimetype", "META-INF/manifest.xml"]);
    expect(container.documentFileList).toEqual([
      "META-INF",
      "META-INFX/file.txt",
      "dir/META-INF/x.xml",
    ]);
  });

  it("does not treat backslash-separated META-INF names as metadata", () => {
    const container = parseEdoc(makeZip(["META-INF\\manifest.xml"]));
    expect(container.documentFileList).toEqual(["META-INF\\manifest.xml"]);
  });
});
