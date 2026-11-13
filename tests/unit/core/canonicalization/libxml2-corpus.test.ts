import { readdirSync, readFileSync } from "fs";
import { join } from "path";
import { createXMLParser } from "../../../../src/utils/xmlParser";
import { XMLCanonicalizer } from "../../../../src/core/canonicalization/XMLCanonicalizer";

// Expected outputs were produced by libxml2 (xmllint), which emits the
// #WithComments variants.
const CORPUS = join(__dirname, "../../../fixtures/c14n_corpus");
const VARIANTS: Array<[string, string]> = [
  ["c14n", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"],
  ["c14n11", "http://www.w3.org/2006/12/xml-c14n11#WithComments"],
  ["exc-c14n", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"],
];

const cases = readdirSync(CORPUS)
  .filter((name) => name.endsWith(".xml"))
  .map((name) => name.replace(/\.xml$/, ""));

describe("canonicalization matches libxml2", () => {
  it.each(cases.flatMap((name) => VARIANTS.map(([ext, uri]) => [name, ext, uri])))(
    "%s (%s)",
    (name, ext, uri) => {
      const xml = readFileSync(join(CORPUS, `${name}.xml`), "utf8");
      const expected = readFileSync(join(CORPUS, `${name}.${ext}`), "utf8");
      const doc = createXMLParser().parseFromString(xml, "application/xml");

      expect(XMLCanonicalizer.canonicalize(doc.documentElement, uri)).toBe(expected);
    },
  );
});
