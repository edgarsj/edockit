import {
  XMLCanonicalizer,
  CANONICALIZATION_METHODS,
} from "../../../../src/core/canonicalization/XMLCanonicalizer";
import { createXMLParser, querySelector } from "../../../../src/utils/xmlParser";
import fs from "fs";
import path from "path";

describe("XMLCanonicalizer", () => {
  it("should correctly initialize with a method", () => {
    const canonicalizer = new XMLCanonicalizer();
    expect(canonicalizer).toBeInstanceOf(XMLCanonicalizer);
  });

  it("should create a canonicalizer from method URI", () => {
    const uri = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    const canonicalizer = XMLCanonicalizer.fromMethod(uri);
    expect(canonicalizer).toBeInstanceOf(XMLCanonicalizer);
  });

  it("should throw error for unsupported method URI", () => {
    const uri = "http://unsupported-method";
    expect(() => XMLCanonicalizer.fromMethod(uri)).toThrow();
  });

  it("should correctly escape XML special characters", () => {
    const input = "& < > \" '";
    const expected = "&amp; &lt; &gt; &quot; &apos;";
    expect(XMLCanonicalizer.escapeXml(input)).toBe(expected);
  });
  // Fixture tests
  describe("canonicalization fixtures", () => {
    // Create a parser to use in all tests
    const parser = createXMLParser();
    const C14N_SAMPLES_PATH = path.join(__dirname, "../../../fixtures/c14n_samples");
    const read_sample = (filename: string): string => {
      return fs.readFileSync(path.join(C14N_SAMPLES_PATH, filename), "utf8").trim();
    };

    // Test fixture 1: Simple XML document
    it("should correctly canonicalize a simple XML document", () => {
      const doc = parser.parseFromString(
        `
        <root>
          <child attr="value">Text content</child>
        </root>
      `,
        "application/xml",
      );

      const node = querySelector(doc, "root") as any;
      const expectedC14n = '<root><child attr="value">Text content</child></root>';
      expect(XMLCanonicalizer.c14n(node)).toBe(expectedC14n);
    });

    // Test fixture 2: Document with namespaces
    it("should correctly handle namespaces in canonicalization", () => {
      const doc = parser.parseFromString(
        `
        <root xmlns="http://example.org" xmlns:ex="http://example.com">
          <child ex:attr="value">
            Some text
            <grandchild>More text</grandchild>
          </child>
        </root>
      `,
        "application/xml",
      );

      const node = querySelector(doc, "root") as any;
      const expectedC14n =
        '<root xmlns="http://example.org" xmlns:ex="http://example.com"><child ex:attr="value">Some text<grandchild>More text</grandchild></child></root>';
      expect(XMLCanonicalizer.c14n(node)).toBe(expectedC14n);
    });

    // Test fixture 3: Document with whitespace
    it("should correctly handle whitespace in canonicalization", () => {
      const doc = parser.parseFromString(
        `
        <root>
          <child>
            This has
            significant whitespace
          </child>
        </root>
      `,
        "application/xml",
      );

      const node = querySelector(doc, "root") as any;
      // C14N removes leading/trailing whitespace in text nodes but preserves internal whitespace
      const expectedC14n =
        "<root><child>This has\n            significant whitespace</child></root>";
      expect(XMLCanonicalizer.c14n(node)).toBe(expectedC14n);
    });

    // Test fixture 4: C14N11 formatting
    it("should apply correct formatting for c14n11", () => {
      const doc = parser.parseFromString(
        `
        <root>
          <child>
            <grandchild>Text</grandchild>
            <grandchild>More</grandchild>
          </child>
        </root>
      `,
        "application/xml",
      );

      const node = querySelector(doc, "root") as any;
      const expectedC14n11 =
        "<root>\n<child>\n<grandchild>Text</grandchild>\n<grandchild>More</grandchild>\n</child>\n</root>";
      expect(XMLCanonicalizer.c14n11(node)).toBe(expectedC14n11);
    });

    // Test fixture 6: XML with attributes
    it("should sort attributes alphabetically", () => {
      const doc = parser.parseFromString(
        `
        <element c="3" a="1" b="2"></element>
      `,
        "application/xml",
      );

      const node = querySelector(doc, "element") as any;
      const expectedC14n = '<element a="1" b="2" c="3"></element>';
      expect(XMLCanonicalizer.c14n(node)).toBe(expectedC14n);
    });

    // Test fixture: Document with multiple namespaces to demonstrate Exclusive C14N differences
    it("should correctly handle namespaces in exclusive canonicalization", () => {
      const doc = parser.parseFromString(
        `<root xmlns="http://default.example.org/" xmlns:a="http://a.example.org/" xmlns:b="http://b.example.org/">
          <a:child xmlns:c="http://c.example.org/">
            <b:grandchild>
              <c:greatgrandchild>Test content</c:greatgrandchild>
            </b:grandchild>
          </a:child>
        </root>
      `,
        "application/xml",
      );

      const childNode = querySelector(doc, "a:child") as any;

      // Regular C14N includes all namespaces in scope
      // const expectedC14n11 =
      //   '<a:child xmlns="http://default.example.org/" xmlns:a="http://a.example.org/" xmlns:b="http://b.example.org/" xmlns:c="http://c.example.org/">\n            <b:grandchild>\n              <c:greatgrandchild>Test content</c:greatgrandchild>\n            </b:grandchild>\n          </a:child>';
      // Regular C14N includes all namespaces in scope
      const expectedC14n11 =
        '<a:child xmlns="http://default.example.org/" xmlns:a="http://a.example.org/" xmlns:b="http://b.example.org/" xmlns:c="http://c.example.org/">\n<b:grandchild>\n<c:greatgrandchild>Test content</c:greatgrandchild>\n</b:grandchild>\n</a:child>';
      // Regular C14N includes all namespaces in scope
      const expectedC14n =
        '<a:child xmlns="http://default.example.org/" xmlns:a="http://a.example.org/" xmlns:b="http://b.example.org/" xmlns:c="http://c.example.org/"><b:grandchild><c:greatgrandchild>Test content</c:greatgrandchild></b:grandchild></a:child>';
      // Exclusive C14N only includes visibly used namespaces
      const expectedExcC14n =
        '<a:child xmlns:a="http://a.example.org/" xmlns:b="http://b.example.org/" xmlns:c="http://c.example.org/"><c:greatgrandchild>Test content</c:greatgrandchild></b:grandchild></a:child>';

      expect(XMLCanonicalizer.c14n11(childNode)).toBe(expectedC14n11);
      expect(XMLCanonicalizer.c14n(childNode)).toBe(expectedC14n);
      //expect(XMLCanonicalizer.excC14n(childNode)).toBe(expectedExcC14n);
    });

    // Test fixture 7: Real-world eDoc signature fragment
    it("should correctly canonicalize a signature fragment", () => {
      const doc = parser.parseFromString(
        `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="">
            <ds:Transforms>
              <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>zvMPfVai/pAG8liFbVnmOLfUGN4rBaV+X1+HE9wPIno=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
      `,
        "application/xml",
      );

      const node = querySelector(doc, "ds:SignedInfo") as any;
      const expectedC14n =
        '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>zvMPfVai/pAG8liFbVnmOLfUGN4rBaV+X1+HE9wPIno=</ds:DigestValue></ds:Reference></ds:SignedInfo>';
      expect(XMLCanonicalizer.c14n(node)).toBe(expectedC14n);
    });
    it("should correctly canonicalize a signature example 1 n11", () => {
      const originalXml = read_sample("samplecontent1.xml");
      const expectedC14n11 = read_sample("samplecontent1_c14n11_signedinfo.xml");

      const doc = parser.parseFromString(originalXml, `text/xml`);
      const node = querySelector(doc, "ds:SignedInfo") as any;
      expect(XMLCanonicalizer.c14n11(node)).toBe(expectedC14n11);
    });
    it("should correctly canonicalize a signature example 1 exc", () => {
      const originalXml = read_sample("samplecontent1.xml");
      const expectedC14nexc = read_sample("samplecontent1_c14nexc_signedinfo.xml");

      const doc = parser.parseFromString(originalXml, `text/xml`);
      const node = querySelector(doc, "ds:SignedInfo") as any;
      expect(XMLCanonicalizer.c14n_exc(node)).toBe(expectedC14nexc);
    });
  });
});
