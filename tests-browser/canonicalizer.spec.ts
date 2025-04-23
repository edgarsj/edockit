// tests-browser/canonicalizer.spec.ts
import { expect } from "@esm-bundle/chai";
import {
  XMLCanonicalizer,
  CANONICALIZATION_METHODS,
} from "../src/core/canonicalization/XMLCanonicalizer";
import { createXMLParser, querySelector } from "../src/utils/xmlParser";

describe("XMLCanonicalizer", () => {
  it("should correctly initialize with a method", () => {
    const canonicalizer = new XMLCanonicalizer();
    expect(canonicalizer).to.be.instanceOf(XMLCanonicalizer);
  });

  it("should create a canonicalizer from method URI", () => {
    const uri = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    const canonicalizer = XMLCanonicalizer.fromMethod(uri);
    expect(canonicalizer).to.be.instanceOf(XMLCanonicalizer);
  });

  it("should throw error for unsupported method URI", () => {
    const uri = "http://unsupported-method";
    expect(() => XMLCanonicalizer.fromMethod(uri)).to.throw();
  });

  it("should correctly escape XML special characters", () => {
    const input = "& < > \" '";
    const expected = "&amp; &lt; &gt; &quot; &apos;";
    expect(XMLCanonicalizer.escapeXml(input)).to.equal(expected);
  });

  // Fixture tests
  describe("canonicalization fixtures", () => {
    // Create a parser to use in all tests
    const parser = createXMLParser();

    // Helper to fetch XML fixtures
    const fetchSample = async (filename: string) => {
      try {
        const response = await fetch(`/tests/fixtures/c14n_samples/${filename}`);
        return await response.text();
      } catch (error) {
        console.error(`Failed to fetch sample ${filename}:`, error);
        return "";
      }
    };
    it("C14N 1.0 vs 1.1 whitespace handling", () => {
      const xml = `<root><a><b>text</b></a></root>`;
      const doc = parser.parseFromString(xml, "text/xml");

      const c14n10 = XMLCanonicalizer.c14n(doc.documentElement as any);
      expect(c14n10).to.equal("<root><a><b>text</b></a></root>");

      const c14n11 = XMLCanonicalizer.c14n11(doc.documentElement as any);
      expect(c14n11).to.equal("<root>\n<a>\n<b>text</b>\n</a>\n</root>");
    });
    it("Mixed content remains unchanged", () => {
      const xml = `<doc>Text <b>bold</b> and <i>italic</i></doc>`;
      const doc = parser.parseFromString(xml, "text/xml");

      const c14n10 = XMLCanonicalizer.c14n(doc.documentElement as any);
      const c14n11 = XMLCanonicalizer.c14n11(doc.documentElement as any);

      expect(c14n10).to.equal(c14n11); // Both should be identical
      expect(c14n10).to.equal("<doc>Text <b>bold</b> and <i>italic</i></doc>");
    });
    // // Test fixture 1: Simple XML document
    // it("should correctly canonicalize a simple XML document", () => {
    //   const doc = parser.parseFromString(
    //     `
    //     <root>
    //       <child attr="value">Text content</child>
    //     </root>
    //   `,
    //     "application/xml",
    //   );

    //   const node = querySelector(doc, "root") as any;
    //   const expectedC14n = '<root><child attr="value">Text content</child></root>';
    //   expect(XMLCanonicalizer.c14n(node)).to.equal(expectedC14n);
    // });

    // // Test fixture 2: Document with namespaces
    // it("should correctly handle namespaces in canonicalization", () => {
    //   const doc = parser.parseFromString(
    //     `
    //     <root xmlns="http://example.org" xmlns:ex="http://example.com">
    //       <child ex:attr="value">
    //         Some text
    //         <grandchild>More text</grandchild>
    //       </child>
    //     </root>
    //   `,
    //     "application/xml",
    //   );

    //   const node = querySelector(doc, "root");
    //   const expectedC14n =
    //     '<root xmlns="http://example.org" xmlns:ex="http://example.com"><child ex:attr="value">Some text<grandchild>More text</grandchild></child></root>';
    //   expect(XMLCanonicalizer.c14n(node as any)).to.equal(expectedC14n);
    // });

    // // Test fixture 3: Document with whitespace
    // it("should correctly handle whitespace in canonicalization", () => {
    //   const doc = parser.parseFromString(
    //     `
    //     <root>
    //       <child>
    //         This has
    //         significant whitespace
    //       </child>
    //     </root>
    //   `,
    //     "application/xml",
    //   );

    //   const node = querySelector(doc, "root") as any;
    //   // C14N removes leading/trailing whitespace in text nodes but preserves internal whitespace
    //   const expectedC14n =
    //     "<root><child>This has\n            significant whitespace</child></root>";
    //   expect(XMLCanonicalizer.c14n(node)).to.equal(expectedC14n);
    // });

    // Test fixture 4: C14N11 formatting
    it("should apply correct formatting for c14n11", async function () {
      const originalXml = await fetchSample("testcontent1.xml");
      const expectedC14n11 = await fetchSample("testcontent1_c14n11.xml");
      const doc = parser.parseFromString(originalXml, `text/xml`) as any;
      let c14n11_str = XMLCanonicalizer.c14n11(doc.documentElement);
      console.log("C14N11 str:", c14n11_str);
      expect(XMLCanonicalizer.c14n11(doc.documentElement)).to.equal(expectedC14n11);
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
      expect(XMLCanonicalizer.c14n(node)).to.equal(expectedC14n);
    });

    // // Test fixture: Document with multiple namespaces to demonstrate Exclusive C14N differences
    // it("should correctly handle namespaces in exclusive canonicalization", () => {
    //   const doc = parser.parseFromString(
    //     `<root xmlns="http://default.example.org/" xmlns:a="http://a.example.org/" xmlns:b="http://b.example.org/">
    //       <a:child xmlns:c="http://c.example.org/">
    //         <b:grandchild>
    //           <c:greatgrandchild>Test content</c:greatgrandchild>
    //         </b:grandchild>
    //       </a:child>
    //     </root>
    //   `,
    //     "application/xml",
    //   );

    //   const childNode = querySelector(doc, "a:child");

    //   // Regular C14N11 includes all namespaces in scope
    //   const expectedC14n11 =
    //     '<a:child xmlns="http://default.example.org/" xmlns:a="http://a.example.org/" xmlns:b="http://b.example.org/" xmlns:c="http://c.example.org/">\n<b:grandchild>\n<c:greatgrandchild>Test content</c:greatgrandchild>\n</b:grandchild>\n</a:child>';

    //   // Regular C14N includes all namespaces in scope
    //   const expectedC14n =
    //     '<a:child xmlns="http://default.example.org/" xmlns:a="http://a.example.org/" xmlns:b="http://b.example.org/" xmlns:c="http://c.example.org/"><b:grandchild><c:greatgrandchild>Test content</c:greatgrandchild></b:grandchild></a:child>';

    //   expect(XMLCanonicalizer.c14n11(childNode as any)).to.equal(expectedC14n11);
    //   expect(XMLCanonicalizer.c14n(childNode as any)).to.equal(expectedC14n);
    // });

    // Tests using fixture files - these need to be loaded asynchronously in the browser
    it("should correctly retain whitespace 1 c14n", async function () {
      // Using async function for async/await
      const originalXml = await fetchSample("whitespace1.xml");
      const expectedC14n = await fetchSample("whitespace1_c14n.xml");

      // Skip the test if samples couldn't be loaded
      if (!originalXml || !expectedC14n) {
        this.skip();
        return;
      }

      const doc = parser.parseFromString(originalXml, `text/xml`);
      expect(XMLCanonicalizer.c14n(doc.documentElement as any)).to.equal(expectedC14n);
    });

    it("should correctly canonicalize a signature example 1 n11", async function () {
      const originalXml = await fetchSample("samplecontent1.xml");
      const expectedC14n11 = await fetchSample("samplecontent1_c14n11_signedinfo.xml");

      // Skip the test if samples couldn't be loaded
      if (!originalXml || !expectedC14n11) {
        this.skip();
        return;
      }

      const doc = parser.parseFromString(originalXml, `text/xml`);
      const node = querySelector(doc, "ds:SignedInfo") as any;
      expect(XMLCanonicalizer.c14n11(node)).to.equal(expectedC14n11);
    });

    it("should correctly canonicalize a signature example 1 c14n", async function () {
      const originalXml = await fetchSample("samplecontent1.xml");
      const expectedC14n = await fetchSample("samplecontent1_c14n_signedinfo.xml");

      // Skip the test if samples couldn't be loaded
      if (!originalXml || !expectedC14n) {
        this.skip();
        return;
      }

      const doc = parser.parseFromString(originalXml, `text/xml`);
      const node = querySelector(doc, "ds:SignedInfo") as any;
      expect(XMLCanonicalizer.c14n11(node)).to.equal(expectedC14n);
    });

    // it("should correctly canonicalize a signature example 1 exc", async function () {
    //   const originalXml = await fetchSample("samplecontent1.xml");
    //   const expectedC14nexc = await fetchSample("samplecontent1_c14nexc_signedinfo.xml");

    //   // Skip the test if samples couldn't be loaded
    //   if (!originalXml || !expectedC14nexc) {
    //     this.skip();
    //     return;
    //   }

    //   const doc = parser.parseFromString(originalXml, `text/xml`);
    //   const node = querySelector(doc, "ds:SignedInfo") as any;
    //   expect(XMLCanonicalizer.c14n_exc(node)).to.equal(expectedC14nexc);
    // });
  });
});
