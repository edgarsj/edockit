import {
  XMLCanonicalizer,
  CANONICALIZATION_METHODS,
} from "../../../../src/core/canonicalization/XMLCanonicalizer";
import { createXMLParser, querySelector } from "../../../../src/utils/xmlParser";

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

    // Test fixture 7: Real-world eDoc signature fragment
    it("should correctly canonicalize a signature fragment", () => {
      const doc = parser.parseFromString(
        `
        <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
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
    it("should correctly canonicalize a signature example 1", () => {
      const doc = parser.parseFromString(
        `<?xml version="1.0" encoding="UTF-8" standalone="no"?><asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S1">
      <ds:SignedInfo Id="S1-SignedInfo">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
      <ds:Reference Id="S1-ref-1" URI="Sample%20File.pdf">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>KEaw8zdE2ySmreG7ZkO2+Agf0tpuVK7g+bdYZKm9XMY=</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Id="S1-ref-2" URI="Sample%20File.docx">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>24JzEZGtUCnMB12jy6eQDSZedGfWUkxaCLYEF/lygEA=</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Id="S1-ref-SignedProperties" Type="http://uri.etsi.org/01903#SignedProperties" URI="#S1-SignedProperties">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>p6LJHwzFitT8DMYXEJzpkoxL6oonJQc2llg+QMu6si8=</ds:DigestValue>
      </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>TpS9H1nbT2TfURZW78+jDo7JhlNFNVpvIhWCGHdDTCDxO+SSJclKyxqoA/ZECew1iqTUrsnwvVni
      lhTw6GC8kw7at+IleVYW9qJ4XSxe8moL04BfVDbMxyHniOu9e2eD</ds:SignatureValue></ds:Signature></asic:XAdESSignatures>`,
        `text/xml`,
      );
      const node = querySelector(doc, "ds:SignedInfo") as any;
      const expectedC14n11 =
        '<ds:SignedInfo xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S1-SignedInfo">\n<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod>\n<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod>\n<ds:Reference Id="S1-ref-1" URI="Sample%20File.pdf">\n<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>\n<ds:DigestValue>KEaw8zdE2ySmreG7ZkO2+Agf0tpuVK7g+bdYZKm9XMY=</ds:DigestValue>\n</ds:Reference>\n<ds:Reference Id="S1-ref-2" URI="Sample%20File.docx">\n<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>\n<ds:DigestValue>24JzEZGtUCnMB12jy6eQDSZedGfWUkxaCLYEF/lygEA=</ds:DigestValue>\n</ds:Reference>\n<ds:Reference Id="S1-ref-SignedProperties" Type="http://uri.etsi.org/01903#SignedProperties" URI="#S1-SignedProperties">\n<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>\n<ds:DigestValue>p6LJHwzFitT8DMYXEJzpkoxL6oonJQc2llg+QMu6si8=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>';
      expect(XMLCanonicalizer.c14n11(node)).toBe(expectedC14n11);
    });
  });
});
