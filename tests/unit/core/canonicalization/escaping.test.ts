import { createXMLParser } from "../../../../src/utils/xmlParser";
import { XMLCanonicalizer } from "../../../../src/core/canonicalization/XMLCanonicalizer";

const METHODS = [
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  "http://www.w3.org/2006/12/xml-c14n11",
  "http://www.w3.org/2001/10/xml-exc-c14n#",
];

describe("Canonical XML escaping", () => {
  const xml = `<r><n>CN=CA &amp; Co &lt;x&gt; "q" 'a'</n><a b="x &amp; &quot;y&quot; &lt;"/></r>`;

  it.each(METHODS)("escapes character data and attribute values (%s)", (method) => {
    const doc = createXMLParser().parseFromString(xml, "application/xml");
    const output = XMLCanonicalizer.canonicalize(doc.documentElement, method);

    expect(output).toContain(`<n>CN=CA &amp; Co &lt;x&gt; "q" 'a'</n>`);
    expect(output).toContain(`<a b="x &amp; &quot;y&quot; &lt;"></a>`);
  });

  it.each(METHODS)("distinguishes escaped markup from elements (%s)", (method) => {
    const parser = createXMLParser();
    const asText = parser.parseFromString(`<r>&lt;x&gt;&lt;/x&gt;</r>`, "application/xml");
    const asElement = parser.parseFromString(`<r><x></x></r>`, "application/xml");

    expect(XMLCanonicalizer.canonicalize(asText.documentElement, method)).not.toBe(
      XMLCanonicalizer.canonicalize(asElement.documentElement, method),
    );
  });

  it.each(METHODS)("renders CDATA sections as escaped character data (%s)", (method) => {
    const parser = createXMLParser();
    const withCdata = parser.parseFromString(
      `<r><n><![CDATA[CN=CA & Co <x>]]></n></r>`,
      "application/xml",
    );
    const asText = parser.parseFromString(
      `<r><n>CN=CA &amp; Co &lt;x&gt;</n></r>`,
      "application/xml",
    );

    const canonical = XMLCanonicalizer.canonicalize(withCdata.documentElement, method);
    expect(canonical).toBe(XMLCanonicalizer.canonicalize(asText.documentElement, method));
    expect(canonical).toContain("CN=CA &amp; Co &lt;x&gt;");
  });

  it.each(METHODS)("retains processing instructions and omits comments (%s)", (method) => {
    const doc = createXMLParser().parseFromString(
      `<r><a/><?app some data?><!-- note --><?bare?></r>`,
      "application/xml",
    );
    const canonical = XMLCanonicalizer.canonicalize(doc.documentElement, method);
    expect(canonical).toContain("<?app some data?>");
    expect(canonical).toContain("<?bare?>");
    expect(canonical).not.toContain("note");
  });

  it.each([
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    "http://www.w3.org/2006/12/xml-c14n11",
  ])("does not repeat inherited namespace declarations on descendants (%s)", (method) => {
    const doc = createXMLParser().parseFromString(
      `<root xmlns:x="urn:x" xmlns="urn:d"><sp Id="a"><x:c xmlns:x="urn:x">t</x:c><e xmlns=""/></sp></root>`,
      "application/xml",
    );
    const sp = doc.documentElement.getElementsByTagName("sp")[0];

    expect(XMLCanonicalizer.canonicalize(sp, method)).toBe(
      `<sp xmlns="urn:d" xmlns:x="urn:x" Id="a"><x:c>t</x:c><e xmlns=""></e></sp>`,
    );
  });

  it.each(METHODS)("renders comments only for the #WithComments variant (%s)", (method) => {
    const doc = createXMLParser().parseFromString(`<r><!-- note --><a/></r>`, "application/xml");

    expect(XMLCanonicalizer.canonicalize(doc.documentElement, method)).toBe("<r><a></a></r>");
    expect(
      XMLCanonicalizer.canonicalize(
        doc.documentElement,
        `${method}#WithComments`.replace("##", "#"),
      ),
    ).toBe("<r><!-- note --><a></a></r>");
  });

  it("carries inherited xml:* attributes onto a canonicalized subtree", () => {
    const doc = createXMLParser().parseFromString(
      `<root xml:lang="lv" xml:space="preserve" xml:base="http://x/"><sp Id="a"><c>t</c></sp></root>`,
      "application/xml",
    );
    const sp = doc.documentElement.getElementsByTagName("sp")[0];

    expect(
      XMLCanonicalizer.canonicalize(sp, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"),
    ).toBe(`<sp Id="a" xml:base="http://x/" xml:lang="lv" xml:space="preserve"><c>t</c></sp>`);
    expect(XMLCanonicalizer.canonicalize(sp, "http://www.w3.org/2006/12/xml-c14n11")).toBe(
      `<sp Id="a" xml:base="http://x/" xml:lang="lv" xml:space="preserve"><c>t</c></sp>`,
    );
    expect(XMLCanonicalizer.canonicalize(sp, "http://www.w3.org/2001/10/xml-exc-c14n#")).toBe(
      `<sp Id="a"><c>t</c></sp>`,
    );
  });

  it("applies the C14N 1.1 xml:base fixup to a canonicalized subtree", () => {
    const doc = createXMLParser().parseFromString(
      `<root xml:base="https://example.com/a/"><mid xml:base="b/"><sp Id="a"/><own xml:base="c.xml"/></mid></root>`,
      "application/xml",
    );
    const c14n11 = "http://www.w3.org/2006/12/xml-c14n11";

    expect(XMLCanonicalizer.canonicalize(doc.getElementsByTagName("sp")[0], c14n11)).toBe(
      `<sp Id="a" xml:base="https://example.com/a/b/"></sp>`,
    );
    expect(XMLCanonicalizer.canonicalize(doc.getElementsByTagName("own")[0], c14n11)).toBe(
      `<own xml:base="https://example.com/a/b/c.xml"></own>`,
    );
  });
});
