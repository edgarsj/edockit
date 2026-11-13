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
});
