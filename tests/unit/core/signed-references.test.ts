import { createHash } from "crypto";
import { createXMLParser } from "../../../src/utils/xmlParser";
import { XMLCanonicalizer } from "../../../src/core/canonicalization/XMLCanonicalizer";
import { verifySignedProperties } from "../../../src/core/signedReferences";
import { computeDigest } from "../../../src/core/verification";

const DS = "http://www.w3.org/2000/09/xmldsig#";

// [transform on the reference, comment-free algorithm used to compute the digest]
const VARIANTS: Array<[string, string]> = [
  [
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  ],
  ["http://www.w3.org/2006/12/xml-c14n11#WithComments", "http://www.w3.org/2006/12/xml-c14n11"],
  [
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
  ],
];

function buildDocument(transform: string, digest: string) {
  // xmlns:unused is in scope but not used, so inclusive and exclusive c14n differ
  return `<ds:Signature xmlns:ds="${DS}" xmlns:unused="urn:unused" Id="S"><ds:SignedInfo><ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp"><ds:Transforms><ds:Transform Algorithm="${transform}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><xades:SignedProperties Id="sp"><!-- not signed --><xades:SignedSignatureProperties/></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature>`;
}

describe("same-document reference digests", () => {
  it.each(VARIANTS)(
    "omits comments for bare-name references with %s",
    async (transform, commentFree) => {
      const probe = createXMLParser().parseFromString(
        buildDocument(transform, "x"),
        "application/xml",
      );
      const digest = createHash("sha256")
        .update(
          XMLCanonicalizer.canonicalize(
            probe.getElementsByTagName("xades:SignedProperties")[0],
            commentFree,
          ),
        )
        .digest("base64");

      const doc = createXMLParser().parseFromString(
        buildDocument(transform, digest),
        "application/xml",
      );
      const signature = doc.documentElement;
      const references = Array.from(
        signature.getElementsByTagName("ds:SignedInfo")[0].getElementsByTagName("ds:Reference"),
      );

      const result = await verifySignedProperties(
        doc,
        signature,
        references,
        new Uint8Array([1, 2, 3]),
        (data, uri) => computeDigest(data, uri),
      );

      expect(result.references[0]).toMatchObject({ uri: "#sp", isValid: true });
    },
  );

  it("rejects unknown canonicalization algorithms instead of falling back", () => {
    const doc = createXMLParser().parseFromString("<r/>", "application/xml");
    expect(() =>
      XMLCanonicalizer.canonicalize(doc.documentElement, "http://www.w3.org/2001/10/xml-exc-c14n"),
    ).toThrow(/Unsupported canonicalization method/);
    expect(XMLCanonicalizer.canonicalize(doc.documentElement, "c14n")).toBe("<r></r>");
  });
});
