import { createHash } from "crypto";
import { createXMLParser } from "../../../src/utils/xmlParser";
import { XMLCanonicalizer } from "../../../src/core/canonicalization/XMLCanonicalizer";
import { verifySignedProperties } from "../../../src/core/signedReferences";
import { computeDigest } from "../../../src/core/verification";

const DS = "http://www.w3.org/2000/09/xmldsig#";
const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

function buildDocument(transform: string, digest: string) {
  return `<ds:Signature xmlns:ds="${DS}" Id="S"><ds:SignedInfo><ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp"><ds:Transforms><ds:Transform Algorithm="${transform}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><xades:SignedProperties Id="sp"><!-- not signed --><xades:SignedSignatureProperties/></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature>`;
}

describe("same-document reference digests", () => {
  it("omits comments for bare-name references even with a #WithComments transform", async () => {
    // Digest of the SignedProperties node-set without comments
    const probe = createXMLParser().parseFromString(buildDocument(C14N, "x"), "application/xml");
    const signedProperties = probe.getElementsByTagName("xades:SignedProperties")[0];
    const digest = createHash("sha256")
      .update(XMLCanonicalizer.canonicalize(signedProperties, C14N))
      .digest("base64");

    const doc = createXMLParser().parseFromString(
      buildDocument(`${C14N}#WithComments`, digest),
      "application/xml",
    );
    const signature = doc.documentElement;
    const signedInfo = signature.getElementsByTagName("ds:SignedInfo")[0];
    const references = Array.from(signedInfo.getElementsByTagName("ds:Reference"));

    const result = await verifySignedProperties(
      doc,
      signature,
      references,
      new Uint8Array([1, 2, 3]),
      (data, uri) => computeDigest(data, uri),
    );

    expect(result.references[0]).toMatchObject({ uri: "#sp", isValid: true });
  });
});
