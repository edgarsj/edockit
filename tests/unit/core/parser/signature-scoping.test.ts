import { parseSignatureElement } from "../../../../src/core/parser/signatureParser";
import { createXMLParser, querySelectorAll } from "../../../../src/utils/xmlParser";

// XAdES qualifying properties (RevocationValues, CertificateValues, SigningTime,
// SignatureTimeStamp) must be read from the CURRENT signature, not document-wide.
// Otherwise every signature in a multi-signature document inherits the first
// signature's embedded material.
function buildSignature(id: string, marker: string): string {
  return `<ds:Signature Id="${id}">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
      <ds:Reference URI="doc.txt">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>digest-${marker}</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>sigval-${marker}</ds:SignatureValue>
    <ds:Object><xades:QualifyingProperties>
      <xades:SignedProperties><xades:SignedSignatureProperties>
        <xades:SigningTime>${marker === "FIRST" ? "2021-01-01T00:00:00Z" : "2022-02-02T00:00:00Z"}</xades:SigningTime>
      </xades:SignedSignatureProperties></xades:SignedProperties>
      <xades:UnsignedSignatureProperties>
        <xades:CertificateValues>
          <xades:EncapsulatedX509Certificate>CERT-${marker}</xades:EncapsulatedX509Certificate>
        </xades:CertificateValues>
        <xades:RevocationValues><xades:OCSPValues>
          <xades:EncapsulatedOCSPValue>OCSP-${marker}</xades:EncapsulatedOCSPValue>
        </xades:OCSPValues></xades:RevocationValues>
      </xades:UnsignedSignatureProperties>
    </xades:QualifyingProperties></ds:Object>
  </ds:Signature>`;
}

const xml = `<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">${buildSignature(
  "S0",
  "FIRST",
)}${buildSignature("S1", "SECOND")}</asic:XAdESSignatures>`;

describe("XAdES qualifying-property scoping in multi-signature documents", () => {
  const doc = createXMLParser().parseFromString(xml, "application/xml") as any;
  const signatureElements = querySelectorAll(doc, "ds\\:Signature, Signature");

  it("parses both signatures", () => {
    expect(signatureElements.length).toBe(2);
  });

  it("reads each signature's own RevocationValues", () => {
    const second = parseSignatureElement(signatureElements[1], doc);
    expect(second.revocationValues?.ocsp).toEqual(["OCSP-SECOND"]);
  });

  it("reads each signature's own CertificateValues (chain)", () => {
    const second = parseSignatureElement(signatureElements[1], doc);
    expect(second.certificateChain?.some((c) => c.includes("CERT-SECOND"))).toBe(true);
    expect(second.certificateChain?.some((c) => c.includes("CERT-FIRST"))).toBe(false);
  });

  it("reads each signature's own SigningTime", () => {
    const second = parseSignatureElement(signatureElements[1], doc);
    expect(second.signingTime.toISOString()).toBe("2022-02-02T00:00:00.000Z");
  });
});
