// tests/unit/core/parser.test.ts
import { readFileSync } from "fs";
import { join } from "path";
import { unzipSync } from "fflate";
import { __test__, parseSignatureFile } from "../../../src/core/parser/signatureParser";
import { createXMLParser } from "../../../src/utils/xmlParser";
import { locateTopLevelSignatures } from "../../../src/core/parser/signatureStructure";

const { parseSignatureElement } = __test__;

const SAMPLE = join(__dirname, "../../fixtures/valid_samples/SampleFile.edoc");
const SIGNATURE_PATH = "META-INF/edoc-signatures-S1.xml";

function loadSampleSignatureXml(): string {
  const files = unzipSync(readFileSync(SAMPLE));
  return new TextDecoder().decode(files[SIGNATURE_PATH]);
}

function parseTopLevel(xml: string) {
  const doc = createXMLParser().parseFromString(xml, "application/xml");
  const [signature] = locateTopLevelSignatures(doc);
  return parseSignatureElement(signature, doc);
}

const DS = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';

function minimalSignature(signedInfoInner: string, extra = ""): string {
  return `<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#"><ds:Signature ${DS} Id="S0">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      ${signedInfoInner}
    </ds:SignedInfo>
    <ds:SignatureValue>AAAA</ds:SignatureValue>
    ${extra}
  </ds:Signature></asic:XAdESSignatures>`;
}

const reference = (uri: string, digest: string) => `<ds:Reference URI="${uri}">
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  <ds:DigestValue>${digest}</ds:DigestValue>
</ds:Reference>`;

describe("Signature Parser", () => {
  it("should extract data from signature element", () => {
    const result = parseTopLevel(loadSampleSignatureXml());

    expect(result.id).toBe("S1");
    expect(result.signingTime.toISOString()).toBe("2025-03-19T16:59:22.000Z");
    expect(result.certificatePEM).toContain("-----BEGIN CERTIFICATE-----");
    expect(result.publicKey).toBeDefined();
    expect(result.signerInfo?.commonName).toBeDefined();
    expect(result.signatureValue?.length).toBeGreaterThan(0);
    expect(result.canonicalSignatureValue).toContain("<ds:SignatureValue");
    expect(result.canonicalizationMethod).toBe("http://www.w3.org/2006/12/xml-c14n11");
    expect(result.references.sort()).toEqual(["Sample File.docx", "Sample File.pdf"]);
    expect(Object.keys(result.signedChecksums).sort()).toEqual([
      "Sample File.docx",
      "Sample File.pdf",
    ]);
    expect(result.signatureTimestamp).toBeDefined();
  });

  it("parseSignatureFile parses the top-level signature of a signature file", () => {
    const xml = loadSampleSignatureXml();
    const result = parseSignatureFile(new TextEncoder().encode(xml), SIGNATURE_PATH);
    expect(result?.id).toBe("S1");
    expect(result?.rawXml).toBe(xml);
  });

  it("falls back to the default canonicalizer when timestamp c14n URI is unsupported", () => {
    const xml = minimalSignature(
      reference("doc.txt", "ZGlnZXN0"),
      `<ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
        <xades:UnsignedProperties><xades:UnsignedSignatureProperties>
          <xades:SignatureTimeStamp>
            <ds:CanonicalizationMethod Algorithm="urn:example:unsupported-c14n"/>
            <xades:EncapsulatedTimeStamp>AAAA</xades:EncapsulatedTimeStamp>
          </xades:SignatureTimeStamp>
        </xades:UnsignedSignatureProperties></xades:UnsignedProperties>
      </xades:QualifyingProperties></ds:Object>`,
    );

    const result = parseTopLevel(xml);
    expect(result.signatureTimestamp).toBe("AAAA");
    expect(result.canonicalSignatureValue).toContain("<ds:SignatureValue");
  });

  it("only reads references from the SignedInfo that is a direct child of the signature", () => {
    const xml = minimalSignature(
      reference("doc.txt", "cmVhbA=="),
      `<ds:Object><ds:SignedInfo>${reference("doc.txt", "b3RoZXI=")}</ds:SignedInfo></ds:Object>`,
    );

    const result = parseTopLevel(xml);
    expect(result.signedChecksums).toEqual({ "doc.txt": "cmVhbA==" });
  });

  it("rejects a signature with more than one SignedInfo", () => {
    const xml = `<ds:Signature ${DS}><ds:SignedInfo/><ds:SignedInfo/><ds:SignatureValue>AA</ds:SignatureValue></ds:Signature>`;
    expect(() => parseTopLevel(xml)).toThrow(/at most one ds:SignedInfo/);
  });

  it("does not accept SignedInfo from a foreign namespace", () => {
    const xml = `<ds:Signature ${DS}><x:SignedInfo xmlns:x="urn:example"/><ds:SignatureValue>AA</ds:SignatureValue></ds:Signature>`;
    expect(() => parseTopLevel(xml)).toThrow(/SignedInfo element not found/);
  });

  it("accepts file names that match Object.prototype properties", () => {
    const xml = minimalSignature(
      `${reference("constructor", "YQ==")}${reference("toString", "Yg==")}`,
    );
    const result = parseTopLevel(xml);
    expect(Object.keys(result.signedChecksums).sort()).toEqual(["constructor", "toString"]);
    expect(result.signedChecksums.constructor).toBe("YQ==");
  });

  it("rejects duplicate references to the same file", () => {
    const xml = minimalSignature(`${reference("doc.txt", "YQ==")}${reference("doc.txt", "Yg==")}`);
    expect(() => parseTopLevel(xml)).toThrow(/Duplicate reference/);
  });

  it("does not select signatures nested below the top level", () => {
    const xml = `<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#"><wrapper><ds:Signature ${DS}/></wrapper></asic:XAdESSignatures>`;
    const doc = createXMLParser().parseFromString(xml, "application/xml");
    expect(locateTopLevelSignatures(doc)).toHaveLength(0);
  });
});
