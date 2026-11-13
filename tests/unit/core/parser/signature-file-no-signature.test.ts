import { parseSignatureFile } from "../../../../src/core/parser/signatureParser";

const NS =
  'xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';

function encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

describe("parseSignatureFile without a Signature element", () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it("returns null for an XAdESSignatures document with no Signature element", () => {
    const xml = `<asic:XAdESSignatures ${NS}>
      <ds:SignedInfo>
        <ds:Reference URI="doc.txt">
          <ds:DigestValue>AAAA</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>BBBB</ds:SignatureValue>
    </asic:XAdESSignatures>`;

    expect(parseSignatureFile(encode(xml), "META-INF/signatures0.xml")).toBeNull();
  });

  it("returns null for an unrelated document", () => {
    const xml = `<root><child/></root>`;
    expect(parseSignatureFile(encode(xml), "META-INF/signatures0.xml")).toBeNull();
  });
});
