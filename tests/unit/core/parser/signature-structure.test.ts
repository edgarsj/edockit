import { createXMLParser } from "../../../../src/utils/xmlParser";
import { resolveSameDocumentReference } from "../../../../src/core/parser/signatureStructure";

describe("resolveSameDocumentReference", () => {
  const doc = createXMLParser().parseFromString(
    `<r><a Id="plain"/><b Id="sp-é"/><c Id="dup"/><d Id="dup"/></r>`,
    "application/xml",
  );

  it("resolves plain and percent-encoded fragments", () => {
    expect(resolveSameDocumentReference(doc, "#plain").localName).toBe("a");
    expect(resolveSameDocumentReference(doc, "#sp-%C3%A9").localName).toBe("b");
  });

  it("rejects missing, ambiguous and malformed references", () => {
    expect(() => resolveSameDocumentReference(doc, "#missing")).toThrow(/not found/);
    expect(() => resolveSameDocumentReference(doc, "#dup")).toThrow(/ambiguous/);
    expect(() => resolveSameDocumentReference(doc, "#bad%E0")).toThrow(/invalid fragment/);
  });
});
