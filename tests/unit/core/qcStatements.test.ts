import * as asn1js from "asn1js";
import {
  CertificatePolicyExtension,
  Extension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  X509CertificateGenerator,
} from "@peculiar/x509";
import {
  getCertificateQualificationFacts,
  getQcStatements,
  parseQcStatementsValue,
  QC_STATEMENTS_OID,
} from "../../../src/core/qcStatements";

function statement(oid: string, info?: asn1js.AsnType): asn1js.Sequence {
  return new asn1js.Sequence({
    value: [new asn1js.ObjectIdentifier({ value: oid }), ...(info ? [info] : [])],
  });
}

function qcStatementsDer(statements: asn1js.Sequence[]): ArrayBuffer {
  return new asn1js.Sequence({ value: statements }).toBER();
}

const ESIGN_STATEMENTS = qcStatementsDer([
  statement("0.4.0.1862.1.1"),
  statement(
    "0.4.0.1862.1.6",
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: "0.4.0.1862.1.6.1" })] }),
  ),
  statement(
    "1.3.6.1.5.5.7.11.2",
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: "0.4.0.194121.1.1" })] }),
  ),
  statement(
    "0.4.0.1862.1.5",
    new asn1js.Sequence({
      value: [
        new asn1js.Sequence({
          value: [
            new asn1js.IA5String({ value: "https://example.test/pds" }),
            new asn1js.PrintableString({ value: "en" }),
          ],
        }),
      ],
    }),
  ),
  statement("0.4.0.1862.1.3", new asn1js.Integer({ value: 30 })),
  statement("0.4.0.1862.1.4"),
]);

describe("qcStatements", () => {
  it("parses ETSI EN 319 412-5 statements", () => {
    expect(parseQcStatementsValue(ESIGN_STATEMENTS)).toEqual({
      qcCompliance: true,
      qcQSCD: true,
      qcTypes: ["esign"],
      semanticsIdentifier: "0.4.0.194121.1.1",
      qcPDS: [{ url: "https://example.test/pds", language: "en" }],
      qcRetentionPeriod: 30,
      statementIds: [
        "0.4.0.1862.1.1",
        "0.4.0.1862.1.6",
        "1.3.6.1.5.5.7.11.2",
        "0.4.0.1862.1.5",
        "0.4.0.1862.1.3",
        "0.4.0.1862.1.4",
      ],
    });
  });

  it("reads multiple QcType values and QcCClegislation", () => {
    const parsed = parseQcStatementsValue(
      qcStatementsDer([
        statement(
          "0.4.0.1862.1.6",
          new asn1js.Sequence({
            value: [
              new asn1js.ObjectIdentifier({ value: "0.4.0.1862.1.6.2" }),
              new asn1js.ObjectIdentifier({ value: "0.4.0.1862.1.6.3" }),
              new asn1js.ObjectIdentifier({ value: "1.2.3.4" }),
            ],
          }),
        ),
        statement(
          "0.4.0.1862.1.7",
          new asn1js.Sequence({ value: [new asn1js.PrintableString({ value: "CH" })] }),
        ),
      ]),
    );

    expect(parsed.qcCompliance).toBe(false);
    expect(parsed.qcTypes).toEqual(["eseal", "web"]);
    expect(parsed.qcCClegislation).toEqual(["CH"]);
  });

  it("rejects malformed values", () => {
    expect(() => parseQcStatementsValue(new Uint8Array([0x04, 0x01, 0x00]))).toThrow();
  });

  it("extracts qualification facts from a certificate", async () => {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const certificate = await X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=Signer, SN=Doe, G=Jane, C=LV, 2.5.4.5=PNOLV-010101-12345",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2027-01-01T00:00:00Z"),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new KeyUsagesExtension(KeyUsageFlags.nonRepudiation, true),
        new CertificatePolicyExtension(["1.3.6.1.4.1.32061.2.1.1", "0.4.0.194112.1.2"]),
        new Extension(QC_STATEMENTS_OID, false, ESIGN_STATEMENTS),
      ],
    });
    const parsed = new X509Certificate(certificate.toString("pem"));

    const facts = getCertificateQualificationFacts(parsed);
    expect(facts.qcStatements?.qcTypes).toEqual(["esign"]);
    expect([...(facts.keyUsage ?? [])]).toEqual(["nonRepudiation"]);
    expect(facts.policies).toEqual(["1.3.6.1.4.1.32061.2.1.1", "0.4.0.194112.1.2"]);
    expect(facts.subjectAttributeOids.has("2.5.4.5")).toBe(true);
    expect(facts.subjectAttributeOids.has("2.5.4.42")).toBe(true);
    expect(facts.notBefore.toISOString()).toBe("2024-01-01T00:00:00.000Z");
  });

  it("returns null for certificates without the extension", async () => {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const certificate = await X509CertificateGenerator.createSelfSigned({
      serialNumber: "02",
      name: "CN=Plain",
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2027-01-01T00:00:00Z"),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });

    expect(getQcStatements(new X509Certificate(certificate.toString("pem")))).toBeNull();
    expect(getCertificateQualificationFacts(certificate).keyUsage).toBeNull();
  });
});
