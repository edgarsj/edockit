import { X509Certificate } from "@peculiar/x509";
import { TSTInfo } from "@peculiar/asn1-tsp";
import { parseTimestamp, verifyTimestamp } from "../../../../src/core/timestamp/verify";
import { createTestTsa, buildTimestampToken, TestTsa, KeyKind } from "./tsa-test-utils";

const canonicalSignatureValue =
  '<ds:SignatureValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S0-SIG">AAAA</ds:SignatureValue>';
const otherSignatureValue =
  '<ds:SignatureValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S0-SIG">BBBB</ds:SignatureValue>';
const imprintData = new TextEncoder().encode(canonicalSignatureValue);

function samePem(a: string | undefined, b: X509Certificate): boolean {
  return !!a && new X509Certificate(a).equal(b);
}

describe("Timestamp token signature validation", () => {
  const tsas: Partial<Record<KeyKind, TestTsa>> = {};
  let otherTsa: TestTsa;
  let noEkuTsa: TestTsa;

  beforeAll(async () => {
    for (const kind of ["RSA", "RSA-PSS", "ECDSA-P256", "ECDSA-P384"] as KeyKind[]) {
      tsas[kind] = await createTestTsa(kind);
    }
    otherTsa = await createTestTsa("ECDSA-P256", { name: "CN=Other TSA, O=edockit tests" });
    noEkuTsa = await createTestTsa("ECDSA-P256", { timeStampingEku: false });
  }, 60000);

  describe.each(["RSA", "RSA-PSS", "ECDSA-P256", "ECDSA-P384"] as KeyKind[])("%s token", (kind) => {
    it("accepts a correctly signed token covering the signature", async () => {
      const tsa = tsas[kind]!;
      const token = await buildTimestampToken(tsa, { imprintData });

      const result = await verifyTimestamp(token, { canonicalSignatureValue });

      expect(result.reason).toBeUndefined();
      expect(result.isValid).toBe(true);
      expect(result.signatureValid).toBe(true);
      expect(result.coversSignature).toBe(true);
      expect(result.info?.genTime.toISOString()).toBe("2025-06-01T12:00:00.000Z");
      expect(samePem(result.info?.tsaCertificate, tsa.cert)).toBe(true);
    });

    it("rejects a token whose signature bytes were modified", async () => {
      const token = await buildTimestampToken(tsas[kind]!, {
        imprintData,
        tamperSignature: true,
      });

      const result = await verifyTimestamp(token, { canonicalSignatureValue });

      expect(result.isValid).toBe(false);
      expect(result.signatureValid).toBe(false);
      expect(result.coversSignature).toBe(true);
    });
  });

  it("rejects a token whose genTime was changed after signing", async () => {
    const token = await buildTimestampToken(tsas["ECDSA-P256"]!, {
      imprintData,
      replaceTstInfo: (original) =>
        new TSTInfo({ ...original, genTime: new Date("2019-01-01T00:00:00Z") }),
    });

    // The decoded time reflects the modified content...
    expect(parseTimestamp(token)?.genTime.toISOString()).toBe("2019-01-01T00:00:00.000Z");

    // ...but the token no longer verifies
    const result = await verifyTimestamp(token, { canonicalSignatureValue });
    expect(result.isValid).toBe(false);
    expect(result.signatureValid).toBe(false);
    expect(result.reason).toMatch(/message-digest/);
  });

  it("rejects a token whose message imprint was changed after signing", async () => {
    const otherHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(otherSignatureValue)),
    );
    const token = await buildTimestampToken(tsas.RSA!, {
      imprintData,
      replaceTstInfo: (original) => {
        original.messageImprint.hashedMessage.buffer = otherHash.buffer;
        return original;
      },
    });

    const result = await verifyTimestamp(token, { canonicalSignatureValue: otherSignatureValue });
    expect(result.coversSignature).toBe(true);
    expect(result.signatureValid).toBe(false);
    expect(result.isValid).toBe(false);
  });

  it("rejects a validly signed token that belongs to a different signature", async () => {
    const token = await buildTimestampToken(tsas["ECDSA-P384"]!, { imprintData });

    const result = await verifyTimestamp(token, { canonicalSignatureValue: otherSignatureValue });

    expect(result.signatureValid).toBe(true);
    expect(result.coversSignature).toBe(false);
    expect(result.isValid).toBe(false);
    expect(result.reason).toMatch(/hash mismatch/);
  });

  describe("TSA certificate identification", () => {
    it("uses the certificate referenced by the SignerInfo, not the first one", async () => {
      const tsa = tsas["ECDSA-P256"]!;
      const token = await buildTimestampToken(tsa, {
        imprintData,
        certificates: [otherTsa.cert, tsa.cert],
      });

      expect(samePem(parseTimestamp(token)?.tsaCertificate, tsa.cert)).toBe(true);

      const result = await verifyTimestamp(token, { canonicalSignatureValue });
      expect(result.isValid).toBe(true);
      expect(samePem(result.info?.tsaCertificate, tsa.cert)).toBe(true);
    });

    it("supports subjectKeyIdentifier signer identifiers", async () => {
      const tsa = tsas.RSA!;
      const token = await buildTimestampToken(tsa, {
        imprintData,
        certificates: [otherTsa.cert, tsa.cert],
        useSubjectKeyIdentifier: true,
      });

      const result = await verifyTimestamp(token, { canonicalSignatureValue });
      expect(result.isValid).toBe(true);
      expect(samePem(result.info?.tsaCertificate, tsa.cert)).toBe(true);
    });

    it("rejects a token when the referenced certificate is not available", async () => {
      const token = await buildTimestampToken(tsas["ECDSA-P256"]!, {
        imprintData,
        certificates: [otherTsa.cert],
      });

      expect(parseTimestamp(token)?.tsaCertificate).toBeUndefined();

      const result = await verifyTimestamp(token, { canonicalSignatureValue });
      expect(result.isValid).toBe(false);
      expect(result.signatureValid).toBe(false);
      expect(result.info?.tsaCertificate).toBeUndefined();
      expect(result.reason).toMatch(/not found/);
    });

    it("accepts the TSA certificate from options.certificates", async () => {
      const tsa = tsas["ECDSA-P256"]!;
      const token = await buildTimestampToken(tsa, { imprintData, certificates: [] });

      const withoutCert = await verifyTimestamp(token, { canonicalSignatureValue });
      expect(withoutCert.isValid).toBe(false);

      const result = await verifyTimestamp(token, {
        canonicalSignatureValue,
        certificates: [otherTsa.cert.toString("pem"), tsa.cert.toString("base64")],
      });
      expect(result.isValid).toBe(true);
      expect(samePem(result.info?.tsaCertificate, tsa.cert)).toBe(true);
    });

    it("rejects a token whose SignerInfo names a certificate with a different key", async () => {
      // Signed by one TSA key while claiming to be another TSA
      const token = await buildTimestampToken(tsas["ECDSA-P256"]!, {
        imprintData,
        certificates: [otherTsa.cert],
        sidCertificate: otherTsa.cert,
        essCertificate: otherTsa.cert,
      });

      const result = await verifyTimestamp(token, { canonicalSignatureValue });
      expect(result.isValid).toBe(false);
      expect(result.signatureValid).toBe(false);
      expect(result.reason).toMatch(/signature is invalid/);
    });

    it("rejects a token whose signing-certificate attribute names another certificate", async () => {
      const tsa = tsas["ECDSA-P256"]!;
      const token = await buildTimestampToken(tsa, {
        imprintData,
        certificates: [tsa.cert, otherTsa.cert],
        essCertificate: otherTsa.cert,
      });

      const result = await verifyTimestamp(token, { canonicalSignatureValue });
      expect(result.isValid).toBe(false);
      expect(result.signatureValid).toBe(false);
      expect(result.reason).toMatch(/SigningCertificateV2/);
    });

    it("accepts a token without a signing-certificate attribute", async () => {
      const token = await buildTimestampToken(tsas.RSA!, { imprintData, essCertificate: null });
      const result = await verifyTimestamp(token, { canonicalSignatureValue });
      expect(result.isValid).toBe(true);
    });

    it("rejects a TSA certificate without the timeStamping extended key usage", async () => {
      const token = await buildTimestampToken(noEkuTsa, { imprintData });

      const result = await verifyTimestamp(token, { canonicalSignatureValue });
      expect(result.signatureValid).toBe(true);
      expect(result.isValid).toBe(false);
      expect(result.reason).toMatch(/timeStamping extended key usage/);
    });
  });

  it("returns isValid false for data that is not a timestamp token", async () => {
    const result = await verifyTimestamp(Buffer.from("not a token").toString("base64"));
    expect(result.isValid).toBe(false);
    expect(result.reason).toBe("Failed to parse timestamp token");
  });
});
