import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "@peculiar/x509";
import {
  checkCRL,
  isSerialInCRL,
  parseCRL,
  validateCRL,
} from "../../../../src/core/revocation/crl";
import { extractCertsFromOCSPResponses } from "../../../../src/core/revocation/ocsp";
import { parseEdoc } from "../../../../src/core/parser";
import { CRL_URL, TestCA, buildCRL, createCA, issueLeaf } from "./pki-helpers";

const lvCrlPath = join(__dirname, "../../../fixtures/crl/LV_eID_ICA_2021.crl");

function readArrayBuffer(path: string): ArrayBuffer {
  const buf = readFileSync(path);
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

describe("parseCRL with national-scale CRLs", () => {
  it("parses a CRL that exceeds the asn1js default node cap (>10k nodes)", () => {
    // The LV eID ICA 2021 CRL has ~13k revoked entries, far more than asn1js's
    // DEFAULT_MAX_NODES (10000) DoS guard. parseCRL must not return null for it.
    const der = readArrayBuffer(lvCrlPath);

    const crl = parseCRL(der);

    expect(crl).not.toBeNull();
    expect(crl!.entries.length).toBeGreaterThan(10000);
  });

  it("exposes usable entries after parsing a large CRL", () => {
    const der = readArrayBuffer(lvCrlPath);

    const crl = parseCRL(der);

    // A serial known to be present in this CRL snapshot.
    const knownRevoked = isSerialInCRL(crl!, "1765cd7d4018b7be662ce1abb2b97197");
    expect(knownRevoked.isRevoked).toBe(true);
    expect(knownRevoked.revokedAt).toBeInstanceOf(Date);
  });
});

describe("validateCRL with the national-scale CRL fixture", () => {
  const container = parseEdoc(
    new Uint8Array(
      readFileSync(join(__dirname, "../../../fixtures/valid_samples/SampleFile.edoc")),
    ),
  );
  const sig = container.signatures[0];
  const signer = new X509Certificate(sig.certificatePEM);
  // The CRL issuer (LV eID ICA 2021) is carried in the signature's embedded OCSP response.
  const issuer = extractCertsFromOCSPResponses(sig.revocationValues?.ocsp ?? [])
    .map((pem) => new X509Certificate(pem))
    .find((c) => c.subject === signer.issuer)!;

  it("verifies the fixture CRL against its issuer while it was current", async () => {
    const crl = parseCRL(readArrayBuffer(lvCrlPath))!;
    const now = new Date(crl.thisUpdate.getTime() + 60 * 1000);

    expect(await validateCRL(crl, signer, issuer, { now })).toBeNull();
  });

  it("treats the fixture CRL as stale after its nextUpdate", async () => {
    const crl = parseCRL(readArrayBuffer(lvCrlPath))!;
    const now = new Date(crl.nextUpdate!.getTime() + 24 * 3600 * 1000);

    expect(await validateCRL(crl, signer, issuer, { now })).toMatch(/stale/);
  });

  it("rejects the fixture CRL for an issuer certificate with a different key", async () => {
    const crl = parseCRL(readArrayBuffer(lvCrlPath))!;
    const otherKeyIssuer = await createCA(issuer.subject);
    const now = new Date(crl.thisUpdate.getTime() + 60 * 1000);

    expect(await validateCRL(crl, signer, otherKeyIssuer.cert, { now })).toMatch(/signature/);
  });
});

describe("CRL validation with a local CA", () => {
  let ca: TestCA;
  let leaf: X509Certificate;
  let fetchSpy: jest.SpyInstance | undefined;

  beforeAll(async () => {
    ca = await createCA();
    leaf = (await issueLeaf(ca, "1234abcd")).cert;
  }, 30000);

  afterEach(() => {
    fetchSpy?.mockRestore();
    fetchSpy = undefined;
  });

  function serveCRL(crl: ArrayBuffer) {
    fetchSpy = jest.spyOn(global, "fetch").mockImplementation(async (input: any) => {
      if (String(input) === CRL_URL) {
        return new Response(crl, { status: 200 });
      }
      throw new Error(`unexpected fetch: ${String(input)}`);
    });
  }

  it("returns good for a current CRL signed by the issuer that does not list the certificate", async () => {
    serveCRL(await buildCRL(ca, { entries: [{ serialNumber: "0badc0de" }] }));

    const result = await checkCRL(leaf, { issuerCertificate: ca.cert });

    expect(result.status).toBe("good");
    expect(result.method).toBe("crl");
  });

  it("returns revoked when a verified CRL lists the certificate", async () => {
    const revocationDate = new Date("2026-01-02T00:00:00Z");
    serveCRL(await buildCRL(ca, { entries: [{ serialNumber: "1234abcd", revocationDate }] }));

    const result = await checkCRL(leaf, { issuerCertificate: ca.cert });

    expect(result.status).toBe("revoked");
    expect(result.revokedAt?.toISOString()).toBe(revocationDate.toISOString());
  });

  it("does not return good for a CRL with a bad signature", async () => {
    // Same issuer name, different key.
    const otherKeyCa = await createCA(ca.cert.subject);
    serveCRL(await buildCRL(otherKeyCa));

    const result = await checkCRL(leaf, { issuerCertificate: ca.cert });

    expect(result.status).toBe("unknown");
    expect(result.isValid).toBe(false);
    expect(result.reason).toMatch(/signature/);
  });

  it("does not return good for a CRL from a different issuer name", async () => {
    serveCRL(await buildCRL(ca, { issuerName: "CN=Someone Else, C=LV" }));

    const result = await checkCRL(leaf, { issuerCertificate: ca.cert });

    expect(result.status).toBe("unknown");
    expect(result.reason).toMatch(/issuer/);
  });

  it("does not return good for a stale CRL", async () => {
    serveCRL(
      await buildCRL(ca, {
        thisUpdate: new Date(Date.now() - 10 * 24 * 3600 * 1000),
        nextUpdate: new Date(Date.now() - 3 * 24 * 3600 * 1000),
      }),
    );

    const result = await checkCRL(leaf, { issuerCertificate: ca.cert });

    expect(result.status).toBe("unknown");
    expect(result.reason).toMatch(/stale/);
  });

  it("returns unknown when the issuer certificate cannot be obtained", async () => {
    fetchSpy = jest.spyOn(global, "fetch").mockRejectedValue(new Error("offline"));

    const result = await checkCRL(leaf);

    expect(result.status).toBe("unknown");
    expect(result.reason).toMatch(/issuer/);
  });
});
