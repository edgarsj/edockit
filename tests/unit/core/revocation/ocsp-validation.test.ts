import {
  AuthorityInfoAccessExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  X509Certificate,
} from "@peculiar/x509";
import { checkOCSP, parseOCSPResponse } from "../../../../src/core/revocation/ocsp";
import {
  OCSP_URL,
  TestCA,
  KeyAndAlg,
  buildCertId,
  buildOCSPResponse,
  createCA,
  generateKey,
  issueCertificate,
  issueLeaf,
  issueResponder,
} from "./pki-helpers";

jest.setTimeout(30000);

describe("OCSP response validation", () => {
  let ca: TestCA;
  let leaf: X509Certificate;
  let otherLeaf: X509Certificate;
  let responder: { cert: X509Certificate } & KeyAndAlg;

  beforeAll(async () => {
    ca = await createCA();
    leaf = (await issueLeaf(ca, "1234abcd")).cert;
    otherLeaf = (await issueLeaf(ca, "5678ef01")).cert;
    responder = await issueResponder(ca);
  });

  it("accepts a good response signed by a delegated responder", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("good");
    expect(result.isValid).toBe(true);
  });

  it("accepts a good response signed by the issuing CA itself", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: ca.cert,
      signer: ca,
      responderIdByName: true,
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("good");
  });

  it("accepts an RSA-PSS-signed response from a delegated responder", async () => {
    const pssResponder = await issueResponder(ca, { key: await generateKey("pss") });
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: pssResponder.cert,
      signer: pssResponder,
      certs: [pssResponder.cert],
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("good");
  });

  it("accepts an ECDSA-signed response from a delegated responder", async () => {
    const ecResponder = await issueResponder(ca, { key: await generateKey("ec") });
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: ecResponder.cert,
      signer: ecResponder,
      certs: [ecResponder.cert],
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("good");
  });

  it("reports revoked status with the revocation time", async () => {
    const revokedAt = new Date("2026-01-02T03:04:05Z");
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
      status: "revoked",
      revokedAt,
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("revoked");
    expect(result.revokedAt?.toISOString()).toBe(revokedAt.toISOString());
  });

  it("does not return good when the signature is invalid", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
      corruptSignature: true,
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).not.toBe("good");
    expect(result.isValid).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it("does not return good when signed by a key that does not match the responder certificate", async () => {
    const otherKey = await generateKey("rsa");
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: otherKey,
      certs: [responder.cert],
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).not.toBe("good");
  });

  it("does not return good for a responder certificate without the OCSPSigning EKU", async () => {
    const noEku = await issueResponder(ca, { eku: false });
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: noEku.cert,
      signer: noEku,
      certs: [noEku.cert],
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).not.toBe("good");
    expect(result.reason).toMatch(/OCSPSigning/);
  });

  it("does not return good for a responder certificate issued by a different CA", async () => {
    // Same CA name, different key: the responder chains to the wrong issuer key.
    const otherCa = await createCA(ca.cert.subject);
    const otherResponder = await issueResponder(otherCa);
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: otherResponder.cert,
      signer: otherResponder,
      certs: [otherResponder.cert],
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).not.toBe("good");
  });

  it("does not return good when the responder certificate is not included", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [],
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).not.toBe("good");
  });

  it("does not return good for an expired responder certificate", async () => {
    const expired = await issueCertificate(ca, {
      subject: "CN=Expired Responder, C=LV",
      serialNumber: "78",
      notBefore: new Date(Date.now() - 10 * 24 * 3600 * 1000),
      notAfter: new Date(Date.now() - 24 * 3600 * 1000),
      extensions: [new ExtendedKeyUsageExtension([ExtendedKeyUsage.ocspSigning])],
    });
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: expired.cert,
      signer: expired,
      certs: [expired.cert],
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).not.toBe("good");
  });

  it("does not return good when the CertID is for a different certificate", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
      certId: await buildCertId(otherLeaf, ca.cert),
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("unknown");
    expect(result.reason).toMatch(/does not contain a status for this certificate/);
  });

  it("does not return good when the CertID names a different issuer", async () => {
    const otherCa = await createCA("CN=Other CA, C=LV");
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
      certId: await buildCertId(leaf, otherCa.cert),
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("unknown");
  });

  it("does not return good when nextUpdate has passed", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
      thisUpdate: new Date(Date.now() - 2 * 3600 * 1000),
      nextUpdate: new Date(Date.now() - 3600 * 1000),
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("unknown");
    expect(result.reason).toMatch(/stale/);
  });

  it("does not return good when thisUpdate is in the future", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
      thisUpdate: new Date(Date.now() + 3600 * 1000),
      nextUpdate: new Date(Date.now() + 2 * 3600 * 1000),
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("unknown");
  });

  it("does not return good for an old response without nextUpdate", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
      thisUpdate: new Date(Date.now() - 3 * 24 * 3600 * 1000),
      nextUpdate: null,
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("unknown");
  });

  it("accepts a recent response without nextUpdate", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
      nextUpdate: null,
    });

    const result = await parseOCSPResponse(response, leaf, ca.cert);

    expect(result.status).toBe("good");
  });

  it("returns error for unparseable data", async () => {
    const result = await parseOCSPResponse(new Uint8Array([1, 2, 3]).buffer, leaf, ca.cert);

    expect(result.status).toBe("error");
  });
});

describe("checkOCSP", () => {
  let ca: TestCA;
  let leaf: X509Certificate;
  let responder: { cert: X509Certificate } & KeyAndAlg;
  let fetchSpy: jest.SpyInstance;

  beforeAll(async () => {
    ca = await createCA();
    leaf = (await issueLeaf(ca)).cert;
    responder = await issueResponder(ca);
  });

  afterEach(() => {
    fetchSpy?.mockRestore();
  });

  it("returns good for a valid response from the responder URL", async () => {
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: responder.cert,
      signer: responder,
      certs: [responder.cert],
    });
    fetchSpy = jest
      .spyOn(global, "fetch")
      .mockImplementation(async () => new Response(response, { status: 200 }));

    const result = await checkOCSP(leaf, null, { certificateChain: [ca.cert.toString("pem")] });

    expect(result.status).toBe("good");
    expect(fetchSpy).toHaveBeenCalledWith(OCSP_URL, expect.objectContaining({ method: "POST" }));
  });

  it("does not return good when the response is signed by an unrelated key", async () => {
    const outsider = await createCA(ca.cert.subject);
    const response = await buildOCSPResponse({
      cert: leaf,
      issuer: ca.cert,
      signerCert: outsider.cert,
      signer: outsider,
      certs: [outsider.cert],
      responderIdByName: true,
    });
    fetchSpy = jest
      .spyOn(global, "fetch")
      .mockImplementation(async () => new Response(response, { status: 200 }));

    const result = await checkOCSP(leaf, null, { certificateChain: [ca.cert.toString("pem")] });

    expect(result.status).not.toBe("good");
    expect(result.isValid).toBe(false);
  });

  it("rejects a supplied issuer certificate that did not sign the certificate", async () => {
    const outsider = await createCA(ca.cert.subject);
    fetchSpy = jest.spyOn(global, "fetch");

    const result = await checkOCSP(leaf, outsider.cert);

    expect(result.status).toBe("unknown");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("tries at most three responder URLs", async () => {
    const urls = [1, 2, 3, 4, 5].map((i) => `http://ocsp${i}.example.test/`);
    const manyUrls = await issueCertificate(ca, {
      subject: "CN=Many URLs, C=LV",
      serialNumber: "99",
      extensions: [new AuthorityInfoAccessExtension({ ocsp: urls })],
    });
    fetchSpy = jest.spyOn(global, "fetch").mockRejectedValue(new Error("offline"));

    const result = await checkOCSP(manyUrls.cert, ca.cert);

    expect(result.status).not.toBe("good");
    expect(fetchSpy).toHaveBeenCalledTimes(3);
  });
});
