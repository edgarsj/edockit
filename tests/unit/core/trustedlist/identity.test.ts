import { webcrypto } from "crypto";
import * as x509 from "@peculiar/x509";
import { extractIssuerIdentityFromCertificate } from "../../../../src/core/trustedlist/identity";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
const CA_NAME = "CN=Identity Test CA, O=Example, C=LV";

async function keys() {
  return webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
}

async function createCa(caKeys: CryptoKeyPair) {
  return x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: CA_NAME,
    notBefore: new Date("2024-01-01"),
    notAfter: new Date("2030-01-01"),
    keys: caKeys,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
    ],
  });
}

/** A leaf naming CA_NAME with the AKI of `claimedIssuerKeys`, signed by `signingKeys`. */
async function createLeaf(claimedIssuerKeys: CryptoKeyPair, signingKeys: CryptoKeyPair) {
  const leafKeys = await keys();
  return x509.X509CertificateGenerator.create({
    serialNumber: "02",
    subject: "CN=Signer, C=LV",
    issuer: CA_NAME,
    notBefore: new Date("2024-01-01"),
    notAfter: new Date("2030-01-01"),
    publicKey: leafKeys.publicKey,
    signingKey: signingKeys.privateKey,
    signingAlgorithm: ALG,
    extensions: [await x509.AuthorityKeyIdentifierExtension.create(claimedIssuerKeys.publicKey)],
  });
}

describe("extractIssuerIdentityFromCertificate", () => {
  it("resolves an issuer whose key verifies the certificate", async () => {
    const caKeys = await keys();
    const ca = await createCa(caKeys);
    const leaf = await createLeaf(caKeys, caKeys);

    const identity = await extractIssuerIdentityFromCertificate(leaf.toString("pem"), {
      certificateChain: [ca.toString("pem")],
    });

    expect(identity.issuerCertificate).not.toBeNull();
    expect(identity.issuerSignatureMismatch).toBeUndefined();
  });

  it("does not report a mismatch for a same-name CA certificate with another key", async () => {
    // e.g. a renewed CA: same subject DN, different key and key identifier
    const currentCaKeys = await keys();
    const renewedCa = await createCa(await keys());
    const leaf = await createLeaf(currentCaKeys, currentCaKeys);

    const identity = await extractIssuerIdentityFromCertificate(leaf.toString("pem"), {
      certificateChain: [renewedCa.toString("pem")],
    });

    expect(identity.issuerCertificate).toBeNull();
    expect(identity.issuerSignatureMismatch).toBe(false);
  });

  it("reports a mismatch when the named issuer key did not sign the certificate", async () => {
    const caKeys = await keys();
    const ca = await createCa(caKeys);
    // Claims the CA (name and AKI) but is signed with an unrelated key
    const leaf = await createLeaf(caKeys, await keys());

    const identity = await extractIssuerIdentityFromCertificate(leaf.toString("pem"), {
      certificateChain: [ca.toString("pem")],
    });

    expect(identity.issuerCertificate).toBeNull();
    expect(identity.issuerSignatureMismatch).toBe(true);
  });
});
