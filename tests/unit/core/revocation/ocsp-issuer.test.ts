import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "@peculiar/x509";
import { parseEdoc } from "../../../../src/core/parser";
import {
  extractCertsFromOCSPResponses,
  resolveIssuerFromChain,
} from "../../../../src/core/revocation/ocsp";

const sampleFilePath = join(__dirname, "../../../fixtures/valid_samples/SampleFile.edoc");

describe("OCSP issuer resolution from embedded data", () => {
  const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
  const sig = container.signatures[0];
  const signer = new X509Certificate(sig.certificatePEM);

  it("recovers the issuer certificate carried inside the embedded OCSP response", () => {
    const pems = extractCertsFromOCSPResponses(sig.revocationValues?.ocsp ?? []);

    expect(pems.length).toBeGreaterThan(0);
    const issuer = pems.map((p) => new X509Certificate(p)).find((c) => c.subject === signer.issuer);
    expect(issuer).toBeDefined();
  });

  it("resolves an issuer that actually signed the certificate", async () => {
    const pems = extractCertsFromOCSPResponses(sig.revocationValues?.ocsp ?? []);

    const issuer = await resolveIssuerFromChain(signer, pems);

    expect(issuer).not.toBeNull();
    expect(await signer.verify({ publicKey: issuer!, signatureOnly: true })).toBe(true);
  });

  it("returns null when no candidate matches the issuer name", async () => {
    expect(await resolveIssuerFromChain(signer, [])).toBeNull();
  });
});
