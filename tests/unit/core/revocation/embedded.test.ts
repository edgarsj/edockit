import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "@peculiar/x509";
import { parseEdoc } from "../../../../src/core/parser";
import { checkRevocationFromEmbedded } from "../../../../src/core/revocation/embedded";

const sampleFilePath = join(__dirname, "../../../fixtures/valid_samples/SampleFile.edoc");

describe("checkRevocationFromEmbedded", () => {
  const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
  const sig = container.signatures[0];
  const cert = new X509Certificate(sig.certificatePEM);
  const atTime = sig.signingTime;

  it("returns a 'good' result for the signer cert from the embedded OCSP response", () => {
    const result = checkRevocationFromEmbedded(
      cert,
      { ocsp: sig.revocationValues?.ocsp ?? [] },
      atTime,
    );

    expect(result).not.toBeNull();
    expect(result!.status).toBe("good");
    expect(result!.method).toBe("ocsp");
    expect(result!.fromEmbedded).toBe(true);
  });

  it("returns null when no embedded material is provided", () => {
    expect(checkRevocationFromEmbedded(cert, {}, atTime)).toBeNull();
    expect(checkRevocationFromEmbedded(cert, { ocsp: [], crl: [] }, atTime)).toBeNull();
  });

  it("returns null when the embedded OCSP does not cover this certificate's serial", () => {
    // The embedded OCSP response is for the signer; the issuer certificate has a
    // different serial number, so the response must not be treated as covering it.
    const issuerPem = sig.certificateChain?.[0];
    if (!issuerPem) {
      return; // no chain cert embedded in this fixture; nothing to assert
    }
    const issuerCert = new X509Certificate(issuerPem);
    const result = checkRevocationFromEmbedded(
      issuerCert,
      { ocsp: sig.revocationValues?.ocsp ?? [] },
      atTime,
    );
    expect(result).toBeNull();
  });
});
