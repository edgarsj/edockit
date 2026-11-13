import { readFileSync } from "fs";
import { join } from "path";
import { unzipSync, zipSync } from "fflate";
import { parseEdoc } from "../../src/core/parser";
import { verifySignature } from "../../src/core/verification";
import { createBundledTrustListProvider } from "../../src/core/trustedlist/bundled-provider";

const sampleFilePath = join(__dirname, "../fixtures/valid_samples/SampleFile.edoc");

// Embedded XAdES RevocationValues live in UnsignedSignatureProperties, so they are
// NOT covered by the signature and can be tampered with. They may only be used as
// revocation evidence after the OCSP response itself has been verified (signature,
// responder authorization, CertID, time relative to the signature timestamp).
function tamperEmbeddedOcsp(): Uint8Array {
  const files = unzipSync(new Uint8Array(readFileSync(sampleFilePath)));
  const signaturePath = Object.keys(files).find((name) => name.includes("signatures"))!;
  const xml = new TextDecoder()
    .decode(files[signaturePath])
    .replace(
      /(<xades:EncapsulatedOCSPValue[^>]*>)([\s\S]*?)(<\/xades:EncapsulatedOCSPValue>)/,
      (_match, open: string, value: string, close: string) => {
        const der = Buffer.from(value.replace(/\s+/g, ""), "base64");
        // Flip a bit in the responder's signature (the end of the structure)
        der[der.length - 1] ^= 0x01;
        return `${open}${der.toString("base64")}${close}`;
      },
    );
  files[signaturePath] = new TextEncoder().encode(xml);
  return zipSync(files);
}

describe("revocation safety with embedded (unauthenticated) data", () => {
  let fetchSpy: jest.SpyInstance;

  beforeEach(() => {
    // No live OCSP/CRL available.
    fetchSpy = jest.spyOn(global, "fetch").mockRejectedValue(new Error("network disabled in test"));
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it("uses an embedded OCSP response only after verifying it", async () => {
    const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
    const sig = container.signatures[0];
    expect(sig.revocationValues?.ocsp.length).toBeGreaterThanOrEqual(1);

    const result = await verifySignature(sig, container.files, {
      includeChecklist: true,
      trustListProvider: createBundledTrustListProvider(),
    });

    expect(result.certificate.revocation).toMatchObject({ status: "good", embedded: true });
    expect(result.status).toBe("VALID");
  });

  it("does not trust a tampered embedded OCSP response: offline revocation is indeterminate", async () => {
    const container = parseEdoc(tamperEmbeddedOcsp());
    const sig = container.signatures[0];

    const result = await verifySignature(sig, container.files, {
      includeChecklist: true,
      trustListProvider: createBundledTrustListProvider(),
    });

    const revocationItem = result.checklist!.find(
      (c) => c.check === "certificate_not_revoked_at_signing_time",
    );
    expect(revocationItem!.status).toBe("indeterminate");
    expect(result.certificate.revocation?.status).not.toBe("good");
    expect(result.status).toBe("INDETERMINATE");
  });

  it("still verifies everything that does not depend on revocation, offline", async () => {
    const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
    const sig = container.signatures[0];

    const result = await verifySignature(sig, container.files, {
      includeChecklist: true,
      trustListProvider: createBundledTrustListProvider(),
    });

    const status = (check: string) => result.checklist!.find((c) => c.check === check)?.status;

    // Signature/certificate/timestamp/trust checks are independent of revocation.
    expect(status("document_integrity")).toBe("pass");
    expect(status("signature_valid")).toBe("pass");
    expect(status("certificate_valid_at_signing_time")).toBe("pass");
    expect(status("timestamp_valid")).toBe("pass");
    expect(status("timestamp_authority_trusted_at_signing_time")).toBe("pass");
    expect(status("issuer_trusted_at_signing_time")).toBe("pass");
  });
});
