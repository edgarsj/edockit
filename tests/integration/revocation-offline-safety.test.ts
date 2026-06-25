import { readFileSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../src/core/parser";
import { verifySignature } from "../../src/core/verification";
import { createBundledTrustListProvider } from "../../src/core/trustedlist/bundled-provider";

const sampleFilePath = join(__dirname, "../fixtures/valid_samples/SampleFile.edoc");

// Embedded XAdES RevocationValues live in UnsignedSignatureProperties, so they are
// NOT covered by the signature and can be tampered with. They must never short-circuit
// the revocation verdict to "good" without authentication. When revocation cannot be
// checked (e.g. offline), the result must be INDETERMINATE, not a pass.
describe("revocation safety with embedded (unauthenticated) data", () => {
  let fetchSpy: jest.SpyInstance;

  beforeEach(() => {
    // No live OCSP/CRL available.
    fetchSpy = jest.spyOn(global, "fetch").mockRejectedValue(new Error("network disabled in test"));
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it("does not trust embedded revocation data: offline revocation is indeterminate, not pass", async () => {
    const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
    const sig = container.signatures[0];
    // The fixture carries an embedded "good" OCSP response that, if trusted blindly,
    // would make revocation pass with no network.
    expect(sig.revocationValues?.ocsp.length).toBeGreaterThanOrEqual(1);

    const result = await verifySignature(sig, container.files, {
      includeChecklist: true,
      trustListProvider: createBundledTrustListProvider(),
    });

    const revocationItem = result.checklist!.find(
      (c) => c.check === "certificate_not_revoked_at_signing_time",
    );
    expect(revocationItem!.status).toBe("indeterminate");
    expect(result.certificate.revocation?.status).not.toBe("good");
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
