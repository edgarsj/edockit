import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "@peculiar/x509";
import { parseEdoc } from "../../src/core/parser";
import { verifySignature } from "../../src/core/verification";
import { createBundledTrustListProvider } from "../../src/core/trustedlist/bundled-provider";
import { extractCRLUrls, extractOCSPUrls } from "../../src/core/revocation";

const sampleFilePath = join(__dirname, "../fixtures/valid_samples/SampleFile.edoc");

describe("LTV revocation from embedded data (offline)", () => {
  let fetchSpy: jest.SpyInstance;

  beforeEach(() => {
    // Simulate a fully offline environment: any live OCSP/CRL/AIA fetch fails.
    fetchSpy = jest.spyOn(global, "fetch").mockRejectedValue(new Error("network disabled in test"));
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it("verifies certificate_not_revoked_at_signing_time from embedded OCSP without network", async () => {
    const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
    const sig = container.signatures[0];

    const result = await verifySignature(sig, container.files, {
      includeChecklist: true,
      trustListProvider: createBundledTrustListProvider(),
    });

    // The signer certificate's revocation was answered from embedded LTV material.
    expect(result.certificate.revocation?.fromEmbedded).toBe(true);
    expect(result.certificate.revocation?.status).toBe("good");

    const revocationItem = result.checklist!.find(
      (c) => c.check === "certificate_not_revoked_at_signing_time",
    );
    expect(revocationItem!.status).toBe("pass");

    // Whole checklist green and overall VALID, even though every live fetch fails.
    for (const item of result.checklist!) {
      expect(item.status).toBe("pass");
    }
    expect(result.status).toBe("VALID");

    // No live fetch was made to the signer certificate's own OCSP/CRL endpoints.
    const signerCert = new X509Certificate(sig.certificatePEM);
    const signerRevocationUrls = [...extractCRLUrls(signerCert), ...extractOCSPUrls(signerCert)];
    const fetchedUrls = fetchSpy.mock.calls.map((call) => String(call[0]));
    for (const url of signerRevocationUrls) {
      expect(fetchedUrls).not.toContain(url);
    }
  });
});
