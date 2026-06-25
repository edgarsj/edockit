import { readFileSync } from "fs";
import { join } from "path";
import { X509Certificate } from "@peculiar/x509";
import { parseEdoc } from "../../src/core/parser";
import { verifySignature } from "../../src/core/verification";
import { createBundledTrustListProvider } from "../../src/core/trustedlist/bundled-provider";
import { extractCRLUrls } from "../../src/core/revocation";

const sampleFilePath = join(__dirname, "../fixtures/valid_samples/SampleFile.edoc");

// The signer's certificate chain is empty in this container, so OCSP normally can't
// build a request and the verifier falls back to downloading the full (~668 KB) CRL.
// The issuer certificate is, however, embedded in the signature's RevocationValues
// OCSP response. Using it lets the lightweight live OCSP query succeed instead.
describe("light live OCSP path via issuer cert from embedded data", () => {
  it("answers revocation with a live OCSP query and does not download the signer CRL", async () => {
    const container = parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));
    const sig = container.signatures[0];
    const signer = new X509Certificate(sig.certificatePEM);
    const signerCrlUrls = extractCRLUrls(signer);
    const ocspResponseDer = Buffer.from(sig.revocationValues!.ocsp[0], "base64");

    const fetchedUrls: string[] = [];
    const fetchSpy = jest
      .spyOn(global, "fetch")
      .mockImplementation(async (input: any): Promise<Response> => {
        const url = String(input);
        fetchedUrls.push(url);
        if (url.includes("ocsp")) {
          // Simulate the live responder returning a current "good" status.
          return new Response(ocspResponseDer, { status: 200 });
        }
        // Everything else (CRLs, AIA caIssuers) is "unavailable" in this test.
        throw new Error(`unexpected fetch: ${url}`);
      });

    const result = await verifySignature(sig, container.files, {
      includeChecklist: true,
      trustListProvider: createBundledTrustListProvider(),
    });

    fetchSpy.mockRestore();

    // Revocation was answered by OCSP (the light path), not the CRL fallback.
    expect(result.certificate.revocation?.method).toBe("ocsp");
    expect(result.certificate.revocation?.status).toBe("good");

    // The large signer CRL was never downloaded.
    for (const crlUrl of signerCrlUrls) {
      expect(fetchedUrls).not.toContain(crlUrl);
    }
  });
});
